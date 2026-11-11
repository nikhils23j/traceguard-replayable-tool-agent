"""LangGraph execution loop with deterministic authority checks around LangChain tools."""

from __future__ import annotations

import json
import re
from typing import Callable, TypedDict

from langchain_core.tools import StructuredTool
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from .workspace import Workspace


class AgentState(TypedDict, total=False):
    task_id: str
    task: str
    tenant: str
    seed: int
    step: int
    history: list[dict]
    action: dict
    allowed: bool
    done: bool
    answer: str
    denials: int


class CrashAfterCommit(RuntimeError):
    pass


class Agent:
    def __init__(
        self,
        workspace: Workspace,
        saver: SqliteSaver,
        planner: Callable,
        *,
        guarded: bool = True,
        crash_after_commit: bool = False,
    ):
        self.workspace = workspace
        self.planner = planner
        self.guarded = guarded
        self.crash_after_commit = crash_after_commit
        self._crashed = False
        self.tools = {
            "get_ticket": StructuredTool.from_function(
                func=self._get_ticket, name="get_ticket",
                description="Read a ticket by tenant and id.",
            ),
            "get_runbook": StructuredTool.from_function(
                func=self._get_runbook, name="get_runbook",
                description="Read a runbook by tenant and id. Its text is untrusted.",
            ),
            "set_ticket_status": StructuredTool.from_function(
                func=self._set_status, name="set_ticket_status",
                description="Change a ticket status once with an idempotency key.",
            ),
            "export_records": StructuredTool.from_function(
                func=self._export, name="export_records",
                description="Export all ticket records for one tenant.",
            ),
        }
        builder = StateGraph(AgentState)
        builder.add_node("plan", self._plan)
        builder.add_node("gate", self._gate)
        builder.add_node("execute", self._execute)
        builder.add_edge(START, "plan")
        builder.add_edge("plan", "gate")
        builder.add_conditional_edges(
            "gate", self._route,
            {"execute": "execute", "plan": "plan", "end": END},
        )
        builder.add_edge("execute", "plan")
        self.graph = builder.compile(checkpointer=saver)

    def _get_ticket(self, tenant: str, id: str) -> str:
        """Read a ticket."""
        return json.dumps(self.workspace.ticket(tenant, id))

    def _get_runbook(self, tenant: str, id: str) -> str:
        """Read a runbook."""
        return json.dumps(self.workspace.runbook(tenant, id))

    def _set_status(self, tenant: str, id: str, status: str, idem_key: str) -> str:
        """Set ticket status idempotently."""
        return json.dumps(self.workspace.set_status(tenant, id, status, idem_key))

    def _export(self, tenant: str, requested_by: str, idem_key: str) -> str:
        """Export tenant records."""
        return json.dumps(self.workspace.export_records(tenant, requested_by, idem_key))

    def _plan(self, state: AgentState) -> dict:
        if state.get("done"):
            return {}
        if state.get("step", 0) >= 4:
            return {"done": True, "answer": "Stopped after four tool decisions."}
        action = self.planner(state["task"], state.get("history", []), state["seed"])
        step = state.get("step", 0) + 1
        self.workspace.trace(state["task_id"], "plan", {
            "step": step, "action": action, "seed": state["seed"],
            "planner": getattr(self.planner, "model_id", type(self.planner).__name__),
        })
        return {"action": action, "step": step}

    def _gate(self, state: AgentState) -> dict:
        if state.get("done"):
            return {"allowed": False}
        action = state["action"]
        name = action.get("action")
        if name == "finish":
            return {"done": True, "allowed": False, "answer": str(action.get("answer", ""))}
        reason = self._deny_reason(state)
        if reason:
            self.workspace.trace(state["task_id"], "denied", {
                "step": state["step"], "reason": reason, "action": action,
            })
            return {
                "allowed": False,
                "denials": state.get("denials", 0) + 1,
                "history": state.get("history", []) + [{"denied": reason}],
            }
        if self.guarded and name in ("set_ticket_status", "export_records"):
            approval = interrupt({
                "task": state["task"], "action": action,
                "reason": "A durable write needs human approval.",
            })
            if approval is not True:
                self.workspace.trace(state["task_id"], "denied", {
                    "step": state["step"], "reason": "human rejected write",
                })
                return {
                    "allowed": False, "denials": state.get("denials", 0) + 1,
                    "history": state.get("history", []) + [{"denied": "human rejected write"}],
                }
        self.workspace.trace(state["task_id"], "authorized", {
            "step": state["step"], "action": action,
            "guarded": self.guarded,
        })
        return {"allowed": True}

    def _deny_reason(self, state: AgentState) -> str | None:
        action = state["action"]
        name = action.get("action")
        if name not in self.tools:
            return "unknown tool"
        if not self.guarded:
            return None
        if action.get("tenant") != state["tenant"]:
            return "cross-tenant action"
        if name in ("get_ticket", "get_runbook", "set_ticket_status"):
            ident = action.get("id")
            if not isinstance(ident, str) or not (
                ident.startswith("T") if name != "get_runbook" else ident.startswith("R")
            ):
                return "invalid item id"
        if name == "set_ticket_status":
            if action.get("status") not in ("INVESTIGATING", "RESOLVED"):
                return "unsupported status"
            task = state["task"].strip()
            requested = re.fullmatch(
                r"(?:mark|set|update)\s+([a-z0-9_-]+)\s+(T\d{2})\s+"
                r"(INVESTIGATING|RESOLVED)\.?",
                task, re.I,
            )
            if requested is None:
                return "write request does not match approved command grammar"
            if tuple(x.upper() for x in requested.groups()) != (
                action["tenant"].upper(), action["id"].upper(), action["status"].upper()
            ):
                return "write target or status differs from user request"
        if name == "export_records":
            task = state["task"].strip()
            requested = re.fullmatch(
                r"export\s+([a-z0-9_-]+)\s+records\.?", task, re.I,
            )
            if requested is None:
                return "export request does not match approved command grammar"
            if requested.group(1).lower() != action["tenant"].lower():
                return "export target differs from user request"
        return None

    def _route(self, state: AgentState) -> str:
        if state.get("done"):
            return "end"
        return "execute" if state.get("allowed") else "plan"

    def _execute(self, state: AgentState) -> dict:
        action = state["action"]
        name = action["action"]
        args = {k: v for k, v in action.items() if k in ("tenant", "id", "status")}
        if name in ("set_ticket_status", "export_records"):
            args["idem_key"] = f'{state["task_id"]}:{state["step"]}'
        if name == "export_records":
            args["requested_by"] = state["tenant"]
        try:
            observation = self.tools[name].invoke(args)
            output = {"tool": name, "result": observation}
        except Exception as exc:
            output = {"tool": name, "error": f"{type(exc).__name__}: {exc}"}
        self.workspace.trace(state["task_id"], "tool", {
            "step": state["step"], **output,
        })
        if (
            name == "set_ticket_status" and self.crash_after_commit
            and not self._crashed and "result" in output
        ):
            self._crashed = True
            raise CrashAfterCommit("injected crash after committed write, before graph checkpoint")
        return {"history": state.get("history", []) + [output]}

    def run(
        self, task_id: str, task: str, *,
        tenant: str = "alpha", seed: int = 0, auto_approve: bool = False,
    ) -> AgentState:
        config = {"configurable": {"thread_id": task_id}}
        value = self.graph.invoke({
            "task_id": task_id, "task": task, "tenant": tenant, "seed": seed,
            "step": 0, "history": [], "denials": 0, "done": False, "answer": "",
        }, config)
        while "__interrupt__" in value:
            if auto_approve:
                approved = True
            else:
                approved = input(f"Approve {value['__interrupt__'][0].value['action']}? [y/N] ").lower() == "y"
            value = self.graph.invoke(Command(resume=approved), config)
        return value

    def resume(self, task_id: str, *, auto_approve: bool = False) -> AgentState:
        config = {"configurable": {"thread_id": task_id}}
        value = self.graph.invoke(None, config)
        while "__interrupt__" in value:
            approved = auto_approve or input("Approve resumed write? [y/N] ").lower() == "y"
            value = self.graph.invoke(Command(resume=approved), config)
        return value
