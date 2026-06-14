"""Executor — validates and runs SIFT tool commands.

The executor is the architectural gatekeeper. The LLM proposes commands;
the executor validates them against the tool registry before execution.
The LLM never touches subprocess directly.
"""

from .runner import ExecutionResult, LocalExecutor, SSHExecutor

__all__ = ["ExecutionResult", "LocalExecutor", "SSHExecutor"]
