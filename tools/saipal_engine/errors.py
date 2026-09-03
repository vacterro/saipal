"""The closed error vocabulary (REGISTRY.json `error_codes`)."""

from __future__ import annotations


class PalError(Exception):
    """A refusal SAIPAL can explain.

    Every refusal carries a machine code from the closed `error_codes` set, a
    human reason, and -- where one exists -- the next action an operator can
    take. A refusal is a result, never a crash.
    """

    def __init__(self, code: str, message: str, *, next_action: str | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.next_action = next_action

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "next_action": self.next_action,
        }
