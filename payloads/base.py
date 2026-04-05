"""
Abstract base class for all attack payloads.

Every payload must define a name, description, severity, and an
execute() method that takes a TargetRunner and returns a PayloadResult.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

from core.runner import TargetRunner


class Severity(str, Enum):
    """Vulnerability severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PayloadResult(BaseModel):
    """Outcome of a payload execution against a target."""

    payload_name: str
    success: bool = Field(description="Whether the attack achieved its objective")
    severity: Severity
    evidence: str = Field(default="", description="Raw output proving the finding")
    details: str = Field(default="", description="Human-readable explanation")
    remediation: str = Field(default="", description="Suggested fix")
    metadata: dict[str, Any] = Field(default_factory=dict)


class BasePayload(ABC):
    """
    Abstract base for all attack payloads.

    Subclasses must implement:
        - name: str
        - description: str
        - severity: Severity
        - execute(runner: TargetRunner) -> PayloadResult
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this payload (e.g., 'memory_poison')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """One-line description of what this payload tests."""
        ...

    @property
    @abstractmethod
    def severity(self) -> Severity:
        """Default severity if the attack succeeds."""
        ...

    @abstractmethod
    def execute(self, runner: TargetRunner) -> PayloadResult:
        """
        Run the attack against the target container.

        Args:
            runner: TargetRunner connected to the spawned container.

        Returns:
            PayloadResult indicating whether the attack succeeded.
        """
        ...

    def __repr__(self) -> str:
        return f"<Payload: {self.name} [{self.severity.value}]>"
