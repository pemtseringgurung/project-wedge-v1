"""
Remediation formatter — maps detected findings to specific, actionable
remediation guidance with severity ratings and implementation details.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from parsers.log_analyzer import Finding, FindingType
from payloads.base import Severity


@dataclass
class Remediation:
    """Actionable fix for a detected vulnerability."""

    title: str
    severity: Severity
    description: str
    steps: list[str]
    code_hint: Optional[str] = None


# Mapping from finding type to remediation templates
_REMEDIATION_DB: dict[FindingType, Remediation] = {
    FindingType.LATERAL_PROPAGATION: Remediation(
        title="Lateral Memory Contamination",
        severity=Severity.CRITICAL,
        description=(
            "Data injected into one agent's memory propagated to other agents, "
            "proving that shared state is not properly isolated. An attacker "
            "can compromise one agent to control the entire system."
        ),
        steps=[
            "Implement state-isolation between agent nodes",
            "Use separate memory namespaces (vector DB collections) per agent",
            "Add input sanitization on all cross-agent data transfers",
            "Implement a validation/approval gate before writing to shared memory",
            "Add provenance tracking to all shared memory writes",
        ],
        code_hint=(
            "# Example: namespace isolation\n"
            "agent_memory = VectorDB(namespace=f'agent_{agent_id}')\n"
            "# Never write directly to shared — go through validator\n"
            "shared_memory.write(data, source=agent_id, requires_approval=True)"
        ),
    ),

    FindingType.INFINITE_LOOP: Remediation(
        title="Agent Verification Loop (DoS)",
        severity=Severity.HIGH,
        description=(
            "Agents entered an infinite verification or tool-calling loop "
            "when presented with contradictory constraints. This is a "
            "denial-of-service vector — an attacker can halt the system "
            "with a single crafted input."
        ),
        steps=[
            "Add a maximum retry/iteration count to all agent loops",
            "Implement contradiction detection before task execution",
            "Add circuit breakers that escalate to human review after N retries",
            "Set hard timeouts on all inter-agent communication",
            "Log and alert on repetitive patterns in agent output",
        ],
        code_hint=(
            "# Example: circuit breaker\n"
            "MAX_RETRIES = 3\n"
            "for attempt in range(MAX_RETRIES):\n"
            "    result = agent.verify(task)\n"
            "    if result.is_consistent:\n"
            "        break\n"
            "else:\n"
            "    escalate_to_human(task, reason='contradiction_detected')"
        ),
    ),

    FindingType.PROMPT_LEAK: Remediation(
        title="System Prompt / Credential Leakage",
        severity=Severity.HIGH,
        description=(
            "Internal system prompts, agent identities, or credentials "
            "were leaked in the agent output. This exposes the system's "
            "architecture and can be used to craft targeted attacks."
        ),
        steps=[
            "Implement output filtering to strip system-level content",
            "Never include credentials in agent prompts — use env vars or secret managers",
            "Add a post-processing layer that redacts sensitive patterns",
            "Separate agent identity from user-visible output",
        ],
        code_hint=(
            "# Example: output sanitizer\n"
            "def sanitize_output(text: str) -> str:\n"
            "    text = re.sub(r'api[_-]?key\\s*[:=]\\s*\\S+', '[REDACTED]', text)\n"
            "    text = re.sub(r'system prompt:.*', '[FILTERED]', text, flags=re.I)\n"
            "    return text"
        ),
    ),

    FindingType.ERROR_CASCADE: Remediation(
        title="Error Cascade / System Instability",
        severity=Severity.MEDIUM,
        description=(
            "Multiple errors cascaded through the agent system, indicating "
            "poor error handling. Under adversarial conditions this can lead "
            "to unpredictable behavior or full system failure."
        ),
        steps=[
            "Add try/except boundaries around each agent's execution",
            "Implement graceful degradation — one agent failure should not cascade",
            "Add structured error logging with correlation IDs",
            "Set up health checks and automatic agent restart on failure",
        ],
        code_hint=(
            "# Example: isolated execution\n"
            "async def run_agent_safe(agent, task):\n"
            "    try:\n"
            "        return await agent.execute(task)\n"
            "    except Exception as e:\n"
            "        logger.error(f'Agent {agent.id} failed: {e}')\n"
            "        return FallbackResponse(error=str(e))"
        ),
    ),
}


def get_remediation(finding: Finding) -> Remediation:
    """
    Map a finding to its remediation guidance.

    Falls back to a generic remediation if the finding type is unknown.
    """
    if finding.finding_type in _REMEDIATION_DB:
        return _REMEDIATION_DB[finding.finding_type]

    return Remediation(
        title="Unknown Vulnerability",
        severity=Severity.MEDIUM,
        description=finding.description,
        steps=[
            "Review the evidence lines for this finding",
            "Investigate the root cause in the agent source code",
            "Implement appropriate safeguards based on the finding type",
        ],
    )


def format_report(findings: list[Finding]) -> str:
    """
    Generate a Markdown-formatted remediation report from findings.

    Returns:
        Markdown string ready for terminal or file output.
    """
    if not findings:
        return "# Security Scan Report\n\n✅ No vulnerabilities detected.\n"

    lines = ["# Security Scan Report\n"]
    lines.append(f"**{len(findings)} finding(s) detected**\n")
    lines.append("---\n")

    for i, finding in enumerate(findings, 1):
        rem = get_remediation(finding)

        lines.append(f"## {i}. {rem.title}")
        lines.append(f"**Severity:** {rem.severity.value}")
        lines.append(f"**Confidence:** {finding.confidence:.0%}")
        lines.append(f"\n{rem.description}\n")

        lines.append("### Evidence")
        for ev in finding.evidence_lines[:5]:
            lines.append(f"```\n{ev}\n```")

        lines.append("\n### Remediation Steps")
        for j, step in enumerate(rem.steps, 1):
            lines.append(f"{j}. {step}")

        if rem.code_hint:
            lines.append(f"\n### Code Example\n```python\n{rem.code_hint}\n```")

        lines.append("\n---\n")

    return "\n".join(lines)
