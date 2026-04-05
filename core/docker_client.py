"""
Robust wrapper around docker-py for managing the local Docker daemon connection.

Provides a singleton-style client accessor with health checks and
human-readable error handling for common failure modes (daemon not running,
permission denied, socket missing, etc.).
"""

from __future__ import annotations

import docker
from docker import DockerClient
from docker.errors import DockerException


class DockerConnectionError(Exception):
    """Raised when we cannot establish a connection to the Docker daemon."""

    def __init__(self, reason: str, suggestion: str) -> None:
        self.reason = reason
        self.suggestion = suggestion
        super().__init__(f"{reason} — {suggestion}")


def _diagnose_connection_failure(exc: Exception) -> DockerConnectionError:
    """Map raw docker-py exceptions to actionable error messages."""
    msg = str(exc).lower()

    if "permission denied" in msg:
        return DockerConnectionError(
            reason="Permission denied when connecting to the Docker socket",
            suggestion="Run with sudo or add your user to the 'docker' group: sudo usermod -aG docker $USER",
        )
    if "connection refused" in msg or "no such file" in msg:
        return DockerConnectionError(
            reason="Docker daemon is not running or the socket is missing",
            suggestion="Start Docker Desktop or run: sudo systemctl start docker",
        )
    if "timeout" in msg:
        return DockerConnectionError(
            reason="Connection to Docker daemon timed out",
            suggestion="The daemon may be overloaded. Restart Docker and try again.",
        )
    # Catch-all
    return DockerConnectionError(
        reason=f"Unexpected Docker error: {exc}",
        suggestion="Ensure Docker is installed and running, then retry.",
    )


def get_client(timeout: int = 30) -> DockerClient:
    """
    Return an authenticated DockerClient connected to the local daemon.

    Raises:
        DockerConnectionError: If the daemon is unreachable, with a
            human-readable reason and remediation suggestion.
    """
    try:
        client = docker.from_env(timeout=timeout)
    except DockerException as exc:
        raise _diagnose_connection_failure(exc) from exc

    # Verify the connection is actually alive
    try:
        client.ping()
    except DockerException as exc:
        raise _diagnose_connection_failure(exc) from exc

    return client


def ping() -> bool:
    """
    Quick liveness check — returns True if the daemon responds to a ping.

    Never raises; returns False on any failure.
    """
    try:
        client = docker.from_env(timeout=5)
        return client.ping()
    except Exception:
        return False


def daemon_info() -> dict:
    """
    Return a subset of daemon metadata useful for diagnostics.

    Raises:
        DockerConnectionError: If the daemon is unreachable.
    """
    client = get_client()
    info = client.info()
    return {
        "server_version": info.get("ServerVersion"),
        "os": info.get("OperatingSystem"),
        "architecture": info.get("Architecture"),
        "cpus": info.get("NCPU"),
        "memory_gb": round(info.get("MemTotal", 0) / (1024**3), 2),
        "containers_running": info.get("ContainersRunning"),
        "images": info.get("Images"),
    }
