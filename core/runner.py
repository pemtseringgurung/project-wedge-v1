"""
Target runner — executes commands inside a spawned container and streams
stdout/stderr back to the host in real-time.

This is the bridge between our payloads and the isolated target environment.
"""

from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Generator, Optional

from docker.errors import APIError, NotFound
from docker.models.containers import Container

from core.docker_client import get_client


@dataclass
class ExecResult:
    """Result of a completed command execution inside a container."""

    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float


@dataclass
class StreamEvent:
    """A single chunk of output from a running command."""

    stream: str  # "stdout" or "stderr"
    data: str
    timestamp: float = field(default_factory=time.time)


class TargetRunner:
    """
    Communicates with a spawned Docker container — sends commands,
    streams output, and manages the execution lifecycle.

    Usage:
        runner = TargetRunner(container_id)
        result = runner.exec("python3 main.py")
        # or stream in real-time:
        for event in runner.exec_stream("python3 main.py"):
            print(event.data, end="")
    """

    def __init__(self, container_id: str) -> None:
        self._container_id = container_id
        self._client = get_client()
        self._container: Container = self._client.containers.get(container_id)
        self._output_log: list[StreamEvent] = []

    @property
    def container_id(self) -> str:
        return self._container_id

    @property
    def output_log(self) -> list[StreamEvent]:
        """Full history of captured output events."""
        return list(self._output_log)

    def is_alive(self) -> bool:
        """Check if the target container is still running."""
        try:
            self._container.reload()
            return self._container.status == "running"
        except (NotFound, APIError):
            return False

    def exec(
        self,
        command: str,
        timeout: Optional[float] = None,
        workdir: str = "/app",
    ) -> ExecResult:
        """
        Execute a command inside the container and wait for completion.

        Args:
            command: Shell command to run (passed to /bin/sh -c).
            timeout: Max seconds to wait. None = no limit.
            workdir: Working directory inside the container.

        Returns:
            ExecResult with exit code, stdout, stderr, and duration.

        Raises:
            TimeoutError: If the command exceeds the timeout.
            RuntimeError: If the container is not running.
        """
        if not self.is_alive():
            raise RuntimeError(f"Container {self._container_id[:12]} is not running")

        start = time.time()

        exec_id = self._client.api.exec_create(
            self._container_id,
            cmd=["/bin/sh", "-c", command],
            workdir=workdir,
            stdout=True,
            stderr=True,
        )

        output = self._client.api.exec_start(exec_id, stream=False, demux=True)
        duration = time.time() - start

        stdout_bytes, stderr_bytes = output if isinstance(output, tuple) else (output, b"")
        stdout_str = (stdout_bytes or b"").decode("utf-8", errors="replace")
        stderr_str = (stderr_bytes or b"").decode("utf-8", errors="replace")

        inspect = self._client.api.exec_inspect(exec_id)
        exit_code = inspect.get("ExitCode", -1)

        # Log the output
        if stdout_str:
            self._output_log.append(StreamEvent(stream="stdout", data=stdout_str))
        if stderr_str:
            self._output_log.append(StreamEvent(stream="stderr", data=stderr_str))

        if timeout and duration > timeout:
            raise TimeoutError(
                f"Command exceeded timeout ({duration:.1f}s > {timeout}s)"
            )

        return ExecResult(
            exit_code=exit_code,
            stdout=stdout_str,
            stderr=stderr_str,
            duration_seconds=round(duration, 3),
        )

    def exec_stream(
        self,
        command: str,
        workdir: str = "/app",
    ) -> Generator[StreamEvent, None, ExecResult]:
        """
        Execute a command and yield output chunks in real-time.

        Yields:
            StreamEvent objects as output arrives.

        Returns:
            ExecResult (accessible via generator .value after StopIteration).
        """
        if not self.is_alive():
            raise RuntimeError(f"Container {self._container_id[:12]} is not running")

        start = time.time()
        collected_stdout: list[str] = []
        collected_stderr: list[str] = []

        exec_id = self._client.api.exec_create(
            self._container_id,
            cmd=["/bin/sh", "-c", command],
            workdir=workdir,
            stdout=True,
            stderr=True,
        )

        output_stream = self._client.api.exec_start(
            exec_id, stream=True, demux=True
        )

        for stdout_chunk, stderr_chunk in output_stream:
            if stdout_chunk:
                text = stdout_chunk.decode("utf-8", errors="replace")
                collected_stdout.append(text)
                event = StreamEvent(stream="stdout", data=text)
                self._output_log.append(event)
                yield event

            if stderr_chunk:
                text = stderr_chunk.decode("utf-8", errors="replace")
                collected_stderr.append(text)
                event = StreamEvent(stream="stderr", data=text)
                self._output_log.append(event)
                yield event

        duration = time.time() - start
        inspect = self._client.api.exec_inspect(exec_id)
        exit_code = inspect.get("ExitCode", -1)

        return ExecResult(
            exit_code=exit_code,
            stdout="".join(collected_stdout),
            stderr="".join(collected_stderr),
            duration_seconds=round(duration, 3),
        )

    def send_input(
        self,
        data: str,
        target_stdin: str = "/app/input.txt",
    ) -> None:
        """
        Write data to a file inside the container that agents can read.

        This simulates feeding input (e.g., a poisoned prompt) to the
        target multi-agent system via file-based communication.
        """
        escaped = data.replace("'", "'\\''")
        self.exec(f"printf '%s' '{escaped}' > {target_stdin}")

    def get_full_log(self) -> str:
        """Return all captured stdout/stderr as a single string."""
        return "".join(e.data for e in self._output_log)

    def clear_log(self) -> None:
        """Reset the captured output history."""
        self._output_log.clear()
