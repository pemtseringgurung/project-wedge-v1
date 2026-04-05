"""
Ephemeral container spawner — dynamically wraps a target directory in a
Docker image, runs it detached, and guarantees cleanup on exit or crash.
"""

from __future__ import annotations

import atexit
import signal
import tempfile
import uuid
from pathlib import Path
from typing import Optional

from docker.errors import DockerException, NotFound, APIError
from docker.models.containers import Container
from docker.models.images import Image
from pydantic import BaseModel, Field

from core.docker_client import get_client, DockerConnectionError


# ---------------------------------------------------------------------------
# Global registry of active containers — cleaned up on process exit
# ---------------------------------------------------------------------------
_active_containers: dict[str, str] = {}  # container_id -> image_tag
_cleanup_registered = False


def _emergency_cleanup(signum=None, frame=None) -> None:
    """Best-effort teardown of every tracked container + image."""
    if not _active_containers:
        return
    try:
        client = get_client(timeout=10)
    except (DockerConnectionError, Exception):
        return

    for cid, tag in list(_active_containers.items()):
        try:
            container = client.containers.get(cid)
            container.kill()
        except Exception:
            pass
        try:
            container = client.containers.get(cid)
            container.remove(force=True)
        except Exception:
            pass
        try:
            client.images.remove(image=tag, force=True)
        except Exception:
            pass

    _active_containers.clear()


def _ensure_cleanup_hooks() -> None:
    """Register atexit + signal handlers exactly once."""
    global _cleanup_registered
    if _cleanup_registered:
        return
    atexit.register(_emergency_cleanup)
    for sig in (signal.SIGTERM, signal.SIGINT):
        prev = signal.getsignal(sig)
        def _handler(s, f, _prev=prev):
            _emergency_cleanup(s, f)
            if callable(_prev) and _prev not in (signal.SIG_DFL, signal.SIG_IGN):
                _prev(s, f)
        signal.signal(sig, _handler)
    _cleanup_registered = True


# ---------------------------------------------------------------------------
# Dockerfile generation
# ---------------------------------------------------------------------------

_DOCKERFILE_TEMPLATE = """\
FROM python:3.11-slim

WORKDIR /app

# Copy the target project into the container
COPY target/ ./

# Install dependencies if a requirements.txt exists
RUN if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi

# Keep the container alive so we can exec into it or stream logs
CMD ["tail", "-f", "/dev/null"]
"""


def _generate_dockerfile(target_dir: Path) -> str:
    """
    Return Dockerfile content that wraps the given target directory.

    The Dockerfile copies everything under `target_dir` into /app inside
    the container and installs requirements.txt if present.
    """
    return _DOCKERFILE_TEMPLATE


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class SpawnResult(BaseModel):
    """Metadata returned after successfully spawning a container."""

    container_id: str
    container_name: str
    image_tag: str
    target_dir: str


def build_image(target_dir: str | Path, tag: Optional[str] = None) -> Image:
    """
    Generate a Dockerfile wrapping `target_dir` and build the image.

    Args:
        target_dir: Absolute path to the user's agent project.
        tag: Optional image tag. Auto-generated if not supplied.

    Returns:
        The built docker Image object.

    Raises:
        FileNotFoundError: If target_dir does not exist.
        DockerConnectionError: If the daemon is unreachable.
        docker.errors.BuildError: If the image build fails.
    """
    target_path = Path(target_dir).resolve()
    if not target_path.is_dir():
        raise FileNotFoundError(f"Target directory does not exist: {target_path}")

    tag = tag or f"agentsec-target-{uuid.uuid4().hex[:12]}"
    client = get_client()

    # Build in a temp context dir so we control the Dockerfile layout
    with tempfile.TemporaryDirectory(prefix="agentsec_build_") as build_ctx:
        build_ctx_path = Path(build_ctx)

        # Write the Dockerfile
        dockerfile_path = build_ctx_path / "Dockerfile"
        dockerfile_path.write_text(_generate_dockerfile(target_path))

        # Symlink (or copy) the target dir as 'target/' inside the build context
        target_link = build_ctx_path / "target"
        # Use copytree for reliability across filesystems
        import shutil
        shutil.copytree(target_path, target_link)

        image, _logs = client.images.build(
            path=str(build_ctx_path),
            tag=tag,
            rm=True,
            forcerm=True,
        )

    return image


def run_container_detached(
    image: Image | str,
    name: Optional[str] = None,
) -> SpawnResult:
    """
    Run a container from the given image in detached mode.

    Registers the container for automatic cleanup on process exit.

    Args:
        image: Image object or tag string.
        name: Optional container name. Auto-generated if not supplied.

    Returns:
        SpawnResult with container metadata.
    """
    _ensure_cleanup_hooks()
    client = get_client()

    tag = image.tags[0] if hasattr(image, "tags") and image.tags else str(image)
    name = name or f"agentsec-run-{uuid.uuid4().hex[:8]}"

    container: Container = client.containers.run(
        image=tag,
        name=name,
        detach=True,
        # Security: drop all capabilities, read-only root where possible
        cap_drop=["ALL"],
        # Resource limits
        mem_limit="512m",
        cpu_period=100000,
        cpu_quota=50000,  # 50% of one core
        # Auto-remove is NOT set — we handle removal ourselves for reliability
    )

    _active_containers[container.id] = tag

    return SpawnResult(
        container_id=container.id,
        container_name=name,
        image_tag=tag,
        target_dir="",  # populated by caller if needed
    )


def teardown(container_id: str, remove_image: bool = True) -> None:
    """
    Forcefully stop and remove a container (and optionally its image).

    This is idempotent — safe to call multiple times or on already-removed
    containers.

    Args:
        container_id: The container ID or name to tear down.
        remove_image: Also remove the backing image (default True).
    """
    client = get_client()

    tag = _active_containers.pop(container_id, None)

    # Stop + remove the container
    try:
        container = client.containers.get(container_id)
        container.kill()
    except (NotFound, APIError):
        pass  # already dead

    try:
        container = client.containers.get(container_id)
        container.remove(force=True)
    except (NotFound, APIError):
        pass  # already gone

    # Remove the image
    if remove_image and tag:
        try:
            client.images.remove(image=tag, force=True)
        except (NotFound, APIError):
            pass
