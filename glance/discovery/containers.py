"""Docker container discovery — builds a merged-path → container-info map.

Queries the Docker socket (if available) to find running containers and their
overlay2 merged paths. Used by the binary cataloger to annotate finds with
container context without any filesystem writes or exports.
"""

from __future__ import annotations

import json
import logging
import subprocess

log = logging.getLogger(__name__)

_DOCKER = "docker"
_SOCKET = "/var/run/docker.sock"


def _docker_available() -> bool:
    import shutil

    return shutil.which(_DOCKER) is not None


def _inspect_containers() -> list[dict]:
    try:
        ids = subprocess.run(
            [_DOCKER, "ps", "-q"],
            capture_output=True, text=True, check=False, timeout=5,
        )
        if ids.returncode != 0 or not ids.stdout.strip():
            return []
        container_ids = ids.stdout.split()
        result = subprocess.run(
            [_DOCKER, "inspect"] + container_ids,
            capture_output=True, text=True, check=False, timeout=10,
        )
        if result.returncode != 0:
            return []
        return json.loads(result.stdout)
    except Exception as exc:
        log.debug("container discovery failed: %s", exc)
        return []


def build_container_map() -> dict[str, dict]:
    """Return a mapping of overlay2 merged-path prefix → container info.

    Returns an empty dict if Docker is not available or no containers are running.
    Each value: ``{id, name, image}``.
    """
    if not _docker_available():
        return {}

    containers = _inspect_containers()
    if not containers:
        return {}

    result: dict[str, dict] = {}
    for c in containers:
        try:
            merged = (
                c.get("GraphDriver", {})
                .get("Data", {})
                .get("MergedDir", "")
            )
            if not merged:
                continue
            name = c.get("Name", "").lstrip("/")
            image = c.get("Config", {}).get("Image", "")
            cid = c.get("Id", "")[:12]
            result[merged] = {"id": cid, "name": name, "image": image}
        except Exception:
            continue

    log.debug("container map: %d running containers", len(result))
    return result


def container_for_path(path: str, container_map: dict[str, dict]) -> dict | None:
    """Return container info if path is inside a known overlay2 merged dir."""
    for merged, info in container_map.items():
        if path.startswith(merged + "/") or path == merged:
            return info
    return None
