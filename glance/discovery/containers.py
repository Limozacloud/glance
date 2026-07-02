"""Container discovery — builds an overlay2-path → container-info map.

Queries Docker and Podman (if available) to find running and stopped containers
and their overlay2 layer paths. Used by the binary cataloger to annotate finds
with container context without any filesystem writes or exports.

Path → provenance mapping:
  MergedDir  → "running-merged"  (assembled overlay view of a live container)
  UpperDir / LowerDir → "stopped-layer"  (raw layer data; container may be stopped)
"""

from __future__ import annotations

import json
import logging
import subprocess

log = logging.getLogger(__name__)

_DOCKER = "docker"
_PODMAN = "podman"


def _runtime_available(binary: str) -> bool:
    import shutil

    return shutil.which(binary) is not None


def _inspect_runtime(binary: str) -> list[dict]:
    """Return docker/podman inspect output for all containers (running + stopped)."""
    try:
        ids = subprocess.run(
            [binary, "ps", "-aq"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if ids.returncode != 0 or not ids.stdout.strip():
            return []
        container_ids = ids.stdout.split()
        result = subprocess.run(
            [binary, "inspect"] + container_ids,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if result.returncode != 0:
            return []
        return json.loads(result.stdout)
    except Exception as exc:
        log.debug("%s container discovery failed: %s", binary, exc)
        return []


def _add_container_to_map(result: dict[str, dict], c: dict) -> None:
    """Insert all overlay2 paths for one container into the map."""
    try:
        gd = c.get("GraphDriver", {}).get("Data", {})
        merged = gd.get("MergedDir", "")
        upper = gd.get("UpperDir", "")
        lower_raw = gd.get("LowerDir", "")

        name = c.get("Name", "").lstrip("/")
        image = c.get("Config", {}).get("Image", "")
        cid = c.get("Id", "")[:12]

        # MergedDir only exists (and is mounted) when the container is running.
        if merged:
            result[merged] = {
                "id": cid,
                "name": name,
                "image": image,
                "provenance": "running-merged",
            }

        # UpperDir is the container's own writable layer — present for both running
        # and stopped containers. First-write wins for shared image layers below.
        layer_info = {"id": cid, "name": name, "image": image, "provenance": "stopped-layer"}
        if upper:
            result.setdefault(upper, layer_info)

        # LowerDir is a colon-separated list of read-only image layers shared across
        # containers that use the same base image. We only register a layer if no
        # other container has claimed it first (first-write wins).
        if lower_raw:
            for layer in lower_raw.split(":"):
                layer = layer.strip()
                if layer:
                    result.setdefault(layer, layer_info)

    except Exception:
        pass


def build_container_map(report=None) -> dict[str, dict]:
    """Return a mapping of overlay2 path prefix → container info.

    Queries Docker and Podman (whichever is available). Includes both running
    and stopped containers.

    Returns an empty dict if no container runtime is reachable. If *report* is
    provided (a ``ScanReport``), a warning is appended when no runtime is found.

    Map values: ``{id, name, image, provenance}`` where provenance is one of
    ``"running-merged"`` or ``"stopped-layer"``.
    """
    result: dict[str, dict] = {}
    found_any_runtime = False

    for binary in (_DOCKER, _PODMAN):
        if not _runtime_available(binary):
            continue
        found_any_runtime = True
        containers = _inspect_runtime(binary)
        for c in containers:
            _add_container_to_map(result, c)
        if containers:
            log.debug("%s: %d container(s) indexed", binary, len(containers))

    if not found_any_runtime and report is not None:
        report.warnings.append(
            "container_map: no container runtime (docker/podman) reachable — "
            "binary finds will not be attributed to containers"
        )

    return result


def container_for_path(path: str, container_map: dict[str, dict]) -> dict | None:
    """Return container info if path is inside a known overlay2 path prefix."""
    for prefix, info in container_map.items():
        if path.startswith(prefix + "/") or path == prefix:
            return info
    return None
