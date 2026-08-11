"""Host side: bring the authority up, talk to it as the agent, tear it down.

The container is used as a *launcher*, and that is disclosed everywhere it
matters. Section 4 asks for three roles to be kept apart and this module labels
them:

    PROVISIONING_AUTHORITY    root, via the rootful Docker socket. Creates the
                              authority-owned store, runtime and code
                              directories. Under the cutover plan this is a
                              one-time administrative step.
    RUNTIME_BROKER_AUTHORITY  uid 940 / 941 inside the container. This is the
                              principal under test.
    RUNTIME_AGENT_AUTHORITY   uid 1000 on the host. Everything the attack suite
                              runs from.

The launcher is *not* absent from the runtime trust path here: keeping the
container alive is a Docker operation and the agent holds the Docker socket. So
this deployment does not demonstrate closure, and the verifier does not treat it
as such. It demonstrates the boundary that closure would rest on, which is a
different and still useful claim.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ACTOR = "agent:cspa3"
AUTHORITY_UID = 940
CODE_FILES = ("v3_authority.py", "container_launch.py")

PROVISIONING_AUTHORITY = "root via rootful docker socket (one-time in deployment)"
RUNTIME_BROKER_AUTHORITY = f"uid {AUTHORITY_UID} / {AUTHORITY_UID + 1}"
RUNTIME_AGENT_AUTHORITY = "uid 1000 on the host"


def _run(cmd, timeout=180, **kwargs):
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False, **kwargs
    )


IMAGE_CACHE = os.path.join(HERE, ".python_image")


def python_image() -> str | None:
    """First local image providing python3, cached.

    This host has ~400 images and probing each costs a container start, which
    dominated the runtime of every verifier pass.
    """
    if os.path.exists(IMAGE_CACHE):
        with open(IMAGE_CACHE, encoding="utf-8") as handle:
            cached = handle.read().strip()
        if cached and _run(["docker", "image", "inspect", cached], timeout=60).returncode == 0:
            return cached
    listing = _run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"])
    for line in listing.stdout.splitlines():
        image = line.strip()
        if not image or "<none>" in image:
            continue
        probe = _run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--entrypoint",
                "sh",
                "--user",
                "0:0",
                image,
                "-c",
                "command -v python3",
            ],
            timeout=90,
        )
        if probe.returncode == 0 and probe.stdout.strip():
            with open(IMAGE_CACHE, "w", encoding="utf-8") as handle:
                handle.write(image)
            return image
    return None


class Deployment:
    def __init__(self, **fields):
        self.__dict__.update(fields)

    def teardown(self) -> None:
        _run(["docker", "rm", "-f", self.container], timeout=120)
        # Everything under the base is owned by the authority uid now, so the
        # agent cannot remove it. The provisioning authority hands it back.
        _run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--user",
                "0:0",
                "--security-opt",
                "label=disable",
                "--entrypoint",
                "sh",
                "-v",
                f"{self.base}:/mnt",
                self.image,
                "-c",
                f"chown -R {os.getuid()}:{os.getgid()} /mnt",
            ],
            timeout=180,
        )
        shutil.rmtree(self.base, ignore_errors=True)


def bring_up(seed: dict | None = None) -> Deployment:
    image = python_image()
    if image is None:
        raise RuntimeError("no local image with python3; cannot run the authority")
    token = uuid.uuid4().hex[:12]
    base = f"/tmp/cspa3-{token}"
    store = os.path.join(base, "canon")
    runtime = os.path.join(base, "run")
    code = os.path.join(base, "code")
    workspace = os.path.join(base, "ws")
    for path in (store, runtime, code, workspace):
        os.makedirs(path, mode=0o755)
    for name in CODE_FILES:
        shutil.copy2(os.path.join(HERE, name), os.path.join(code, name))
    os.makedirs(os.path.join(store, "files"), mode=0o755, exist_ok=True)
    for name, content in (seed or {"README.md": "canonical seed\n"}).items():
        with open(os.path.join(store, "files", name), "w", encoding="utf-8") as handle:
            handle.write(content)

    resource = str(uuid.uuid4())
    container = f"cspa3-authority-{token}"
    result = _run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            container,
            "--network",
            "none",
            "--security-opt",
            "label=disable",
            "--user",
            "0:0",
            "--entrypoint",
            "python3",
            "-e",
            f"CSPA3_AUTHORITY_UID={AUTHORITY_UID}",
            "-e",
            f"CSPA3_RESOURCE={resource}",
            "-e",
            f"CSPA3_ACTOR={ACTOR}",
            "-e",
            f"CSPA3_AGENT_UID={os.getuid()}",
            "-v",
            f"{store}:/srv/canonical",
            "-v",
            f"{runtime}:/srv/run",
            "-v",
            f"{code}:/srv/code",
            image,
            "/srv/code/container_launch.py",
        ],
        timeout=180,
    )
    if result.returncode != 0:
        shutil.rmtree(base, ignore_errors=True)
        raise RuntimeError(f"authority container failed to start: {result.stderr.strip()[:300]}")

    ready = {}
    deadline = time.time() + 60
    while time.time() < deadline:
        for label in ("decide", "broker"):
            path = os.path.join(runtime, f"{label}.ready")
            if label not in ready and os.path.exists(path):
                try:
                    with open(path, encoding="utf-8") as handle:
                        ready[label] = json.load(handle)
                except (OSError, ValueError):
                    pass
        if len(ready) == 2:
            break
        time.sleep(0.1)
    if len(ready) != 2:
        logs = _run(["docker", "logs", container], timeout=60)
        _run(["docker", "rm", "-f", container], timeout=120)
        raise RuntimeError(f"authority never signalled ready: {(logs.stdout + logs.stderr)[:400]}")

    return Deployment(
        base=base,
        store=store,
        runtime=runtime,
        code=code,
        workspace=workspace,
        image=image,
        container=container,
        resource=resource,
        actor=ACTOR,
        agent_uid=os.getuid(),
        broker_socket=os.path.join(runtime, "broker.sock"),
        decide_socket=os.path.join(runtime, "decide.sock"),
        key_file=os.path.join(runtime, "authority.key"),
        broker_uid=ready["broker"]["uid"],
        decision_uid=ready["decide"]["uid"],
        store_owner_uid=os.stat(store).st_uid,
        roles={
            "PROVISIONING_AUTHORITY": PROVISIONING_AUTHORITY,
            "RUNTIME_BROKER_AUTHORITY": RUNTIME_BROKER_AUTHORITY,
            "RUNTIME_AGENT_AUTHORITY": RUNTIME_AGENT_AUTHORITY,
            "launcher_in_runtime_trust_path": True,
            "why": "the agent holds the Docker socket that keeps this container "
            "alive, so the launcher is not absent from the runtime trust "
            "path and this deployment does not demonstrate closure",
        },
    )
