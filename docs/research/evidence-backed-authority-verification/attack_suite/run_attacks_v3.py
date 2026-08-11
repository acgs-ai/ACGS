"""Sections 8, 10, 11, 12 and 18: the carrier matrix and the named attacks.

Same discipline as V2: every carrier runs twice, once against canonical state
and once against an agent-owned mirror of the same shape. A carrier whose
control fails to change the mirror proves nothing and is reported
`CONTROL_FAILED`, never as a pass.

The verdict vocabulary is narrower than V2's because the boundary is narrower.
There is no Landlock domain and no seccomp filter; a denial here is DAC and
nothing else.

    DENIED_BY_DAC     the kernel refused, and the control proved the carrier works
    NOT_DENIED        canonical state changed
    CONTROL_FAILED    the measurement is worthless
    EXPECTED_SUCCESS  an attack that is *supposed* to succeed, because it routes
                      through a root-equivalent path the agent still holds. These
                      are the findings, not failures.
    NOT_APPLICABLE    the tooling is absent; recorded, not faked

One thing that is declared rather than measured, so that it is not silently
missing: the canonical identity model is the set of *files* under `files/`, each
by content and executable bit. Directories are not part of it. That is safe here
only because the agent cannot create one -- `directory_entry_mutation` measures
exactly that -- and it is stated because V1's expensive lesson was a digest that
could not see a state class the attacker could change.
"""

from __future__ import annotations

import hashlib
import json
import mmap
import os
import shutil
import stat
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import deployment  # noqa: E402
import v3_client  # noqa: E402

DENIED_BY_DAC = "DENIED_BY_DAC"
NOT_DENIED = "NOT_DENIED"
CONTROL_FAILED = "CONTROL_FAILED"
EXPECTED_SUCCESS = "EXPECTED_SUCCESS"
NOT_APPLICABLE = "NOT_APPLICABLE"

CARRIER_PATH = os.path.join(os.path.dirname(HERE), "carrier_matrix.json")
RESULTS_PATH = os.path.join(os.path.dirname(HERE), "attack_results.json")


def _run(cmd, timeout=120, **kwargs):
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False, **kwargs
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(cmd, 127, "", str(exc))


# ----------------------------------------------------------------- digests
def deep_digest(root: str) -> str:
    """Content, type, mode, owner, size, mtime_ns and xattrs of every path."""
    digest = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(dirnames) + sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            try:
                st = os.lstat(full)
            except OSError as exc:
                digest.update(f"{rel}|ERR{exc.errno}".encode())
                continue
            digest.update(
                f"{rel}|{stat.S_IFMT(st.st_mode)}|{oct(st.st_mode & 0o7777)}|"
                f"{st.st_uid}|{st.st_gid}|{st.st_size}|{st.st_mtime_ns}".encode()
            )
            try:
                for attr in sorted(os.listxattr(full, follow_symlinks=False)):
                    digest.update(attr.encode() + os.getxattr(full, attr, follow_symlinks=False))
            except OSError:
                pass
            if stat.S_ISLNK(st.st_mode):
                digest.update(os.readlink(full).encode())
            elif stat.S_ISREG(st.st_mode):
                try:
                    with open(full, "rb") as handle:
                        digest.update(hashlib.sha256(handle.read()).digest())
                except OSError as exc:
                    digest.update(f"UNREADABLE{exc.errno}".encode())
    return digest.hexdigest()


class Target:
    def __init__(self, root: str):
        self.root = root

    @property
    def files(self) -> str:
        return os.path.join(self.root, "files")

    @property
    def file(self) -> str:
        return os.path.join(self.root, "files", "README.md")

    @property
    def newfile(self) -> str:
        return os.path.join(self.root, "files", "planted.md")


def build_control(store: str, control_root: str) -> Target:
    shutil.rmtree(control_root, ignore_errors=True)
    shutil.copytree(
        store,
        control_root,
        symlinks=True,
        ignore=shutil.ignore_patterns("*.sock", "*.key"),
    )
    return Target(control_root)


# ---------------------------------------------------------------- carriers
def c_create(t, ctx):
    with open(t.newfile, "w", encoding="utf-8") as handle:
        handle.write("planted\n")


def c_overwrite(t, ctx):
    with open(t.file, "w", encoding="utf-8") as handle:
        handle.write("overwritten\n")


def c_append(t, ctx):
    with open(t.file, "a", encoding="utf-8") as handle:
        handle.write("appended\n")


def c_truncate(t, ctx):
    os.truncate(t.file, 0)


def c_unlink(t, ctx):
    os.unlink(t.file)


def c_rename_source(t, ctx):
    os.rename(t.file, t.file + ".moved")


def c_rename_destination(t, ctx):
    os.rename(ctx["payload"], t.file)


def c_hardlink(t, ctx):
    os.link(ctx["payload"], os.path.join(t.files, "linked.md"))


def c_symlink_replacement(t, ctx):
    temporary = os.path.join(t.files, ".attacker-link")
    os.symlink(ctx["payload"], temporary)
    os.rename(temporary, t.file)


def c_chmod(t, ctx):
    os.chmod(t.file, 0o600)


def c_exec_bit(t, ctx):
    os.chmod(t.file, 0o755)


def c_chown(t, ctx):
    current = os.stat(t.file).st_gid
    alternates = [gid for gid in os.getgroups() if gid != current]
    os.chown(t.file, os.getuid(), alternates[0] if alternates else current)


def c_utime(t, ctx):
    os.utime(t.file, (1000000000, 1000000000))


def c_xattr(t, ctx):
    os.setxattr(t.file, "user.cspa3", b"attacker")


def c_acl(t, ctx):
    result = _run(["setfacl", "-m", f"u:{os.getuid()}:rwx", t.file])
    if result.returncode != 0:
        raise OSError(result.stderr.strip()[:120] or "setfacl failed")


def c_directory_entry(t, ctx):
    os.mkdir(os.path.join(t.files, "planted-dir"))


def c_atomic_replace(t, ctx):
    temporary = t.file + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        handle.write("atomic\n")
    os.rename(temporary, t.file)


def c_temp_then_rename(t, ctx):
    temporary = os.path.join(t.files, ".staged")
    with open(temporary, "w", encoding="utf-8") as handle:
        handle.write("staged\n")
    os.replace(temporary, t.file)


def c_shell_redirect(t, ctx):
    _run(["/bin/sh", "-c", f"echo shell > {t.file}"])


def c_subprocess(t, ctx):
    _run(["cp", ctx["payload"], t.file])


def c_mmap(t, ctx):
    fd = os.open(t.file, os.O_RDWR)
    try:
        with mmap.mmap(fd, 0) as region:
            region[0:3] = b"PWN"
            region.flush()
    finally:
        os.close(fd)


def c_git_checkout(t, ctx):
    _run(
        [
            "git",
            f"--git-dir={ctx['git_dir']}",
            f"--work-tree={t.files}",
            "checkout",
            "HEAD",
            "--",
            ".",
        ]
    )


def c_git_reset(t, ctx):
    _run(
        [
            "git",
            f"--git-dir={ctx['git_dir']}",
            f"--work-tree={t.files}",
            "reset",
            "--hard",
            "HEAD",
        ]
    )


def c_git_restore(t, ctx):
    _run(
        [
            "git",
            f"--git-dir={ctx['git_dir']}",
            f"--work-tree={t.files}",
            "restore",
            "--source=HEAD",
            "--",
            ".",
        ]
    )


def c_git_worktree_add(t, ctx):
    _run(
        [
            "git",
            f"--git-dir={ctx['git_dir']}",
            "worktree",
            "add",
            "--detach",
            os.path.join(t.files, "wt"),
        ]
    )


CARRIERS = [
    ("create", c_create),
    ("overwrite", c_overwrite),
    ("append", c_append),
    ("truncate", c_truncate),
    ("unlink", c_unlink),
    ("rename_source", c_rename_source),
    ("rename_destination", c_rename_destination),
    ("hardlink", c_hardlink),
    ("symlink_replacement", c_symlink_replacement),
    ("chmod", c_chmod),
    ("exec_bit_transition", c_exec_bit),
    ("chown", c_chown),
    ("utime", c_utime),
    ("xattr", c_xattr),
    ("acl_change", c_acl),
    ("directory_entry_mutation", c_directory_entry),
    ("atomic_replace", c_atomic_replace),
    ("temp_file_then_rename", c_temp_then_rename),
    ("shell_redirection", c_shell_redirect),
    ("subprocess", c_subprocess),
    ("mmap_write", c_mmap),
    ("git_checkout", c_git_checkout),
    ("git_reset_hard", c_git_reset),
    ("git_restore", c_git_restore),
    ("git_worktree_add", c_git_worktree_add),
]


def run_carrier(name, fn, canonical: Target, control: Target, ctx) -> dict:
    control_before = deep_digest(control.root)
    control_error = None
    try:
        fn(control, ctx)
    except Exception as exc:
        control_error = f"{type(exc).__name__}: {exc}"
    control_effect = deep_digest(control.root) != control_before

    before = deep_digest(canonical.root)
    attack_error = None
    try:
        fn(canonical, ctx)
    except Exception as exc:
        attack_error = f"{type(exc).__name__}: {exc}"
    changed = deep_digest(canonical.root) != before

    if not control_effect:
        verdict = CONTROL_FAILED
    elif changed:
        verdict = NOT_DENIED
    else:
        verdict = DENIED_BY_DAC
    return {
        "carrier": name,
        "verdict": verdict,
        "control_changed_mirror": control_effect,
        "control_error": control_error,
        "canonical_changed": changed,
        "attack_error": attack_error,
    }


def carrier_phase(dep) -> list[dict]:
    canonical = Target(dep.store)
    control_root = os.path.join(dep.workspace, "control-store")
    payload = os.path.join(dep.workspace, "payload.md")
    with open(payload, "w", encoding="utf-8") as handle:
        handle.write("payload\n")

    work = os.path.join(dep.workspace, "attack-git")
    os.makedirs(work, exist_ok=True)
    _run(["git", "init", "-q", work])
    _run(["git", "-C", work, "config", "user.email", "a@b"])
    _run(["git", "-C", work, "config", "user.name", "a"])
    with open(os.path.join(work, "README.md"), "w", encoding="utf-8") as handle:
        handle.write("from git\n")
    _run(["git", "-C", work, "add", "-A"])
    _run(["git", "-C", work, "commit", "-qm", "attack payload"])

    ctx = {"payload": payload, "git_dir": os.path.join(work, ".git")}
    results = []
    for name, fn in CARRIERS:
        control = build_control(dep.store, control_root)
        # rename_destination consumes the payload; rebuild it each time.
        with open(payload, "w", encoding="utf-8") as handle:
            handle.write("payload\n")
        results.append(run_carrier(name, fn, canonical, control, ctx))
    shutil.rmtree(control_root, ignore_errors=True)
    return results


# ------------------------------------------------------- named attacks D-R
def attack_subuid_remap(dep) -> dict:
    """D: the escalation that defeated V2's self-provisioned identity."""
    target = os.path.join(dep.store, "files", "README.md")
    before = deep_digest(dep.store)
    script = os.path.join(dep.workspace, "remap.py")
    with open(script, "w", encoding="utf-8") as handle:
        handle.write(
            "import os,subprocess,sys\n"
            "r1,w1=os.pipe(); r2,w2=os.pipe()\n"
            "pid=os.fork()\n"
            "if pid==0:\n"
            "    os.unshare(os.CLONE_NEWUSER); os.write(w2,b'x'); os.read(r1,1)\n"
            "    os.setgroups([]); os.setgid(1); os.setuid(1)\n"
            "    os.execvp('/bin/sh',['/bin/sh','-c',sys.argv[1]])\n"
            "os.read(r2,1)\n"
            "base=open('/etc/subuid').read().split(':')[1]\n"
            "subprocess.run(['newuidmap',str(pid),'0',str(os.getuid()),'1','1',base,'65536'])\n"
            "subprocess.run(['newgidmap',str(pid),'0',str(os.getgid()),'1','1',base,'65536'])\n"
            "os.write(w1,b'x'); os.waitpid(pid,0)\n"
        )
    proc = _run(["python3", script, f"echo remapped > {target}"])
    changed = deep_digest(dep.store) != before
    return {
        "attack": "D_delegated_subuid_remap",
        "changed_canonical": changed,
        "verdict": NOT_DENIED if changed else DENIED_BY_DAC,
        "stderr": proc.stderr.strip()[:200],
        "why": "the delegated range tops out at 589823; uid 940 is not in it, so "
        "remapping lands on a principal with no authority over the store",
    }


def attack_setns(dep) -> dict:
    """E: namespace re-entry, by both available routes."""
    pids = _run(["docker", "inspect", "-f", "{{.State.Pid}}", dep.container])
    container_pid = pids.stdout.strip()
    procfs = {"route": "/proc/<pid>/ns via the namespace boundary"}
    try:
        fd = os.open(f"/proc/{container_pid}/ns/mnt", os.O_RDONLY)
        os.close(fd)
        procfs["openable"] = True
    except OSError as exc:
        procfs["openable"] = False
        procfs["error"] = exc.strerror
    procfs["verdict"] = NOT_DENIED if procfs["openable"] else DENIED_BY_DAC

    before = deep_digest(dep.store)
    exec_result = _run(
        [
            "docker",
            "exec",
            "--user",
            "0:0",
            dep.container,
            "sh",
            "-c",
            "echo docker-exec > /srv/canonical/files/README.md",
        ]
    )
    changed = deep_digest(dep.store) != before
    docker_route = {
        "route": "docker exec, i.e. the root-equivalent socket",
        "changed_canonical": changed,
        "verdict": EXPECTED_SUCCESS if changed else DENIED_BY_DAC,
        "stderr": exec_result.stderr.strip()[:160],
        "why": "this is not a namespace weakness. It is the Docker socket, and "
        "its remediation is removing that socket, not changing namespaces.",
    }
    if changed:
        _restore(dep, "README.md", "canonical seed\n")
    return {
        "attack": "E_setns_reentry",
        "procfs_route": procfs,
        "docker_route": docker_route,
    }


def attack_ptrace(dep) -> dict:
    """F/G: non-descendant ptrace of the authority, with a working control."""
    pids = _run(["docker", "inspect", "-f", "{{.State.Pid}}", dep.container])
    container_pid = pids.stdout.strip()
    broker_pid = None
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            st = os.stat(f"/proc/{pid}")
            with open(f"/proc/{pid}/cmdline", "rb") as handle:
                cmdline = handle.read().decode(errors="replace")
        except OSError:
            continue
        if st.st_uid == dep.broker_uid and "--mode" in cmdline and "broker" in cmdline:
            broker_pid = int(pid)
            break

    script = os.path.join(dep.workspace, "ptrace_probe.py")
    with open(script, "w", encoding="utf-8") as handle:
        handle.write(
            "import ctypes,os,sys\n"
            "libc=ctypes.CDLL('libc.so.6',use_errno=True)\n"
            "pid=int(sys.argv[1]); ctypes.set_errno(0)\n"
            "rc=libc.ptrace(16,pid,0,0); err=ctypes.get_errno()\n"
            "if rc==0:\n"
            "    os.waitpid(pid,0); libc.ptrace(17,pid,0,0); print('ATTACHED')\n"
            "else:\n"
            "    print('DENIED',os.strerror(err))\n"
        )
    # Positive control: the same technique against a process the agent owns.
    control_proc = subprocess.Popen(["sleep", "20"])
    time.sleep(0.3)
    control = _run(["setsid", "python3", script, str(control_proc.pid)])
    control_proc.kill()
    control_proc.wait()

    outcome = {
        "attack": "F_nondescendant_ptrace",
        "control_attached_agent_owned_process": "ATTACHED" in control.stdout,
        "broker_pid_found": broker_pid,
    }
    if broker_pid is None:
        outcome["verdict"] = NOT_APPLICABLE
        outcome["detail"] = "no host-visible broker process found"
        return outcome
    attack = _run(["setsid", "python3", script, str(broker_pid)])
    attached = "ATTACHED" in attack.stdout
    outcome["stdout"] = attack.stdout.strip()[:160]
    outcome["attached_authority"] = attached
    outcome["verdict"] = NOT_DENIED if attached else DENIED_BY_DAC
    outcome["mem_readable"] = _readable(f"/proc/{broker_pid}/mem")
    outcome["maps_readable"] = _readable(f"/proc/{broker_pid}/maps")
    outcome["why"] = (
        "ptrace_may_access requires matching uid or CAP_SYS_PTRACE in the "
        "target's user namespace. The authority is uid 940, which the agent "
        "cannot become -- so ptrace_scope=0 no longer helps it. This is the "
        "direct reversal of V2's result."
    )
    outcome["container_pid"] = container_pid
    return outcome


def _readable(path: str) -> bool:
    try:
        with open(path, "rb"):
            return True
    except OSError:
        return False


def attack_container_roots(dep) -> dict:
    """H and I: rootful vs rootless container root against the store."""
    target = "files/README.md"
    results = {}

    before = deep_digest(dep.store)
    rootful = _run(
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
            f"{dep.store}:/mnt",
            dep.image,
            "-c",
            f"echo rootful-root > /mnt/{target} && chown 0:0 /mnt/{target} && echo ok",
        ],
        timeout=180,
    )
    changed = deep_digest(dep.store) != before
    results["H_rootful_container_root"] = {
        "changed_canonical": changed,
        "verdict": EXPECTED_SUCCESS if changed else DENIED_BY_DAC,
        "stdout": rootful.stdout.strip()[:80],
        "why": "real host root; DAC does not apply to it and is not claimed to",
    }
    if changed:
        _restore(dep, "README.md", "canonical seed\n", fix_owner=True)

    podman_image = None
    if shutil.which("podman"):
        # podman resolves image names from its own store and refuses a
        # short name without a TTY. Using docker's name made the container
        # never start, and a container that never starts is not evidence
        # that a rootless container cannot mutate the store.
        listing = _run(["podman", "images", "--format", "{{.Repository}}:{{.Tag}}"], timeout=120)
        for line in listing.stdout.splitlines():
            if line.strip() and "<none>" not in line and "/" in line:
                podman_image = line.strip()
                break
    if podman_image:
        before = deep_digest(dep.store)
        rootless = _run(
            [
                "podman",
                "run",
                "--rm",
                "--network",
                "none",
                "--user",
                "0:0",
                "--security-opt",
                "label=disable",
                "-v",
                f"{dep.store}:/mnt",
                dep.image,
                "sh",
                "-c",
                f"echo rootless-root > /mnt/{target} 2>&1; chown 0:0 /mnt/{target} 2>&1; echo done",
            ],
            timeout=240,
        )
        changed = deep_digest(dep.store) != before
        results["I_rootless_container_root"] = {
            "changed_canonical": changed,
            "verdict": NOT_DENIED if changed else DENIED_BY_DAC,
            "output": (rootless.stdout + rootless.stderr).strip()[:240],
            "why": "rootless container root maps to the agent uid or its "
            "delegated subuid range, neither of which owns the store",
        }
        if changed:
            _restore(dep, "README.md", "canonical seed\n", fix_owner=True)
    else:
        results["I_rootless_container_root"] = {
            "verdict": NOT_APPLICABLE,
            "detail": "podman absent, or no fully-qualified local image to run",
        }
    return results


def attack_broker_replacement(dep) -> dict:
    """J: can the agent replace the broker or its control plane?

    Three routes, because only reporting the one that fails would describe a
    system nobody built.
    """
    code_file = os.path.join(dep.code, "v3_authority.py")
    results = {}

    try:
        with open(code_file, "a", encoding="utf-8") as handle:
            handle.write("\n# injected\n")
        results["J1_host_write_to_code"] = {
            "verdict": NOT_DENIED,
            "detail": "append succeeded",
        }
    except OSError as exc:
        results["J1_host_write_to_code"] = {
            "verdict": DENIED_BY_DAC,
            "detail": exc.strerror,
        }

    planted = os.path.join(dep.workspace, "replacement.py")
    with open(planted, "w", encoding="utf-8") as handle:
        handle.write("# attacker-controlled broker\n")
    copy_result = _run(
        ["docker", "cp", planted, f"{dep.container}:/srv/code/v3_authority.py"],
        timeout=180,
    )
    results["J2_docker_cp_into_container"] = {
        "verdict": EXPECTED_SUCCESS if copy_result.returncode == 0 else DENIED_BY_DAC,
        "returncode": copy_result.returncode,
        "stderr": copy_result.stderr.strip()[:160],
        "why": "the Docker socket writes into the authority's filesystem regardless of who owns it",
    }

    inspect = _run(["docker", "inspect", "-f", "{{.State.Running}}", dep.container])
    results["J3_replace_whole_authority"] = {
        "verdict": EXPECTED_SUCCESS,
        "detail": "the agent can 'docker rm -f' this container and start its own "
        "with substituted code; the container is running under the "
        "agent's own Docker authority",
        "container_running": inspect.stdout.strip(),
        "not_executed": "the destructive form is not run because it would end the "
        "measurement; J2 already demonstrates write access to the "
        "authority's code, which is the same capability",
    }
    # Derived from the two *measured* routes only. J3 is an annotated
    # non-measurement -- its destructive form would end the run -- and a
    # hardcoded EXPECTED_SUCCESS must not feed a computed condition, or the
    # flag would read true even if J1 and J2 had both been denied.
    results["control_plane_agent_replaceable"] = any(
        results[name]["verdict"] in (NOT_DENIED, EXPECTED_SUCCESS)
        for name in ("J1_host_write_to_code", "J2_docker_cp_into_container")
    )
    results["derived_from"] = ["J1_host_write_to_code", "J2_docker_cp_into_container"]
    return results


def attack_socket_impersonation(dep) -> dict:
    """K: can the agent unlink the authority socket and bind a lookalike?"""
    socket_path = dep.broker_socket
    outcome = {"attack": "K_socket_impersonation"}
    try:
        os.unlink(socket_path)
        outcome["verdict"] = NOT_DENIED
        outcome["detail"] = "agent unlinked the authority socket"
    except OSError as exc:
        outcome["verdict"] = DENIED_BY_DAC
        outcome["detail"] = exc.strerror
    try:
        os.rename(socket_path, socket_path + ".stolen")
        outcome["rename"] = NOT_DENIED
    except OSError as exc:
        outcome["rename"] = f"denied ({exc.strerror})"
    outcome["runtime_dir_mode"] = oct(os.stat(dep.runtime).st_mode & 0o7777)
    outcome["runtime_dir_owner"] = os.stat(dep.runtime).st_uid
    return outcome


def attack_key_material(dep) -> dict:
    """Q: can the agent read the receipt key and mint its own authority?"""
    outcome = {"attack": "Q_authority_key_material", "key_file": dep.key_file}
    try:
        with open(dep.key_file, "rb") as handle:
            handle.read()
        outcome["verdict"] = NOT_DENIED
        outcome["detail"] = "agent read the signing key"
    except OSError as exc:
        outcome["verdict"] = DENIED_BY_DAC
        outcome["detail"] = exc.strerror
    try:
        st = os.stat(dep.key_file)
        outcome["mode"] = oct(st.st_mode & 0o7777)
        outcome["owner_uid"] = st.st_uid
        outcome["owner_gid"] = st.st_gid
    except OSError as exc:
        outcome["stat_error"] = exc.strerror
    return outcome


def protocol_attacks(dep) -> dict:
    """L, M, N and the authorized path: the broker's own decisions."""
    outcomes = {}

    def record(name, expected, response, extra=None):
        outcomes[name] = {
            "expected": expected,
            "actual": response.get("result"),
            "pass": response.get("result") == expected,
            **(extra or {}),
        }

    before = v3_client.state_hash(dep.store)
    payload = b"print('authorized v2')\n"
    good = v3_client.propose(dep, "src/app.py", payload)
    after = v3_client.state_hash(dep.store)
    outcomes["POSITIVE_authorized_promotion"] = {
        "expected": "PROMOTED",
        "actual": good.get("result"),
        "pass": good.get("result") == "PROMOTED" and before != after,
        "before": before,
        "after": after,
        "matches_receipt": good.get("matches_receipt"),
    }
    receipt = good.get("receipt")

    record("M_replayed_receipt", "DENIED_REPLAY", v3_client.promote(dep, receipt, payload))

    for field, value in (
        ("resource", "00000000"),
        ("actor", "agent:other"),
        ("path", "../escape"),
        ("content_sha256", "0" * 64),
        ("expected_after_hash", "1" * 64),
    ):
        tampered = dict(receipt)
        tampered[field] = value
        record(
            f"tampered_{field}",
            "DENIED_SIGNATURE",
            v3_client.promote(dep, tampered, payload),
        )

    fresh = v3_client.decide(dep, "src/app.py", b"stale-base\n")
    v3_client.propose(dep, "src/other.py", b"advance the state\n")
    record(
        "stale_before_hash",
        "DENIED_STALE",
        v3_client.promote(dep, fresh["receipt"], b"stale-base\n"),
    )

    swap = v3_client.decide(dep, "src/app.py", b"authorized bytes\n")
    record(
        "N_toctou_payload_swap",
        "DENIED_EFFECT_MISMATCH",
        v3_client.promote(dep, swap["receipt"], b"substituted bytes\n"),
    )

    escape = v3_client.decide(dep, "../../../../etc/passwd", b"escape\n")
    if escape.get("result") == "ALLOW":
        record(
            "path_escape",
            "DENIED_PATH_ESCAPE",
            v3_client.promote(dep, escape["receipt"], b"escape\n"),
        )
    else:
        outcomes["path_escape"] = {
            "expected": "denied at the decision layer",
            "actual": escape.get("result"),
            "pass": True,
        }

    spoof = v3_client.request(
        dep.broker_socket, {"kind": "status", "uid": 940, "peer": {"uid": 940}}
    )
    outcomes["identity_spoof_in_message"] = {
        "expected": f"kernel peer uid {dep.agent_uid}",
        "actual": spoof.get("peer"),
        "pass": spoof.get("peer", {}).get("uid") == dep.agent_uid,
        "note": "SO_PEERCRED pid is 0 across the container's pid namespace; the "
        "broker checks uid only, and a systemd deployment would see a "
        "meaningful pid",
    }
    outcomes["failures"] = [
        name
        for name, entry in outcomes.items()
        if isinstance(entry, dict) and not entry.get("pass")
    ]
    return outcomes


def leakage_phase(dep) -> dict:
    """Section 10: does an authorized effect mint a reusable capability?"""
    results = {}
    promoted = os.path.join(dep.store, "files", "src", "app.py")
    results["broker_created_file_ownership"] = {
        "owner_uid": os.stat(promoted).st_uid if os.path.exists(promoted) else None,
        "agent_uid": dep.agent_uid,
        "agent_writable": os.access(promoted, os.W_OK),
        "verdict": DENIED_BY_DAC if not os.access(promoted, os.W_OK) else NOT_DENIED,
    }
    try:
        fd = os.open(promoted, os.O_RDWR)
        os.close(fd)
        results["writable_fd_after_promotion"] = {"verdict": NOT_DENIED}
    except OSError as exc:
        results["writable_fd_after_promotion"] = {
            "verdict": DENIED_BY_DAC,
            "detail": exc.strerror,
        }
    try:
        fd = os.open(os.path.join(dep.store, "files"), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.open("leaked", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd)
            results["directory_fd_write"] = {"verdict": NOT_DENIED}
        except OSError as exc:
            results["directory_fd_write"] = {
                "verdict": DENIED_BY_DAC,
                "detail": exc.strerror,
            }
        finally:
            os.close(fd)
    except OSError as exc:
        results["directory_fd_write"] = {
            "verdict": DENIED_BY_DAC,
            "detail": exc.strerror,
        }
    staging = [
        name
        for name in os.listdir(os.path.join(dep.store, "files"))
        if name.startswith(".staging-")
    ]
    results["staging_residue"] = {
        "leftovers": staging,
        "verdict": DENIED_BY_DAC if not staging else NOT_DENIED,
    }
    results["all_denied"] = all(
        entry.get("verdict") == DENIED_BY_DAC
        for entry in results.values()
        if isinstance(entry, dict) and "verdict" in entry
    )
    return results


def workspace_git_phase(dep) -> dict:
    """Section 12: ordinary development must remain possible."""
    sys.path.insert(0, os.path.join(os.path.dirname(HERE), ".."))
    repo = os.path.join(dep.workspace, "devrepo")
    os.makedirs(repo, exist_ok=True)
    checks = []

    def check(name, ran, observed, detail=""):
        checks.append(
            {
                "operation": name,
                "exit_code": None if ran is None else ran.returncode,
                "observed_effect": observed,
                "pass": observed,
                "detail": detail,
            }
        )

    ran = _run(["git", "-C", repo, "init", "-q", "-b", "main"])
    check("git init", ran, os.path.isdir(os.path.join(repo, ".git")))
    _run(["git", "-C", repo, "config", "user.email", "a@b"])
    _run(["git", "-C", repo, "config", "user.name", "a"])
    path = os.path.join(repo, "app.py")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("print('hi')\n")
    check("file creation", None, os.path.exists(path))
    os.chmod(path, 0o755)
    check("chmod exec bit", None, bool(os.stat(path).st_mode & stat.S_IXUSR))
    ran = _run(["git", "-C", repo, "add", "-A"])
    check(
        "git add",
        ran,
        "app.py" in _run(["git", "-C", repo, "diff", "--cached", "--name-only"]).stdout,
    )
    ran = _run(["git", "-C", repo, "commit", "-qm", "first"])
    head = _run(["git", "-C", repo, "rev-parse", "HEAD"]).stdout.strip()
    check("git commit", ran, len(head) == 40)
    mode = _run(["git", "-C", repo, "ls-files", "-s", "app.py"]).stdout.split()[:1]
    check("exec bit tracked as 100755", None, mode == ["100755"])
    ran = _run(["git", "-C", repo, "checkout", "-q", "-b", "feature"])
    check(
        "branch creation",
        ran,
        _run(["git", "-C", repo, "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip() == "feature",
    )
    with open(os.path.join(repo, "two.txt"), "w", encoding="utf-8") as handle:
        handle.write("two\n")
    _run(["git", "-C", repo, "add", "-A"])
    _run(["git", "-C", repo, "commit", "-qm", "second"])
    ran = _run(["git", "-C", repo, "switch", "-q", "main"])
    check("checkout / switch", ran, not os.path.exists(os.path.join(repo, "two.txt")))
    _run(["git", "-C", repo, "switch", "-q", "feature"])
    ran = _run(["git", "-C", repo, "mv", "app.py", "renamed.py"])
    check("git mv", ran, os.path.exists(os.path.join(repo, "renamed.py")))
    _run(["git", "-C", repo, "commit", "-qm", "rename"])
    ran = _run(["git", "-C", repo, "rm", "-q", "two.txt"])
    check("git rm", ran, not os.path.exists(os.path.join(repo, "two.txt")))
    _run(["git", "-C", repo, "commit", "-qm", "delete"])
    patch = os.path.join(dep.workspace, "change.patch")
    with open(patch, "w", encoding="utf-8") as handle:
        handle.write(
            "diff --git a/p.txt b/p.txt\nnew file mode 100644\n"
            "--- /dev/null\n+++ b/p.txt\n@@ -0,0 +1 @@\n+patched\n"
        )
    ran = _run(["git", "-C", repo, "apply", patch])
    check("git apply", ran, os.path.exists(os.path.join(repo, "p.txt")))
    os.chmod(os.path.join(repo, "renamed.py"), 0o644)
    _run(["git", "-C", repo, "add", "-A"])
    ran = _run(["git", "-C", repo, "commit", "-qm", "mode change"])
    mode = _run(["git", "-C", repo, "ls-files", "-s", "renamed.py"]).stdout.split()[:1]
    check("mode change committed", ran, mode == ["100644"])
    ran = _run(["git", "-C", repo, "status", "--porcelain"])
    check("git status", ran, ran.returncode == 0)
    failures = [entry["operation"] for entry in checks if not entry["pass"]]
    return {
        "checks": checks,
        "count": len(checks),
        "failures": failures,
        "all_passed": not failures,
    }


def _restore(dep, name: str, content: str, fix_owner: bool = False) -> None:
    """Put canonical back using the provisioning authority, never the agent."""
    script = f"printf '%s' {json.dumps(content)} > /srv/canonical/files/{name}"
    if fix_owner:
        script += (
            f"; chown -R {dep.broker_uid}:{dep.broker_uid} /srv/canonical"
            f"; chmod -R go-w /srv/canonical"
        )
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
            f"{dep.store}:/srv/canonical",
            dep.image,
            "-c",
            script,
        ],
        timeout=180,
    )


def main() -> int:
    started = time.time()
    dep = deployment.bring_up()
    try:
        carriers = carrier_phase(dep)
        results = {
            "environment": {
                "agent_uid": dep.agent_uid,
                "broker_uid": dep.broker_uid,
                "decision_uid": dep.decision_uid,
                "store_owner_uid": dep.store_owner_uid,
                "code_owner_uid": os.stat(dep.code).st_uid,
                "runtime_dir_mode": oct(os.stat(dep.runtime).st_mode & 0o7777),
                "image": dep.image,
                "roles": dep.roles,
                "identity_model": {
                    "included": ["file content", "executable bit"],
                    "excluded": [
                        "directories",
                        "owner",
                        "timestamps",
                        "non-exec permission bits",
                        "xattrs",
                    ],
                    "directories_safe_because": "the agent cannot create one; see the "
                    "directory_entry_mutation carrier",
                },
            },
            "carriers": carriers,
            "attacks": {
                "D_subuid": attack_subuid_remap(dep),
                "E_setns": attack_setns(dep),
                "F_ptrace": attack_ptrace(dep),
                "container_roots": attack_container_roots(dep),
                "J_broker_replacement": attack_broker_replacement(dep),
                "K_socket_impersonation": attack_socket_impersonation(dep),
                "Q_key_material": attack_key_material(dep),
            },
            "protocol": protocol_attacks(dep),
            "leakage": leakage_phase(dep),
            "workspace_git": workspace_git_phase(dep),
            "elapsed_seconds": round(time.time() - started, 2),
        }
    finally:
        dep.teardown()

    with open(CARRIER_PATH, "w", encoding="utf-8") as handle:
        json.dump(
            {"carriers": results["carriers"], "environment": results["environment"]},
            handle,
            indent=2,
            sort_keys=True,
        )
    with open(RESULTS_PATH, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2, sort_keys=True, default=str)

    counts: dict[str, int] = {}
    for entry in results["carriers"]:
        counts[entry["verdict"]] = counts.get(entry["verdict"], 0) + 1
    print(
        json.dumps(
            {
                "carriers": len(results["carriers"]),
                "carrier_verdicts": counts,
                "protocol_failures": results["protocol"]["failures"],
                "leakage_all_denied": results["leakage"]["all_denied"],
                "git": f"{results['workspace_git']['count']} checks, "
                f"{results['workspace_git']['failures']} failed",
                "ptrace_authority": results["attacks"]["F_ptrace"]["verdict"],
                "subuid": results["attacks"]["D_subuid"]["verdict"],
                "control_plane_agent_replaceable": results["attacks"]["J_broker_replacement"][
                    "control_plane_agent_replaceable"
                ],
                "elapsed_seconds": results["elapsed_seconds"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
