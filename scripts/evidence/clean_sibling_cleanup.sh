#!/usr/bin/env bash
# Cleanup primitive shared by the clean-sibling prover and its failure tests.

# This helper participates in the proof boundary even when sourced directly.
# Never inherit caller-selected implementations of filesystem or git tools.
for variable in ${!LD_@}; do
  printf 'clean-sibling cleanup rejected ambient loader environment: %s\n' "$variable" >&2
  # shellcheck disable=SC2317
  return 2 2>/dev/null || exit 2
done
for variable in ${!GIT_@}; do
  case "$variable:${!variable}" in
    GIT_CONFIG_NOSYSTEM:1 | GIT_CONFIG_GLOBAL:/dev/null) ;;
    GIT_CONFIG_* | GIT_EXEC_PATH:* | GIT_TEMPLATE_DIR:* | GIT_EXTERNAL_DIFF:* | \
      GIT_ASKPASS:* | GIT_SSH:* | GIT_SSH_COMMAND:* | GIT_PROXY_COMMAND:* | \
      GIT_ALTERNATE_OBJECT_DIRECTORIES:* | GIT_OBJECT_DIRECTORY:* | \
      GIT_INDEX_FILE:* | GIT_WORK_TREE:* | GIT_DIR:* | GIT_COMMON_DIR:* | \
    GIT_NAMESPACE:* | GIT_REPLACE_REF_BASE:* | GIT_ATTR_NOSYSTEM:*)
      printf 'clean-sibling cleanup rejected ambient Git environment: %s\n' "$variable" >&2
      # shellcheck disable=SC2317
      return 2 2>/dev/null || exit 2
      ;;
  esac
done
unset GIT_PAGER GIT_EDITOR GIT_SEQUENCE_EDITOR
PATH=/usr/bin:/bin
export PATH
hash -r

# Standalone callers receive the same Git boundary as the prover.  When the
# prover sourced us its stricter wrapper is already defined and is preserved.
if ! declare -F git >/dev/null; then
  GIT_CONFIG_NOSYSTEM=1
  GIT_CONFIG_GLOBAL=/dev/null
  HOME=/dev/null
  XDG_CONFIG_HOME=/dev/null
  export GIT_CONFIG_NOSYSTEM GIT_CONFIG_GLOBAL HOME XDG_CONFIG_HOME
  git() {
    /usr/bin/git --no-optional-locks \
      -c core.hooksPath=/dev/null \
      -c core.fsmonitor=false \
      -c core.untrackedCache=false \
      -c credential.helper= \
      -c core.askPass= \
      -c core.attributesFile=/dev/null \
      "$@"
  }
fi

clean_sibling_reject_control_path() {
  local label="$1"
  local value="$2"
  local had_lc_all=0
  local saved_lc_all=''
  if [[ "${LC_ALL+x}" == x ]]; then
    had_lc_all=1
    saved_lc_all="$LC_ALL"
  fi
  LC_ALL=C
  case "$value" in
    *[![:print:]]*)
      if [[ "$had_lc_all" == 1 ]]; then
        LC_ALL="$saved_lc_all"
      else
        unset LC_ALL
      fi
      printf 'cleanup refused control-character path: %s\n' "$label" >&2
      return 2
      ;;
  esac
  if [[ "$had_lc_all" == 1 ]]; then
    LC_ALL="$saved_lc_all"
  else
    unset LC_ALL
  fi
}

clean_sibling_worktree_list_contains() {
  local listing="$1"
  local worktree="$2"
  printf '%s\n' "$listing" | awk '
    BEGIN {
      expected = ARGV[1]
      ARGV[1] = ""
      found = 0
    }
    $0 == expected { found = 1 }
    END { exit found ? 0 : 1 }
  ' "worktree $worktree"
}

clean_sibling_worktree_paths_digest() {
  local listing="$1"

  printf '%s\n' "$listing" | awk '
    /^worktree / {
      print substr($0, 10)
    }
  ' | /usr/bin/sha256sum | /usr/bin/awk '{print $1}'
}

clean_sibling_snapshot_worktree_registry() {
  local registry_root="$1"
  local expected_identity="${2:-}"
  local snapshot_python="${SNAPSHOT_PYTHON:-/usr/bin/python3}"

  [[ "$registry_root" == /* ]] || return 2
  if [[ ! -e "$registry_root" && ! -L "$registry_root" ]]; then
    printf 'empty:%s\n' "$(printf '' | /usr/bin/sha256sum | /usr/bin/awk '{print $1}')"
    return 0
  fi
  [[ -d "$registry_root" && ! -L "$registry_root" ]] || {
    printf 'cleanup refused because worktree registry enumeration failed: %s\n' \
      "$registry_root" >&2
    return 2
  }
  if [[ -n "$expected_identity" ]]; then
    [[ "$expected_identity" =~ ^[0-9]+:[0-9]+:[0-9]+$ ]] || return 2
  fi
  "$snapshot_python" - "$registry_root" "$expected_identity" <<'PY'
import base64
import hashlib
import json
import os
import stat
import struct
import sys


def fail(message: str) -> "None":
    print(message, file=sys.stderr)
    raise SystemExit(2)


def field(tag: bytes, payload: bytes) -> bytes:
    return tag + struct.pack(">Q", len(payload)) + payload


def reject_control_text(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def read_safe_file(directory_fd: int, name: str, label: str, required: bool) -> bytes:
    try:
        file_fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
    except OSError as exc:
        if not required and exc.errno == 2:
            return b""
        fail(f"cleanup refused because worktree registry {label} read failed: {exc}")
    try:
        file_stat = os.fstat(file_fd)
        if (not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink != 1 or
                file_stat.st_uid != os.getuid()):
            fail(f"cleanup refused because worktree registry {label} identity changed")
        data = os.read(file_fd, 4096)
        if os.read(file_fd, 1):
            fail(f"cleanup refused because worktree registry {label} is too large")
    finally:
        os.close(file_fd)
    return data


def validate_single_line_path(data: bytes, label: str, *, must_be_absolute: bool) -> None:
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        fail(f"cleanup refused because worktree registry {label} is malformed")
    raw_path = data[:-1]
    if b"\0" in raw_path or any(byte < 32 or byte == 127 for byte in raw_path):
        fail(f"cleanup refused because worktree registry {label} is malformed")
    if must_be_absolute and not raw_path.startswith(b"/"):
        fail(f"cleanup refused because worktree registry {label} is malformed")


def stat_identity(file_stat: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_uid,
        stat.S_IMODE(file_stat.st_mode),
        file_stat.st_nlink,
        file_stat.st_size,
    )


def read_registered_gitfile(gitfile_path: str, registry_root: str, name: str) -> tuple[os.stat_result, bytes]:
    try:
        gitfile_fd = os.open(
            gitfile_path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        )
    except OSError as exc:
        fail(f"cleanup refused because worktree registry gitdir target is unreadable: {exc}")
    try:
        before = os.fstat(gitfile_fd)
        if not stat.S_ISREG(before.st_mode):
            fail("cleanup refused because worktree registry gitdir target is unsafe")
        if before.st_uid != os.getuid() or before.st_nlink != 1:
            fail("cleanup refused because worktree registry gitdir target identity is unsafe")
        data = os.read(gitfile_fd, 4096)
        if os.read(gitfile_fd, 1):
            fail("cleanup refused because worktree registry gitdir target is too large")
        expected = b"gitdir: " + os.fsencode(os.path.join(registry_root, name)) + b"\n"
        if data != expected:
            fail("cleanup refused because worktree registry gitdir target binding is malformed")
        after = os.fstat(gitfile_fd)
        if stat_identity(after) != stat_identity(before):
            fail("cleanup refused because worktree registry gitdir target changed during snapshot")
    finally:
        os.close(gitfile_fd)
    return before, data


root = sys.argv[1]
expected_identity = sys.argv[2]
expected = None
if expected_identity:
    expected = tuple(int(part) for part in expected_identity.split(":"))

try:
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
except OSError as exc:
    fail(f"cleanup refused because worktree registry enumeration failed: {exc}")

try:
    root_stat = os.fstat(root_fd)
    if expected is not None and (
            root_stat.st_dev, root_stat.st_ino, root_stat.st_uid) != expected:
        fail("cleanup refused because worktree registry identity changed")
    chunks = []
    for name in sorted(os.listdir(root_fd), key=os.fsencode):
        if reject_control_text(name):
            fail("cleanup refused control-character worktree registry entry")
        try:
            entry_stat = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except OSError as exc:
            fail(f"cleanup refused because worktree registry enumeration failed: {exc}")
        if stat.S_ISLNK(entry_stat.st_mode) or not stat.S_ISDIR(entry_stat.st_mode):
            fail(f"cleanup refused because worktree registry entry is not a directory: {name}")
        try:
            entry_fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=root_fd,
            )
        except OSError as exc:
            fail(f"cleanup refused because worktree registry enumeration failed: {exc}")
        try:
            gitdir = read_safe_file(entry_fd, "gitdir", "gitdir", required=True)
            validate_single_line_path(gitdir, "gitdir", must_be_absolute=True)
            gitfile_path = os.fsdecode(gitdir[:-1])
            gitfile_stat, gitfile_data = read_registered_gitfile(gitfile_path, root, name)
            commondir = read_safe_file(entry_fd, "commondir", "commondir", required=False)
            if commondir:
                validate_single_line_path(commondir, "commondir", must_be_absolute=False)
            chunks.append(b"".join((
                field(b"N", os.fsencode(name)),
                field(b"E", b":".join(str(value).encode() for value in (
                    entry_stat.st_dev,
                    entry_stat.st_ino,
                    entry_stat.st_uid,
                    stat.S_IMODE(entry_stat.st_mode),
                ))),
                field(b"G", gitdir),
                field(b"T", b":".join(str(value).encode() for value in (
                    gitfile_stat.st_dev,
                    gitfile_stat.st_ino,
                    gitfile_stat.st_uid,
                    stat.S_IMODE(gitfile_stat.st_mode),
                    gitfile_stat.st_nlink,
                    gitfile_stat.st_size,
                )) + b":" + hashlib.sha256(gitfile_data).hexdigest().encode()),
                field(b"C", commondir),
            )))
        finally:
            os.close(entry_fd)
finally:
    os.close(root_fd)

prefix = "present" if chunks else "empty"
print(prefix + ":" + hashlib.sha256(b"".join(chunks)).hexdigest())
PY
}

clean_sibling_find_admin_sentinel() {
  local registry_root="$1"
  local expected_identity="$2"
  local sentinel="$3"
  local registry_fd=''
  local snapshot_python="${SNAPSHOT_PYTHON:-/usr/bin/python3}"
  local rc=0

  [[ "$registry_root" == /* && -d "$registry_root" && ! -L "$registry_root" ]] || return 2
  [[ "$expected_identity" =~ ^[0-9]+:[0-9]+:[0-9]+$ ]] || return 2
  [[ "$sentinel" =~ ^[0-9a-f]{64}$ ]] || return 2
  exec {registry_fd}<"$registry_root" || return 2
  "$snapshot_python" - "$registry_fd" "$expected_identity" "$registry_root" "$sentinel" <<'PY'
import errno
import os
import stat
import sys

fd = int(sys.argv[1])
expected = tuple(int(part) for part in sys.argv[2].split(":"))
registry_root = sys.argv[3]
sentinel = (sys.argv[4] + "\n").encode()
try:
    root_stat = os.fstat(fd)
    if (root_stat.st_dev, root_stat.st_ino, root_stat.st_uid) != expected:
        print("cleanup refused because worktree registry identity changed", file=sys.stderr)
        sys.exit(2)
    for name in os.listdir(fd):
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
            print("cleanup refused control-character worktree registry entry", file=sys.stderr)
            sys.exit(2)
        try:
            entry_stat = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except OSError as exc:
            print(f"cleanup refused because worktree registry enumeration failed: {exc}", file=sys.stderr)
            sys.exit(2)
        if stat.S_ISLNK(entry_stat.st_mode) or not stat.S_ISDIR(entry_stat.st_mode):
            print(f"cleanup refused because worktree registry entry is not a directory: {name}", file=sys.stderr)
            sys.exit(2)
        try:
            entry_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        except OSError as exc:
            print(f"cleanup refused because worktree registry enumeration failed: {exc}", file=sys.stderr)
            sys.exit(2)
        try:
            try:
                sentinel_fd = os.open(
                    "acgs-clean-sibling-owner",
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                    dir_fd=entry_fd,
                )
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    continue
                print(f"cleanup refused because worktree registry sentinel read failed: {exc}", file=sys.stderr)
                sys.exit(2)
            with os.fdopen(sentinel_fd, "rb") as handle:
                sentinel_stat = os.fstat(handle.fileno())
                if not stat.S_ISREG(sentinel_stat.st_mode) or sentinel_stat.st_nlink != 1:
                    print("cleanup refused because worktree admin sentinel is not a regular file", file=sys.stderr)
                    sys.exit(2)
                if stat.S_ISLNK(sentinel_stat.st_mode) or sentinel_stat.st_uid != os.getuid():
                    print("cleanup refused because worktree admin sentinel identity changed", file=sys.stderr)
                    sys.exit(2)
                if stat.S_IMODE(sentinel_stat.st_mode) != 0o600:
                    print("cleanup refused because worktree admin sentinel mode changed", file=sys.stderr)
                    sys.exit(2)
                if handle.read(4096) == sentinel:
                    print(os.path.join(registry_root, name))
        finally:
            os.close(entry_fd)
except Exception as exc:
    print(f"cleanup refused because worktree registry enumeration failed: {exc}", file=sys.stderr)
    sys.exit(2)
PY
  rc=$?
  exec {registry_fd}<&-
  return "$rc"
}

clean_sibling_find_linked_gitfile_registration() {
  local registry_root="$1"
  local expected_registry_identity="$2"
  local expected_gitfile_identity="$3"
  local registry_fd=''
  local snapshot_python="${SNAPSHOT_PYTHON:-/usr/bin/python3}"
  local rc=0

  [[ "$registry_root" == /* && -d "$registry_root" && ! -L "$registry_root" ]] || return 2
  [[ "$expected_registry_identity" =~ ^[0-9]+:[0-9]+:[0-9]+$ ]] || return 2
  [[ "$expected_gitfile_identity" =~ ^[0-9]+:[0-9]+:[0-9]+$ ]] || return 2
  exec {registry_fd}<"$registry_root" || return 2
  "$snapshot_python" - "$registry_fd" "$expected_registry_identity" \
    "$registry_root" "$expected_gitfile_identity" <<'PY'
import errno
import os
import stat
import sys

fd = int(sys.argv[1])
expected_registry = tuple(int(part) for part in sys.argv[2].split(":"))
registry_root = sys.argv[3]
expected_gitfile = tuple(int(part) for part in sys.argv[4].split(":"))


def fail(message: str) -> "None":
    print(message, file=sys.stderr)
    raise SystemExit(2)


def reject_control_text(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


try:
    root_stat = os.fstat(fd)
    if (root_stat.st_dev, root_stat.st_ino, root_stat.st_uid) != expected_registry:
        fail("cleanup refused because worktree registry identity changed")
    for name in os.listdir(fd):
        if reject_control_text(name):
            fail("cleanup refused control-character worktree registry entry")
        try:
            entry_stat = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except OSError as exc:
            fail(f"cleanup refused because worktree registry enumeration failed: {exc}")
        if stat.S_ISLNK(entry_stat.st_mode) or not stat.S_ISDIR(entry_stat.st_mode):
            fail(f"cleanup refused because worktree registry entry is not a directory: {name}")
        try:
            entry_fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=fd,
            )
        except OSError as exc:
            fail(f"cleanup refused because worktree registry enumeration failed: {exc}")
        try:
            try:
                gitdir_fd = os.open(
                    "gitdir",
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                    dir_fd=entry_fd,
                )
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    continue
                fail(f"cleanup refused because worktree gitdir read failed: {exc}")
            try:
                gitdir_stat = os.fstat(gitdir_fd)
                if (not stat.S_ISREG(gitdir_stat.st_mode) or
                        gitdir_stat.st_nlink != 1 or
                        gitdir_stat.st_uid != os.getuid()):
                    fail("cleanup refused because worktree gitdir identity changed")
                data = os.read(gitdir_fd, 4096)
                if os.read(gitdir_fd, 1):
                    fail("cleanup refused because worktree gitdir path is too large")
            finally:
                os.close(gitdir_fd)
            if not data.endswith(b"\n") or data.count(b"\n") != 1:
                fail("cleanup refused because worktree gitdir path is malformed")
            raw_path = data[:-1]
            if (not raw_path.startswith(b"/") or b"\0" in raw_path or
                    any(byte < 32 or byte == 127 for byte in raw_path)):
                fail("cleanup refused because worktree gitdir path is malformed")
            try:
                linked_stat = os.stat(os.fsdecode(raw_path), follow_symlinks=False)
            except OSError as exc:
                fail(f"cleanup refused because worktree gitdir target is unreadable: {exc}")
            if stat.S_ISLNK(linked_stat.st_mode):
                fail("cleanup refused because worktree gitdir target is a symlink")
            if (linked_stat.st_dev, linked_stat.st_ino, linked_stat.st_uid) == expected_gitfile:
                print(os.path.join(registry_root, name))
        finally:
            os.close(entry_fd)
except Exception as exc:
    fail(f"cleanup refused because worktree registry enumeration failed: {exc}")
PY
  rc=$?
  exec {registry_fd}<&-
  return "$rc"
}

clean_sibling_capture_retained_gitfile() {
  local gitfile_fd="$1"
  local gitfile_path="$2"
  local phase="${3:-linked}"
  local snapshot_python="${SNAPSHOT_PYTHON:-/usr/bin/python3}"
  local fd_target=''

  [[ "$gitfile_fd" =~ ^[0-9]+$ ]] || return 2
  [[ "$gitfile_path" == /* ]] || return 2
  case "$phase" in
    linked | unlinked) ;;
    *) return 2 ;;
  esac
  if [[ "$phase" == linked ]]; then
    fd_target="$(/usr/bin/readlink "/proc/$$/fd/$gitfile_fd" 2>/dev/null || true)"
    [[ "$fd_target" == "$gitfile_path" ]] || {
      printf 'cleanup refused because retained worktree gitfile moved/replaced: %s\n' \
        "$gitfile_path" >&2
      return 2
    }
  fi
  "$snapshot_python" - "$gitfile_fd" "$gitfile_path" "$phase" <<'PY'
import base64
import hashlib
import os
import stat
import sys


def fail(message: str) -> "None":
    print(message, file=sys.stderr)
    raise SystemExit(2)


fd = int(sys.argv[1])
path = sys.argv[2]
phase = sys.argv[3]
try:
    fd_stat = os.fstat(fd)
    if not stat.S_ISREG(fd_stat.st_mode):
        fail("cleanup refused because retained worktree gitfile is not a regular file")
    if fd_stat.st_uid != os.getuid():
        fail("cleanup refused because retained worktree gitfile owner changed")
    if phase == "linked":
        path_stat = os.stat(path, follow_symlinks=False)
        if stat.S_ISLNK(path_stat.st_mode):
            fail("cleanup refused because worktree gitfile path is a symlink")
        if (fd_stat.st_dev, fd_stat.st_ino, fd_stat.st_uid) != (
                path_stat.st_dev, path_stat.st_ino, path_stat.st_uid):
            fail("cleanup refused because retained worktree gitfile path changed")
        if fd_stat.st_mode != path_stat.st_mode:
            fail("cleanup refused because retained worktree gitfile mode changed")
        if fd_stat.st_nlink != path_stat.st_nlink:
            fail("cleanup refused because retained worktree gitfile link count changed")
        if fd_stat.st_nlink != 1:
            fail("cleanup refused because retained worktree gitfile link count changed")
    elif phase == "unlinked":
        if os.path.lexists(path):
            fail("cleanup refused because retained worktree gitfile path remains")
        if fd_stat.st_nlink != 0:
            fail("cleanup refused because retained worktree gitfile link count changed")
    else:
        fail("cleanup refused because retained worktree gitfile phase is invalid")
    if fd_stat.st_size > 4096:
        fail("cleanup refused because retained worktree gitfile content is too large")
    dup_fd = os.dup(fd)
    try:
        os.lseek(dup_fd, 0, os.SEEK_SET)
        data = os.read(dup_fd, 4097)
        if len(data) != fd_stat.st_size:
            fail("cleanup refused because retained worktree gitfile content changed")
        if os.read(dup_fd, 1):
            fail("cleanup refused because retained worktree gitfile content is too large")
    finally:
        os.close(dup_fd)
except OSError as exc:
    fail(f"cleanup refused because retained worktree gitfile is unreadable: {exc}")
print(":".join((
    str(fd_stat.st_dev),
    str(fd_stat.st_ino),
    str(fd_stat.st_uid),
    format(stat.S_IMODE(fd_stat.st_mode), "o"),
    str(fd_stat.st_nlink),
    str(fd_stat.st_size),
    hashlib.sha256(data).hexdigest(),
    base64.b64encode(data).decode("ascii"),
)))
PY
}

clean_sibling_validate_retained_gitfile() {
  local gitfile_fd="$1"
  local gitfile_path="$2"
  local expected_identity="$3"
  local expected_mode="$4"
  local expected_links="$5"
  local expected_size="$6"
  local expected_sha256="$7"
  local expected_b64="$8"
  local phase="${9:-linked}"
  local current=''
  local current_device=''
  local current_inode=''
  local current_uid=''
  local current_identity=''
  local current_mode=''
  local current_links=''
  local current_size=''
  local current_sha256=''
  local current_b64=''

  [[ "$gitfile_fd" =~ ^[0-9]+$ ]] || return 2
  [[ "$expected_identity" =~ ^[0-9]+:[0-9]+:[0-9]+$ ]] || return 2
  [[ "$expected_mode" =~ ^[0-7]+$ && "$expected_links" =~ ^[0-9]+$ &&
    "$expected_size" =~ ^[0-9]+$ && "$expected_sha256" =~ ^[0-9a-f]{64}$ ]] || return 2
  case "$phase" in
    linked | unlinked) ;;
    *) return 2 ;;
  esac
  current="$(clean_sibling_capture_retained_gitfile "$gitfile_fd" "$gitfile_path" "$phase")" ||
    return 2
  IFS=: read -r current_device current_inode current_uid current_mode current_links \
    current_size current_sha256 current_b64 <<<"$current"
  current_identity="$current_device:$current_inode:$current_uid"
  if [[ "$current_identity" != "$expected_identity" ||
    "$current_mode" != "$expected_mode" ||
    "$current_links" != "$expected_links" ||
    "$current_size" != "$expected_size" ||
    "$current_sha256" != "$expected_sha256" ||
    "$current_b64" != "$expected_b64" ]]; then
    printf 'cleanup refused because retained worktree gitfile identity or content changed: %s\n' \
      "$gitfile_path" >&2
    return 2
  fi
}

clean_sibling_gitfile_pre_detach_witness() {
  /usr/bin/python3 -I -S - \
    "$WORKTREE_GITFILE_PATH" \
    "$WORKTREE_GITFILE_IDENTITY" \
    "$WORKTREE_GITFILE_MODE" \
    "$WORKTREE_GITFILE_SIZE" \
    "$WORKTREE_GITFILE_SHA256" \
    "$WORKTREE_GITFILE_CONTENT_B64" <<'PY'
import hashlib
import json
import sys

payload = {
    "content_b64": sys.argv[6],
    "identity": sys.argv[2],
    "mode": sys.argv[3],
    "path": sys.argv[1],
    "sha256": sys.argv[5],
    "size": sys.argv[4],
}
encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
print(hashlib.sha256(encoded).hexdigest())
PY
}

clean_sibling_record_worktree_gitfile_pre_detach_witness() {
  [[ "${WORKTREE_GITFILE_RETENTION_REQUIRED:-0}" == 1 ]] || return 0
  [[ -n "${WORKTREE_GITFILE_FD:-}" &&
    -n "${WORKTREE_GITFILE_PATH:-}" &&
    -n "${WORKTREE_GITFILE_IDENTITY:-}" &&
    -n "${WORKTREE_GITFILE_MODE:-}" &&
    -n "${WORKTREE_GITFILE_LINKS:-}" &&
    -n "${WORKTREE_GITFILE_SIZE:-}" &&
    -n "${WORKTREE_GITFILE_SHA256:-}" &&
    -n "${WORKTREE_GITFILE_CONTENT_B64:-}" ]] ||
    return 2
  [[ "$WORKTREE_GITFILE_FD" =~ ^[0-9]+$ &&
    "$WORKTREE_GITFILE_IDENTITY" =~ ^[0-9]+:[0-9]+:[0-9]+$ &&
    "$WORKTREE_GITFILE_MODE" =~ ^[0-7]+$ &&
    "$WORKTREE_GITFILE_LINKS" =~ ^[0-9]+$ &&
    "$WORKTREE_GITFILE_SIZE" =~ ^[0-9]+$ &&
    "$WORKTREE_GITFILE_SHA256" =~ ^[0-9a-f]{64}$ &&
    "$WORKTREE_GITFILE_CONTENT_B64" =~ ^[A-Za-z0-9+/=]+$ ]] ||
    return 2
  [[ -f "$WORKTREE_GITFILE_PATH" && ! -L "$WORKTREE_GITFILE_PATH" ]] || return 2
  clean_sibling_validate_retained_gitfile \
    "$WORKTREE_GITFILE_FD" \
    "$WORKTREE_GITFILE_PATH" \
    "$WORKTREE_GITFILE_IDENTITY" \
    "$WORKTREE_GITFILE_MODE" \
    "$WORKTREE_GITFILE_LINKS" \
    "$WORKTREE_GITFILE_SIZE" \
    "$WORKTREE_GITFILE_SHA256" \
    "$WORKTREE_GITFILE_CONTENT_B64" \
    linked || return 2
  WORKTREE_GITFILE_PRE_DETACH_WITNESS="$(clean_sibling_gitfile_pre_detach_witness)"
  [[ "$WORKTREE_GITFILE_PRE_DETACH_WITNESS" =~ ^[0-9a-f]{64}$ ]] || return 2
}

clean_sibling_close_worktree_gitfile_pre_detach_witness() {
  local gitfile_fd=''
  [[ "${WORKTREE_GITFILE_RETENTION_REQUIRED:-0}" == 1 ]] || return 0
  [[ -n "${WORKTREE_GITFILE_FD:-}" &&
    -n "${WORKTREE_GITFILE_PRE_DETACH_WITNESS:-}" ]] || return 2
  clean_sibling_validate_retained_gitfile \
    "$WORKTREE_GITFILE_FD" \
    "$WORKTREE_GITFILE_PATH" \
    "$WORKTREE_GITFILE_IDENTITY" \
    "$WORKTREE_GITFILE_MODE" \
    "$WORKTREE_GITFILE_LINKS" \
    "$WORKTREE_GITFILE_SIZE" \
    "$WORKTREE_GITFILE_SHA256" \
    "$WORKTREE_GITFILE_CONTENT_B64" \
    linked || return 2
  [[ "$(clean_sibling_gitfile_pre_detach_witness)" == "$WORKTREE_GITFILE_PRE_DETACH_WITNESS" ]] ||
    return 2
  gitfile_fd="$WORKTREE_GITFILE_FD"
  exec {WORKTREE_GITFILE_FD}<&- || return 2
  WORKTREE_GITFILE_FD=''
  [[ ! -e "/proc/$$/fd/$gitfile_fd" && ! -L "/proc/$$/fd/$gitfile_fd" ]] ||
    return 2
  [[ -f "$WORKTREE_GITFILE_PATH" && ! -L "$WORKTREE_GITFILE_PATH" ]] || return 2
}

clean_sibling_initialize_worktree_gitfile_witness() {
  local retained_gitfile=''
  local git_device=''
  local git_inode=''
  local git_uid=''
  [[ "${WORKTREE_ADDED:-0}" == 1 && -n "${WORKTREE:-}" ]] || return 0
  if [[ "${WORKTREE_GITFILE_RETENTION_REQUIRED:-0}" == 1 ||
    -n "${WORKTREE_GITFILE_PRE_DETACH_WITNESS:-}" ]]; then
    return 0
  fi
  WORKTREE_GITFILE_PATH="$WORKTREE/.git"
  [[ -f "$WORKTREE_GITFILE_PATH" && ! -L "$WORKTREE_GITFILE_PATH" ]] || return 2
  exec {WORKTREE_GITFILE_FD}<"$WORKTREE_GITFILE_PATH" || return 2
  retained_gitfile="$(
    clean_sibling_capture_retained_gitfile "$WORKTREE_GITFILE_FD" "$WORKTREE_GITFILE_PATH" linked
  )" || return 2
  IFS=: read -r git_device git_inode git_uid WORKTREE_GITFILE_MODE \
    WORKTREE_GITFILE_LINKS WORKTREE_GITFILE_SIZE WORKTREE_GITFILE_SHA256 \
    WORKTREE_GITFILE_CONTENT_B64 <<<"$retained_gitfile"
  WORKTREE_GITFILE_IDENTITY="$git_device:$git_inode:$git_uid"
  WORKTREE_GITFILE_RETENTION_REQUIRED=1
}

clean_sibling_record_worktree_absence_proof() {
  [[ "${WORKTREE_ADDED:-0}" == 1 && -n "${WORKTREE:-}" ]] || return 0
  [[ -n "${TMP_ROOT:-}" && -n "${WORKTREE_GITFILE_PATH:-}" ]] || return 2
  [[ ! -e "$TMP_ROOT" && ! -L "$TMP_ROOT" ]] || {
    printf 'cleanup refused Git deregistration while quota root remains attached: %s\n' \
      "$TMP_ROOT" >&2
    return 2
  }
  [[ ! -e "$WORKTREE" && ! -L "$WORKTREE" ]] || {
    printf 'cleanup refused Git deregistration while worktree path remains: %s\n' \
      "$WORKTREE" >&2
    return 2
  }
  [[ ! -e "$WORKTREE_GITFILE_PATH" && ! -L "$WORKTREE_GITFILE_PATH" ]] || {
    printf 'cleanup refused Git deregistration while worktree gitfile remains: %s\n' \
      "$WORKTREE_GITFILE_PATH" >&2
    return 2
  }
  WORKTREE_ABSENCE_PROVED=1
}

clean_sibling_require_worktree_absent_before_git_deregister() {
  [[ "${WORKTREE_ADDED:-0}" == 1 && -n "${WORKTREE:-}" ]] || return 0
  [[ -n "${TMP_ROOT:-}" && -n "${WORKTREE_GITFILE_PATH:-}" ]] || return 2
  [[ "${WORKTREE_ABSENCE_PROVED:-0}" == 1 ]] || {
    printf 'cleanup refused Git deregistration without prior worktree absence proof: %s\n' \
      "$WORKTREE" >&2
    return 2
  }
}

clean_sibling_git_worktree_remove_in_absent_namespace() {
  local bwrap_bin="${BWRAP_BIN:-/usr/bin/bwrap}"
  [[ -x "$bwrap_bin" && ! -L "$bwrap_bin" ]] || {
    printf 'cleanup refused because worktree registry remover requires bwrap\n' >&2
    return 2
  }
  (
    local fd_path=''
    local fd=''
    # shellcheck disable=SC2231
    for fd_path in /proc/$$/fd/*; do
      fd="${fd_path##*/}"
      [[ "$fd" =~ ^[0-9]+$ ]] || continue
      [[ "$fd" -le 2 ]] && continue
      eval "exec ${fd}>&-"
    done
    exec "$bwrap_bin" \
    --die-with-parent \
    --unshare-all \
    --unshare-user \
    --unshare-ipc \
    --unshare-pid \
    --new-session \
    --cap-drop ALL \
    --disable-userns \
    --ro-bind /usr /usr \
    --ro-bind /bin /bin \
    --ro-bind-try /lib /lib \
    --ro-bind-try /lib64 /lib64 \
    --ro-bind-try /etc/passwd /etc/passwd \
    --ro-bind-try /etc/group /etc/group \
    --ro-bind-try /etc/nsswitch.conf /etc/nsswitch.conf \
    --proc /proc \
    --dev /dev \
    --tmpfs /tmp \
    --bind "$SOURCE_REPO" "$SOURCE_REPO" \
    --bind "$SOURCE_COMMON_GITDIR" "$SOURCE_COMMON_GITDIR" \
    --dir "$TMP_ROOT" \
    --tmpfs "$TMP_ROOT" \
    --chdir "$SOURCE_REPO" \
    /usr/bin/env -i \
      GIT_CONFIG_NOSYSTEM=1 \
      GIT_CONFIG_GLOBAL=/dev/null \
      HOME=/dev/null \
      XDG_CONFIG_HOME=/dev/null \
      PATH=/usr/bin:/bin \
      /usr/bin/git --no-optional-locks \
        -c core.hooksPath=/dev/null \
        -c core.fsmonitor=false \
        -c core.untrackedCache=false \
        -c credential.helper= \
        -c core.askPass= \
        -c core.attributesFile=/dev/null \
        -C "$SOURCE_REPO" worktree remove --force "$WORKTREE" >/dev/null 2>&1
  )
}

clean_sibling_snapshot_direct_entries() {
  local root_fd="$1"
  local expected_identity="$2"
  local directory="$3"
  local exclude_name="${4:-}"
  local exclude_identity="${5:-}"
  local exclude_sha256="${6:-}"
  local snapshot_python="${SNAPSHOT_PYTHON:-/usr/bin/python3}"

  [[ "$root_fd" =~ ^[0-9]+$ ]] || return 2
  [[ "$expected_identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-7]+$ ]] || return 2
  [[ "$directory" == /* && -d "$directory" && ! -L "$directory" ]] || return 2
  [[ "$snapshot_python" == /usr/bin/python3 && -x "$snapshot_python" && \
    "$(realpath -e "$snapshot_python" 2>/dev/null || true)" == /usr/bin/python3.* ]] || {
    printf 'caller TMPDIR snapshot failed: trusted snapshot interpreter unavailable\n' >&2
    return 2
  }
  # Traverse only through the caller-directory descriptor opened by the prover.
  # Root identity and path-to-fd identity are checked inside the same trusted
  # process before and after traversal. The digest also binds root metadata.
  PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX='' "$snapshot_python" - \
    "$root_fd" "$expected_identity" "$directory" \
    "$exclude_name" "$exclude_identity" "$exclude_sha256" <<'PY'
import hashlib
import os
import stat
import struct
import sys


def fail(message: str) -> "None":
    print(f"caller TMPDIR snapshot failed: {message}", file=sys.stderr)
    raise SystemExit(2)


def metadata(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev, value.st_ino, value.st_uid, value.st_gid,
        stat.S_IFMT(value.st_mode), stat.S_IMODE(value.st_mode),
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )


def root_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_uid, stat.S_IMODE(value.st_mode))


def bundle_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_uid, stat.S_IMODE(value.st_mode), value.st_size)


def field(tag: bytes, payload: bytes) -> bytes:
    return tag + struct.pack(">Q", len(payload)) + payload


def encode_meta(value: os.stat_result) -> bytes:
    return b"".join(struct.pack(">Q", part) for part in metadata(value))


def parse_bundle_identity(value: str) -> tuple[int, int, int, int, int]:
    parts = value.split(":")
    if len(parts) != 5:
        fail("excluded recovery bundle identity malformed")
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3], 8), int(parts[4]))
    except ValueError:
        fail("excluded recovery bundle identity malformed")


def sha256_file(
    parent_fd: int,
    name: str,
    expected_identity: tuple[int, int, int, int, int],
) -> str:
    fd = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=parent_fd,
    )
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            fail("excluded recovery bundle opened as non-regular")
        if opened.st_nlink != 1 or bundle_identity(opened) != expected_identity:
            fail("excluded recovery bundle descriptor identity changed")
        digest = hashlib.sha256()
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
        if bundle_identity(os.fstat(fd)) != expected_identity:
            fail("excluded recovery bundle changed during read")
        return digest.hexdigest()
    finally:
        os.close(fd)


def verify_excluded_recovery(parent_fd: int, name: str) -> None:
    if not exclude_name:
        return
    if name != exclude_name:
        return
    if (
        not name.startswith(".acgs-quota-artifact-recovery-")
        or not name.endswith(".bundle")
        or "/" in name
        or name in {"", ".", ".."}
    ):
        fail("excluded recovery bundle basename unsafe")
    expected_bundle_identity = parse_bundle_identity(exclude_identity)
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        fail("excluded recovery bundle is not regular")
    if before.st_nlink != 1:
        fail("excluded recovery bundle link count is not final")
    if bundle_identity(before) != expected_bundle_identity:
        fail("excluded recovery bundle identity changed")
    if sha256_file(parent_fd, name, expected_bundle_identity) != exclude_sha256:
        fail("excluded recovery bundle digest changed")
    after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if metadata(after) != metadata(before):
        fail("excluded recovery bundle changed during snapshot")


def is_quota_recovery_bundle(name: str) -> bool:
    return (
        name.startswith(".acgs-quota-artifact-recovery-")
        and name.endswith(".bundle")
        and "/" not in name
        and name not in {"", ".", ".."}
    )


def snapshot_entry(parent_fd: int, name: str) -> bytes:
    raw_name = os.fsencode(name)
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        fail(f"cannot lstat entry: {error.strerror}")
    mode = before.st_mode
    result = field(b"N", raw_name) + field(b"M", encode_meta(before))
    try:
        if stat.S_ISREG(mode):
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
            try:
                opened = os.fstat(fd)
                if metadata(opened) != metadata(before):
                    fail("regular file changed before read")
                digest = hashlib.sha256()
                while chunk := os.read(fd, 1024 * 1024):
                    digest.update(chunk)
                if metadata(os.fstat(fd)) != metadata(opened):
                    fail("regular file changed during read")
            finally:
                os.close(fd)
            result += field(b"F", digest.digest())
        elif stat.S_ISLNK(mode):
            result += field(b"L", os.fsencode(os.readlink(name, dir_fd=parent_fd)))
        elif stat.S_ISDIR(mode):
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
                         dir_fd=parent_fd)
            try:
                opened = os.fstat(fd)
                if metadata(opened) != metadata(before):
                    fail("directory changed before traversal")
                children = sorted((entry.name for entry in os.scandir(fd)), key=os.fsencode)
                nested = b"".join(snapshot_entry(fd, child) for child in children)
                if metadata(os.fstat(fd)) != metadata(opened):
                    fail("directory changed during traversal")
            finally:
                os.close(fd)
            result += field(b"D", hashlib.sha256(nested).digest())
        else:
            fail("unsupported caller entry type")
        after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        fail(f"entry unreadable or replaced: {error.strerror}")
    if metadata(after) != metadata(before):
        fail("entry changed during snapshot")
    return result


fd_number = int(sys.argv[1])
expected_parts = sys.argv[2].split(":")
expected = tuple(int(part, 8 if index == 3 else 10) for index, part in enumerate(expected_parts))
path = sys.argv[3]
exclude_name = sys.argv[4]
exclude_identity = sys.argv[5]
exclude_sha256 = sys.argv[6]
if bool(exclude_name) != bool(exclude_identity) or bool(exclude_name) != bool(exclude_sha256):
    fail("excluded recovery bundle metadata incomplete")
if exclude_name and (
    "/" in exclude_name
    or exclude_name in {"", ".", ".."}
    or not is_quota_recovery_bundle(exclude_name)
    or any(ord(ch) < 32 or ord(ch) == 127 for ch in exclude_name)
    or not exclude_sha256
    or any(ch not in "0123456789abcdef" for ch in exclude_sha256)
    or len(exclude_sha256) != 64
):
    fail("excluded recovery bundle metadata unsafe")
root_fd = -1
try:
    root_fd = os.dup(fd_number)
    os.lseek(root_fd, 0, os.SEEK_SET)
    root_before = os.fstat(root_fd)
    path_before = os.stat(path, follow_symlinks=False)
    if root_identity(root_before) != expected or root_identity(path_before) != expected:
        fail("caller directory path no longer refers to authenticated descriptor")
    names = sorted((entry.name for entry in os.scandir(root_fd)), key=os.fsencode)
    excluded_seen = False
    chunks = []
    for name in names:
        if is_quota_recovery_bundle(name):
            if not exclude_name:
                fail("quota recovery bundle requires exclusion metadata")
            if name != exclude_name:
                fail("unexpected quota recovery bundle")
            verify_excluded_recovery(root_fd, name)
            excluded_seen = True
            continue
        chunks.append(snapshot_entry(root_fd, name))
    if exclude_name and not excluded_seen:
        fail("excluded recovery bundle missing")
    snapshot = b"".join(chunks)
    root_after = os.fstat(root_fd)
    path_after = os.stat(path, follow_symlinks=False)
    if metadata(root_after) != metadata(root_before):
        fail("caller directory changed during traversal")
    if root_identity(root_after) != expected or root_identity(path_after) != expected:
        fail("caller directory path changed during traversal")
except OSError as error:
    fail(f"caller directory unreadable or replaced: {error.strerror}")
finally:
    if root_fd >= 0:
        os.close(root_fd)
root_binding = b"".join(struct.pack(">Q", part) for part in root_identity(root_before))
print(hashlib.sha256(field(b"R", root_binding) + snapshot).hexdigest())
PY
}

clean_sibling_remove_owned_root() {
  local parent_fd="$1" root="$2" expected="$3" marker_pid="$4" expected_mnt_id="${5:-}"
  local expected_recovery_fd="${6:-}"
  local expected_recovery_identity="${7:-}"
  local expected_recovery_sha256="${8:-}"
  local expected_recovery_relpath="${9:-}"
  PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX='' /usr/bin/python3 - \
    "$parent_fd" "$root" "$expected" "$marker_pid" "$expected_mnt_id" \
    "$expected_recovery_fd" "$expected_recovery_identity" \
    "$expected_recovery_sha256" "$expected_recovery_relpath" <<'PY'
import hashlib
import os
import secrets
import stat
import sys


def fail(message: str) -> "None":
    print(f"descriptor-safe cleanup refused: {message}", file=sys.stderr)
    raise SystemExit(2)


parent_fd = int(sys.argv[1])
root = sys.argv[2]
expected = tuple(int(part, 8 if index == 3 else 10)
                 for index, part in enumerate(sys.argv[3].split(":")))
marker_pid = sys.argv[4].encode() + b"\n"
expected_mnt_id = sys.argv[5]
expected_recovery_fd_text = sys.argv[6]
expected_recovery_identity_text = sys.argv[7]
expected_recovery_sha256 = sys.argv[8]
expected_recovery_relpath = sys.argv[9]
name = os.path.basename(root)
if not expected_mnt_id.isdigit():
    fail("root mount id missing")
if os.path.dirname(root) != os.readlink(f"/proc/self/fd/{parent_fd}"):
    fail("root is outside authenticated parent")
if bool(expected_recovery_fd_text) != bool(expected_recovery_identity_text):
    fail("expected recovery link metadata incomplete")
if bool(expected_recovery_fd_text) != bool(expected_recovery_sha256):
    fail("expected recovery link metadata incomplete")
if bool(expected_recovery_fd_text) != bool(expected_recovery_relpath):
    fail("expected recovery link metadata incomplete")
expected_recovery_fd = -1
expected_recovery_identity: tuple[int, int, int, int, int] | None = None
verified_recovery_links: set[str] = set()
if expected_recovery_fd_text:
    if not expected_recovery_fd_text.isdigit():
        fail("expected recovery descriptor is invalid")
    expected_recovery_fd = int(expected_recovery_fd_text)
    parts = expected_recovery_identity_text.split(":")
    if len(parts) != 5:
        fail("expected recovery identity malformed")
    try:
        expected_recovery_identity = (
            int(parts[0]),
            int(parts[1]),
            int(parts[2]),
            int(parts[3], 8),
            int(parts[4]),
        )
    except ValueError:
        fail("expected recovery identity malformed")
    if (
        expected_recovery_relpath.startswith("/")
        or expected_recovery_relpath in {"", ".", ".."}
        or "/../" in f"/{expected_recovery_relpath}/"
        or any(part in {"", ".", ".."} for part in expected_recovery_relpath.split("/"))
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in expected_recovery_relpath)
        or not expected_recovery_relpath.startswith("trusted-ledger/")
    ):
        fail("expected recovery ledger path unsafe")
    recovery_name = os.path.basename(expected_recovery_relpath)
    if (
        not recovery_name.startswith("quota-artifact-recovery-")
        or not recovery_name.endswith(".bundle")
        or expected_recovery_sha256 == ""
        or len(expected_recovery_sha256) != 64
        or any(ch not in "0123456789abcdef" for ch in expected_recovery_sha256)
    ):
        fail("expected recovery metadata unsafe")


def fd_mnt_id(fd_number: int) -> str:
    with open(f"/proc/self/fdinfo/{fd_number}", encoding="utf-8") as fdinfo:
        for line in fdinfo:
            if line.startswith("mnt_id:"):
                value = line.split(":", 1)[1].strip()
                if value.isdigit():
                    return value
                break
    fail("descriptor mount id unavailable")


def ensure_same_mount(fd_number: int, label: str) -> None:
    if fd_mnt_id(fd_number) != expected_mnt_id:
        fail(f"{label} crossed mount boundary")


def stable_descriptor_tuple(fd_number: int) -> tuple[int, int, int, int, int, str]:
    st = os.fstat(fd_number)
    return (
        st.st_dev,
        st.st_ino,
        st.st_uid,
        stat.S_IFMT(st.st_mode),
        stat.S_IMODE(st.st_mode),
        fd_mnt_id(fd_number),
    )


def recovery_bundle_identity(fd_number: int) -> tuple[int, int, int, int, int]:
    st = os.fstat(fd_number)
    if not stat.S_ISREG(st.st_mode):
        fail("expected recovery descriptor changed type")
    return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_size)


def sha256_fd(fd_number: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd_number, 0, os.SEEK_SET)
    while chunk := os.read(fd_number, 1024 * 1024):
        digest.update(chunk)
    os.lseek(fd_number, 0, os.SEEK_SET)
    return digest.hexdigest()


def is_expected_recovery_link(fd_number: int, relpath: str) -> bool:
    if expected_recovery_identity is None or relpath != expected_recovery_relpath:
        return False
    st = os.fstat(fd_number)
    expected_st = os.fstat(expected_recovery_fd)
    if st.st_nlink != 2:
        fail("expected recovery ledger link count changed before mutation")
    if expected_st.st_nlink != 2:
        fail("expected recovery parent link count changed before mutation")
    if recovery_bundle_identity(fd_number) != expected_recovery_identity:
        fail("expected recovery ledger identity changed")
    if recovery_bundle_identity(expected_recovery_fd) != expected_recovery_identity:
        fail("expected recovery parent identity changed")
    if st.st_dev != expected_st.st_dev or st.st_ino != expected_st.st_ino:
        fail("expected recovery ledger link does not match parent descriptor")
    if relpath not in verified_recovery_links:
        if sha256_fd(fd_number) != expected_recovery_sha256:
            fail("expected recovery ledger digest changed")
        if sha256_fd(expected_recovery_fd) != expected_recovery_sha256:
            fail("expected recovery parent digest changed")
        verified_recovery_links.add(relpath)
    return True


def directory_identity(fd_number: int) -> tuple[int, int, int, int, int, str]:
    st = os.fstat(fd_number)
    if not stat.S_ISDIR(st.st_mode):
        fail("directory descriptor changed type")
    return stable_descriptor_tuple(fd_number)


def child_identity(
    fd_number: int,
    relpath: str,
) -> tuple[tuple[int, int, int, int, int, str], str, int]:
    # Trust boundary: this helper authenticates descriptor deletion only inside
    # the same UID, mount namespace, and user-manager context it was launched in.
    st = os.fstat(fd_number)
    if stat.S_ISDIR(st.st_mode):
        return stable_descriptor_tuple(fd_number), "directory", 0
    if stat.S_ISREG(st.st_mode):
        if is_expected_recovery_link(fd_number, relpath):
            return stable_descriptor_tuple(fd_number), "regular", 1
        if st.st_nlink != 1:
            fail("regular file link count changed before mutation")
        return stable_descriptor_tuple(fd_number), "regular", 0
    fail("unsupported child file type")


def regular_file_after_unlink(
    fd_number: int,
    expected: tuple[int, int, int, int, int, str],
    expected_links: int,
) -> None:
    st = os.fstat(fd_number)
    if not stat.S_ISREG(st.st_mode):
        fail("regular file descriptor changed type after unlink")
    if stable_descriptor_tuple(fd_number) != expected:
        fail("regular file descriptor changed after unlink")
    if st.st_nlink != expected_links:
        fail("regular file link count changed after unlink")


def direct_child_snapshot(
    directory_fd: int,
    relroot: str = "",
) -> tuple[tuple[str, tuple[int, int, int, int, int, str], str, int], ...]:
    snapshot = []
    for child in sorted(os.listdir(directory_fd), key=os.fsencode):
        child_fd = -1
        try:
            child_fd = os.open(
                child,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                dir_fd=directory_fd,
            )
            ensure_same_mount(child_fd, child)
            child_relpath = f"{relroot}/{child}" if relroot else child
            child_tuple, child_kind, child_unlink_links = child_identity(child_fd, child_relpath)
            snapshot.append((child, child_tuple, child_kind, child_unlink_links))
        except OSError as exc:
            fail(f"direct child snapshot refused {child}: {exc.strerror}")
        finally:
            if child_fd >= 0:
                os.close(child_fd)
    return tuple(snapshot)


fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=parent_fd)
st = os.fstat(fd)
identity = (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))
if identity != expected:
    fail("root identity changed")
ensure_same_mount(fd, "root")
marker_fd = os.open(".acgs-clean-sibling-owned", os.O_RDONLY | os.O_NOFOLLOW,
                    dir_fd=fd)
try:
    ensure_same_mount(marker_fd, "ownership marker")
    marker_st = os.fstat(marker_fd)
    if (not stat.S_ISREG(marker_st.st_mode) or marker_st.st_nlink != 1 or
            marker_st.st_uid != st.st_uid or os.read(marker_fd, 128) != marker_pid):
        fail("ownership marker changed")
finally:
    os.close(marker_fd)


def preflight(directory_fd: int, relroot: str = "") -> None:
    ensure_same_mount(directory_fd, "directory")
    before = directory_identity(directory_fd)
    for child in list(os.listdir(directory_fd)):
        child_fd = -1
        try:
            child_fd = os.open(
                child,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                dir_fd=directory_fd,
            )
            ensure_same_mount(child_fd, child)
            child_relpath = f"{relroot}/{child}" if relroot else child
            _, child_kind, _ = child_identity(child_fd, child_relpath)
            if child_kind == "directory":
                os.close(child_fd)
                child_fd = os.open(
                    child,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
                    dir_fd=directory_fd,
                )
                preflight(child_fd, child_relpath)
        except OSError as exc:
            fail(f"preflight refused {child}: {exc.strerror}")
        finally:
            if child_fd >= 0:
                os.close(child_fd)
    if directory_identity(directory_fd) != before:
        fail("directory changed during preflight")


sealed_direct_children = direct_child_snapshot(fd)
preflight(fd)
tomb = f".acgs-cleanup-{secrets.token_hex(16)}"
os.rename(name, tomb, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
os.fsync(parent_fd)
root_removed = False


def restore_quarantined_root() -> None:
    try:
        os.stat(tomb, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        return
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        return
    except FileNotFoundError:
        pass
    except OSError:
        return
    try:
        os.rename(tomb, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError:
        pass


try:
    try:
        moved = os.stat(tomb, dir_fd=parent_fd, follow_symlinks=False)
        moved_identity = (moved.st_dev, moved.st_ino, moved.st_uid,
                          stat.S_IMODE(moved.st_mode))
        if moved_identity != expected or os.fstat(fd).st_ino != moved.st_ino:
            fail("root substituted at teardown boundary")
        ensure_same_mount(fd, "root after rename")
        if direct_child_snapshot(fd) != sealed_direct_children:
            fail("root direct children changed after quarantine")
        preflight(fd)

        def empty(directory_fd: int, relroot: str = "") -> None:
            ensure_same_mount(directory_fd, "directory")
            parent_before = directory_identity(directory_fd)
            for child in list(os.listdir(directory_fd)):
                if child.startswith(".acgs-child-cleanup-"):
                    fail("unexpected cleanup tomb present")
                child_fd = os.open(
                    child,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                    dir_fd=directory_fd,
                )
                ensure_same_mount(child_fd, child)
                child_relpath = f"{relroot}/{child}" if relroot else child
                child_tuple, child_kind, child_unlink_links = child_identity(child_fd, child_relpath)
                child_tomb = f".acgs-child-cleanup-{secrets.token_hex(16)}"
                moved_child = False
                try:
                    if directory_identity(directory_fd) != parent_before:
                        fail("directory changed before child quarantine")
                    os.rename(child, child_tomb, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                    moved_child = True
                    try:
                        if child_kind == "directory":
                            tomb_fd = os.open(
                                child_tomb,
                                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
                                dir_fd=directory_fd,
                            )
                        else:
                            tomb_fd = os.open(
                                child_tomb,
                                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                                dir_fd=directory_fd,
                            )
                        try:
                            tomb_tuple, tomb_kind, tomb_unlink_links = child_identity(
                                tomb_fd, child_relpath
                            )
                            if (
                                tomb_tuple != child_tuple
                                or tomb_kind != child_kind
                                or tomb_unlink_links != child_unlink_links
                            ):
                                fail(f"{child} tomb identity changed")
                            current_tuple, current_kind, current_unlink_links = child_identity(
                                child_fd, child_relpath
                            )
                            if (
                                current_tuple != child_tuple
                                or current_kind != child_kind
                                or current_unlink_links != child_unlink_links
                            ):
                                fail(f"{child} descriptor changed after quarantine")
                            if child_kind == "directory":
                                empty(tomb_fd, child_relpath)
                                if directory_identity(directory_fd) != parent_before:
                                    fail("directory changed before child rmdir")
                                os.rmdir(child_tomb, dir_fd=directory_fd)
                            else:
                                if directory_identity(directory_fd) != parent_before:
                                    fail("directory changed before child unlink")
                                os.unlink(child_tomb, dir_fd=directory_fd)
                                regular_file_after_unlink(
                                    child_fd, child_tuple, child_unlink_links
                                )
                        finally:
                            os.close(tomb_fd)
                    finally:
                        os.close(child_fd)
                except BaseException:
                    if moved_child:
                        try:
                            os.rename(child_tomb, child, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                        except OSError:
                            pass
                    raise
            if directory_identity(directory_fd) != parent_before:
                fail("directory changed during empty")

        empty(fd)
        if os.fstat(fd).st_ino != moved.st_ino:
            fail("root descriptor changed during teardown")
        ensure_same_mount(fd, "root after empty")
    except BaseException:
        restore_quarantined_root()
        raise
finally:
    os.close(fd)
try:
    os.rmdir(tomb, dir_fd=parent_fd)
    root_removed = True
except OSError as exc:
    restore_quarantined_root()
    fail(f"root crossed mount boundary during final removal: {exc.strerror}")
PY
}

clean_sibling_remove_registered_worktree() {
  local worktree_list=''
  local still_registered=0

  [[ "${WORKTREE_ADDED:-0}" == 1 && -n "${WORKTREE:-}" ]] || return 0
  WORKTREE_REGISTRATION_REMOVED=0
  WORKTREE_POST_REMOVE_GITFILE_VALIDATED=0
  clean_sibling_require_worktree_absent_before_git_deregister || return 2
  [[ -z "${WORKTREE_GITFILE_FD:-}" ]] || {
    printf 'cleanup refused Git deregistration while worktree gitfile descriptor is open\n' >&2
    return 2
  }
  [[ -n "${WORKTREE_GITFILE_PRE_DETACH_WITNESS:-}" ]] || {
    printf 'cleanup refused Git deregistration without pre-detach gitfile witness: %s\n' \
      "$WORKTREE" >&2
    return 2
  }
  if [[ "${WORKTREE_GITFILE_RETENTION_REQUIRED:-0}" == 1 ||
    -n "${WORKTREE_GITFILE_CONTENT_B64:-}" ]]; then
    [[ "$(clean_sibling_gitfile_pre_detach_witness)" == "$WORKTREE_GITFILE_PRE_DETACH_WITNESS" ]] ||
      return 2
  fi
  if ! worktree_list="$(git -C "$SOURCE_REPO" worktree list --porcelain)"; then
    printf 'cleanup refused because worktree registry query failed: %s\n' "$WORKTREE" >&2
    return 2
  fi
  if ! clean_sibling_worktree_list_contains "$worktree_list" "$WORKTREE"; then
    WORKTREE_REGISTRATION_REMOVED=1
    WORKTREE_POST_REMOVE_GITFILE_VALIDATED=1
    return 0
  fi
  if ! clean_sibling_git_worktree_remove_in_absent_namespace; then
    printf 'cleanup refused because exact worktree deregistration failed once: %s\n' \
      "$WORKTREE" >&2
    return 2
  fi
  if ! worktree_list="$(git -C "$SOURCE_REPO" worktree list --porcelain)"; then
    printf 'cleanup refused because worktree registry query failed: %s\n' "$WORKTREE" >&2
    return 2
  fi
  if clean_sibling_worktree_list_contains "$worktree_list" "$WORKTREE"; then
    still_registered=1
  fi
  if [[ "$still_registered" == 1 ]]; then
    printf 'cleanup refused to delete still-registered worktree root: %s\n' "$WORKTREE" >&2
    return 2
  fi
  # shellcheck disable=SC2034
  WORKTREE_REGISTRATION_REMOVED=1
  WORKTREE_POST_REMOVE_GITFILE_VALIDATED=1
  clean_sibling_require_worktree_absent_before_git_deregister || return 2
  return 0
}

clean_sibling_retain_recovery_contracts() {
  [[ -n "${TMP_ROOT:-}" && -d "$TMP_ROOT" && ! -L "$TMP_ROOT" ]] || return 0
  /usr/bin/python3 -I -S - "$TMP_ROOT" "$TMP_PARENT" \
    "${ACGS_POSTGRES_RECOVERY_ROOT:-}" <<'PY'
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time


def fail(message: str = "cleanup refused recovery contract") -> None:
    print(message, file=sys.stderr)
    raise SystemExit(2)


tmp_root, tmp_parent, recovery_root = sys.argv[1:4]
uid = os.getuid()
INTENT_STABLE_ABSENCE_SECONDS = 65.0
INTENT_POLL_SECONDS = 1.0
try:
    root_fd = os.open(tmp_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    parent_fd = os.open(tmp_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
except OSError as exc:
    fail(f"cleanup refused recovery contract root: {exc}")
contracts: list[str] = []
recovery_fd = -1
intent_identity_by_name: dict[str, tuple[int, int, int, int, int, int, str]] = {}
intent_payload_by_name: dict[str, bytes] = {}
try:
    root_stat = os.fstat(root_fd)
    parent_stat = os.fstat(parent_fd)
    if root_stat.st_uid != uid or parent_stat.st_uid != uid:
        fail("cleanup refused recovery contract root identity")
    search_roots = [tmp_root]
    if recovery_root:
        recovery_name = os.path.basename(recovery_root)
        if (
            not os.path.isabs(recovery_root)
            or os.path.dirname(recovery_root) != tmp_parent
            or recovery_name in {"", ".", ".."}
            or "/" in recovery_name
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in recovery_name)
            or os.path.realpath(recovery_root) == os.path.realpath(tmp_root)
            or os.path.realpath(recovery_root).startswith(os.path.realpath(tmp_root) + os.sep)
        ):
            fail("cleanup refused PostgreSQL recovery root binding")
        try:
            recovery_stat = os.stat(recovery_name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            fail(f"cleanup refused PostgreSQL recovery root stat: {exc}")
        if (
            not stat.S_ISDIR(recovery_stat.st_mode)
            or recovery_stat.st_uid != uid
            or stat.S_IMODE(recovery_stat.st_mode) != 0o700
        ):
            fail("cleanup refused PostgreSQL recovery root identity")
        try:
            recovery_fd = os.open(
                recovery_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        except OSError as exc:
            fail(f"cleanup refused PostgreSQL recovery root open: {exc}")
        opened_recovery = os.fstat(recovery_fd)
        recovery_path_stat = os.stat(recovery_root, follow_symlinks=False)
        if (
            opened_recovery.st_dev,
            opened_recovery.st_ino,
            opened_recovery.st_uid,
            stat.S_IMODE(opened_recovery.st_mode),
        ) != (
            recovery_stat.st_dev,
            recovery_stat.st_ino,
            recovery_stat.st_uid,
            stat.S_IMODE(recovery_stat.st_mode),
        ) or (
            opened_recovery.st_dev,
            opened_recovery.st_ino,
            opened_recovery.st_uid,
            stat.S_IMODE(opened_recovery.st_mode),
        ) != (
            recovery_path_stat.st_dev,
            recovery_path_stat.st_ino,
            recovery_path_stat.st_uid,
            stat.S_IMODE(recovery_path_stat.st_mode),
        ):
            fail("cleanup refused PostgreSQL recovery root identity")
        search_roots = [recovery_root]
    nonce_files: list[str] = []
    for search_root in search_roots:
        for current_root, dirs, files in os.walk(search_root, topdown=True, followlinks=False):
            dirs[:] = sorted(name for name in dirs if "\0" not in name)
            if "recovery-contract.env" in files:
                contracts.append(os.path.join(current_root, "recovery-contract.env"))
            if "proof-nonce.hex" in files:
                nonce_files.append(os.path.join(current_root, "proof-nonce.hex"))
    intent_server_records: list[tuple[str, str, str]] = []
    intent_client_records: list[tuple[str, str, str]] = []
    intent_names: list[str] = []
    intent_bridge_packet: dict[str, str] = {}

    def safe_under_tmp_root(path_value: str) -> bool:
        if (
            not path_value.startswith("/")
            or "\0" in path_value
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in path_value)
        ):
            return False
        normalized = os.path.normpath(path_value)
        if normalized != path_value:
            return False
        try:
            return os.path.commonpath([tmp_root, normalized]) == tmp_root and normalized != tmp_root
        except ValueError:
            return False

    def read_intent_file(name: str) -> dict[str, str]:
        if recovery_fd < 0:
            fail("cleanup refused PostgreSQL recovery intent without recovery root")
        if not re.fullmatch(r"[a-z0-9_.-]{1,160}\.intent", name):
            fail("cleanup refused PostgreSQL recovery intent filename")
        try:
            before_path = os.stat(name, dir_fd=recovery_fd, follow_symlinks=False)
            fd = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=recovery_fd,
            )
        except OSError as exc:
            fail(f"cleanup refused PostgreSQL recovery intent open: {exc}")
        try:
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != uid
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or before.st_size <= 0
                or before.st_size > 2048
            ):
                fail("cleanup refused PostgreSQL recovery intent identity")
            if (
                before.st_dev,
                before.st_ino,
                before.st_uid,
                stat.S_IMODE(before.st_mode),
                before.st_nlink,
                before.st_size,
            ) != (
                before_path.st_dev,
                before_path.st_ino,
                before_path.st_uid,
                stat.S_IMODE(before_path.st_mode),
                before_path.st_nlink,
                before_path.st_size,
            ):
                fail("cleanup refused PostgreSQL recovery intent path binding")
            payload = os.read(fd, before.st_size + 1)
            if len(payload) != before.st_size or os.read(fd, 1):
                fail("cleanup refused PostgreSQL recovery intent size")
            digest = hashlib.sha256(payload).hexdigest()
            after = os.fstat(fd)
            after_path = os.stat(name, dir_fd=recovery_fd, follow_symlinks=False)
            identity = (
                before.st_dev,
                before.st_ino,
                before.st_uid,
                stat.S_IMODE(before.st_mode),
                before.st_nlink,
                before.st_size,
            )
            if identity != (
                after.st_dev,
                after.st_ino,
                after.st_uid,
                stat.S_IMODE(after.st_mode),
                after.st_nlink,
                after.st_size,
            ) or identity != (
                after_path.st_dev,
                after_path.st_ino,
                after_path.st_uid,
                stat.S_IMODE(after_path.st_mode),
                after_path.st_nlink,
                after_path.st_size,
            ):
                fail("cleanup refused PostgreSQL recovery intent changed during read")
            intent_identity_by_name[name] = (*identity, digest)
            intent_payload_by_name[name] = payload
        finally:
            os.close(fd)
        try:
            text_value = payload.decode("ascii")
        except UnicodeDecodeError:
            fail("cleanup refused PostgreSQL recovery intent grammar")
        lines_value = text_value.splitlines()
        if text_value != "\n".join(lines_value) + "\n":
            fail("cleanup refused PostgreSQL recovery intent grammar")
        parsed_value: dict[str, str] = {}
        for line in lines_value:
            if "=" not in line:
                fail("cleanup refused PostgreSQL recovery intent grammar")
            key, value = line.split("=", 1)
            if key in parsed_value or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
                fail("cleanup refused PostgreSQL recovery intent grammar")
            parsed_value[key] = value
        return parsed_value

    def list_recovery_names() -> list[str]:
        if recovery_fd < 0:
            fail("cleanup refused PostgreSQL recovery intent scan")
        scan_fd = -1
        try:
            scan_fd = os.open(
                ".",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=recovery_fd,
            )
            return sorted(os.listdir(scan_fd), key=os.fsencode)
        except OSError as exc:
            fail(f"cleanup refused PostgreSQL recovery intent scan: {exc}")
        finally:
            if scan_fd >= 0:
                os.close(scan_fd)

    def parse_key_value_payload(payload: bytes, label: str) -> dict[str, str]:
        try:
            text_value = payload.decode("ascii")
        except UnicodeDecodeError:
            fail(f"cleanup refused {label} grammar")
        lines_value = text_value.splitlines()
        if text_value != "\n".join(lines_value) + "\n":
            fail(f"cleanup refused {label} grammar")
        parsed_value: dict[str, str] = {}
        for line in lines_value:
            if "=" not in line:
                fail(f"cleanup refused {label} grammar")
            key, value = line.split("=", 1)
            if key in parsed_value or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
                fail(f"cleanup refused {label} grammar")
            parsed_value[key] = value
        return parsed_value

    def recovery_root_mount_id() -> str:
        if recovery_fd < 0:
            fail("cleanup refused PostgreSQL recovery root mount")
        with open(f"/proc/self/fdinfo/{recovery_fd}", encoding="utf-8") as fdinfo:
            for line in fdinfo:
                if line.startswith("mnt_id:"):
                    value = line.split(":", 1)[1].strip()
                    if not value.isdigit():
                        fail("cleanup refused PostgreSQL recovery root mount")
                    return value
        fail("cleanup refused PostgreSQL recovery root mount")

    def parse_ledger_payload_manifest(
        value: str,
        expected_count: int,
        expected_proof_label: str,
        expected_packet_sha256: str,
    ) -> dict[str, bytes]:
        try:
            raw = base64.b64decode(value.encode("ascii"), validate=True)
            decoded = json.loads(raw.decode("ascii"))
        except (ValueError, json.JSONDecodeError):
            fail("cleanup refused recovery ledger payload manifest")
        if not isinstance(decoded, list) or len(decoded) != expected_count:
            fail("cleanup refused recovery ledger payload manifest")
        payloads: dict[str, bytes] = {}
        canonical_manifest: list[list[str]] = []
        servers = 0
        expected_nonce = expected_proof_label.rsplit("-", 1)[1]
        expected_server = f"{expected_proof_label}-server"
        server_bridge: dict[str, str] = {}
        for item in decoded:
            if (
                not isinstance(item, list)
                or len(item) != 2
                or not isinstance(item[0], str)
                or not isinstance(item[1], str)
            ):
                fail("cleanup refused recovery ledger payload manifest")
            name, payload_b64 = item
            if name in payloads or not re.fullmatch(r"[a-z0-9_.-]{1,160}\.intent", name):
                fail("cleanup refused recovery ledger payload manifest")
            try:
                payload = base64.b64decode(payload_b64.encode("ascii"), validate=True)
            except ValueError:
                fail("cleanup refused recovery ledger payload manifest")
            if len(payload) <= 0 or len(payload) > 2048:
                fail("cleanup refused recovery ledger payload manifest")
            parsed_payload = parse_key_value_payload(payload, "recovery ledger intent payload")
            if name.endswith("-server.intent"):
                servers += 1
                required_keys = [
                    "intent_version",
                    "schema",
                    "phase",
                    "proof_nonce",
                    "proof_label",
                    "server_name",
                    "record_path",
                    "server_cidfile",
                    "server_namefile",
                    "socket_bridge_basename",
                    "socket_bridge_identity",
                    "socket_bridge_marker_sha256",
                    "socket_bridge_mnt_id",
                ]
                if list(parsed_payload) != required_keys:
                    fail("cleanup refused recovery ledger payload manifest")
                if name != f"{expected_proof_label}-server.intent":
                    fail("cleanup refused recovery ledger payload manifest")
                if (
                    parsed_payload["intent_version"] != "2"
                    or parsed_payload["schema"] != "acgs-postgres-recovery-intent/server/v2"
                    or parsed_payload["phase"] != "server-intent"
                    or parsed_payload["proof_nonce"] != expected_nonce
                    or parsed_payload["proof_label"] != expected_proof_label
                    or parsed_payload["server_name"] != expected_server
                    or parsed_payload["record_path"] != parsed_payload["server_namefile"]
                    or not safe_under_tmp_root(parsed_payload["server_cidfile"])
                    or not safe_under_tmp_root(parsed_payload["server_namefile"])
                    or parsed_payload["socket_bridge_basename"]
                    != f"{expected_proof_label}-socket-bridge"
                    or not re.fullmatch(
                        r"[0-9]+:[0-9]+:[0-9]+:1777",
                        parsed_payload["socket_bridge_identity"],
                    )
                    or not re.fullmatch(
                        r"[0-9a-f]{64}",
                        parsed_payload["socket_bridge_marker_sha256"],
                    )
                    or not parsed_payload["socket_bridge_mnt_id"].isdigit()
                ):
                    fail("cleanup refused recovery ledger payload manifest")
                server_bridge = {
                    "socket_bridge_basename": parsed_payload["socket_bridge_basename"],
                    "socket_bridge_identity": parsed_payload["socket_bridge_identity"],
                    "socket_bridge_marker_sha256": parsed_payload["socket_bridge_marker_sha256"],
                    "socket_bridge_mnt_id": parsed_payload["socket_bridge_mnt_id"],
                }
            else:
                required_keys = [
                    "intent_version",
                    "phase",
                    "proof_nonce",
                    "proof_label",
                    "server_name",
                    "client_name",
                    "record_path",
                    "client_cidfile",
                    "client_namefile",
                ]
                if list(parsed_payload) != required_keys:
                    fail("cleanup refused recovery ledger payload manifest")
                client_name = parsed_payload["client_name"]
                if (
                    parsed_payload["intent_version"] != "1"
                    or parsed_payload["phase"] != "client-intent"
                    or parsed_payload["proof_nonce"] != expected_nonce
                    or parsed_payload["proof_label"] != expected_proof_label
                    or parsed_payload["server_name"] != expected_server
                    or not re.fullmatch(
                        rf"{re.escape(expected_proof_label)}-client-[0-9]+-[0-9]+",
                        client_name,
                    )
                    or name != f"{client_name}.intent"
                    or parsed_payload["record_path"] != parsed_payload["client_namefile"]
                    or not safe_under_tmp_root(parsed_payload["client_cidfile"])
                    or not safe_under_tmp_root(parsed_payload["client_namefile"])
                ):
                    fail("cleanup refused recovery ledger payload manifest")
            payloads[name] = payload
            canonical_manifest.append(
                [name, base64.b64encode(payload).decode("ascii")]
            )
        if servers != 1:
            fail("cleanup refused recovery ledger payload manifest")
        if sorted(canonical_manifest, key=lambda item: os.fsencode(item[0])) != canonical_manifest:
            fail("cleanup refused recovery ledger payload manifest")
        canonical_raw = json.dumps(canonical_manifest, separators=(",", ":")).encode("ascii")
        if base64.b64encode(canonical_raw).decode("ascii") != value:
            fail("cleanup refused recovery ledger payload manifest")
        packet_lines = [
            "contract_version=2",
            "schema=acgs-postgres-recovery-contract/v2",
            "external_cleanup_uncertain=1",
            "cleanup_status=2",
            f"proof_nonce={expected_nonce}",
            f"proof_label={expected_proof_label}",
            f"server_name={expected_server}",
            f"socket_bridge_basename={server_bridge['socket_bridge_basename']}",
            f"socket_bridge_identity={server_bridge['socket_bridge_identity']}",
            f"socket_bridge_marker_sha256={server_bridge['socket_bridge_marker_sha256']}",
            f"socket_bridge_mnt_id={server_bridge['socket_bridge_mnt_id']}",
            f"recovery_root_mnt_id={server_bridge['socket_bridge_mnt_id']}",
        ]
        if hashlib.sha256(("\n".join(packet_lines) + "\n").encode("ascii")).hexdigest() != expected_packet_sha256:
            fail("cleanup refused recovery ledger packet binding")
        return payloads

    def parse_committed_ledger_record(record: bytes, expected_proof_label: str) -> dict[str, str]:
        parsed_record = parse_key_value_payload(record, "recovery ledger record")
        required = [
            "committed_recovery_record",
            "proof_label",
            "intent_count",
            "packet_sha256",
            "intent_manifest_sha256",
            "intent_payload_manifest_b64",
        ]
        if list(parsed_record) != required:
            fail("cleanup refused recovery ledger record grammar")
        if parsed_record["committed_recovery_record"] != "1":
            fail("cleanup refused recovery ledger record")
        if parsed_record["proof_label"] != expected_proof_label:
            fail("cleanup refused recovery ledger proof binding")
        if not re.fullmatch(r"[1-9][0-9]?", parsed_record["intent_count"]):
            fail("cleanup refused recovery ledger count")
        if int(parsed_record["intent_count"]) > 64:
            fail("cleanup refused recovery ledger count")
        if not re.fullmatch(r"[0-9a-f]{64}", parsed_record["packet_sha256"]):
            fail("cleanup refused recovery ledger packet")
        if not re.fullmatch(r"[0-9a-f]{64}", parsed_record["intent_manifest_sha256"]):
            fail("cleanup refused recovery ledger manifest")
        return parsed_record

    def canonical_intent_payload_manifest_b64(names: list[str]) -> str:
        manifest = [
            [
                name,
                base64.b64encode(intent_payload_by_name[name]).decode("ascii"),
            ]
            for name in names
        ]
        encoded = json.dumps(manifest, separators=(",", ":")).encode("ascii")
        return base64.b64encode(encoded).decode("ascii")

    atomic_temp_counter = [0]

    def read_exact_fd(fd: int, expected_size: int) -> bytes:
        chunks = []
        remaining = expected_size + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def write_all_fd(fd: int, payload: bytes, reason: str, on_error) -> None:
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0:
                on_error(reason)
            offset += written

    def fdatasync_file(fd: int) -> None:
        if hasattr(os, "fdatasync"):
            os.fdatasync(fd)
        else:
            os.fsync(fd)

    def atomic_temp_name(kind: str, final_name: str, payload: bytes) -> str:
        atomic_temp_counter[0] += 1
        digest = hashlib.sha256(payload).hexdigest()
        return (
            f".acgs-clean-sibling.atomic.{kind}.{final_name}."
            f"{len(payload)}.{digest}.tmp.{os.getpid()}.{atomic_temp_counter[0]}"
        )

    def parse_atomic_temp_name(name: str) -> tuple[str, str, int, str] | None:
        match = re.fullmatch(
            r"\.acgs-clean-sibling\.atomic\."
            r"(intent|ledger|complete)\."
            r"([A-Za-z0-9_.-]+)\."
            r"([0-9]+)\."
            r"([0-9a-f]{64})\.tmp\.[0-9]+\.[0-9]+",
            name,
        )
        if match is None:
            return None
        final_name = match.group(2)
        if "/" in final_name or final_name in {"", ".", ".."}:
            return None
        return match.group(1), final_name, int(match.group(3)), match.group(4)

    def atomic_final_name_matches_kind(kind: str, final_name: str) -> bool:
        if kind == "intent":
            return bool(
                re.fullmatch(
                    rf"acp-postgres-gate-{uid}-[0-9a-f]{{32}}-(server|client-[0-9]+-[0-9]+)\.intent",
                    final_name,
                )
            )
        if kind == "ledger":
            return bool(
                re.fullmatch(rf"acp-postgres-gate-{uid}-[0-9a-f]{{32}}\.committed", final_name)
            )
        if kind == "complete":
            return bool(
                re.fullmatch(rf"acp-postgres-gate-{uid}-[0-9a-f]{{32}}\.complete", final_name)
            )
        return False

    def file_has_exact_payload(
        dir_fd: int,
        name: str,
        expected_size: int,
        expected_digest: str,
        *,
        allow_link_count: set[int],
    ) -> bool:
        fd = -1
        try:
            fd = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=dir_fd,
            )
            st = os.fstat(fd)
            if (
                not stat.S_ISREG(st.st_mode)
                or st.st_uid != uid
                or stat.S_IMODE(st.st_mode) != 0o600
                or st.st_nlink not in allow_link_count
                or st.st_size != expected_size
            ):
                return False
            payload = read_exact_fd(fd, expected_size)
            return (
                len(payload) == expected_size
                and hashlib.sha256(payload).hexdigest() == expected_digest
                and not os.read(fd, 1)
            )
        except FileNotFoundError:
            return False
        except OSError:
            return False
        finally:
            if fd >= 0:
                os.close(fd)

    def verify_final_atomic_payload(
        dir_fd: int, final_name: str, payload: bytes, reason: str, on_error
    ) -> bool:
        digest = hashlib.sha256(payload).hexdigest()
        if not file_has_exact_payload(
            dir_fd,
            final_name,
            len(payload),
            digest,
            allow_link_count={1},
        ):
            try:
                os.stat(final_name, dir_fd=dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                return False
            except OSError:
                on_error(reason)
            on_error(reason)
        return True

    def reconcile_same_inode_quarantine_link(
        dir_fd: int,
        source_name: str,
        quarantine_name: str,
        expected_size: int,
        expected_digest: str,
        reason: str,
        on_error,
    ) -> bool:
        if (
            "/" in source_name
            or source_name in {"", ".", ".."}
            or "/" in quarantine_name
            or quarantine_name in {"", ".", ".."}
            or expected_size < 0
            or expected_size > 262144
        ):
            return False
        source_fd = -1
        quarantine_fd = -1
        try:
            source_fd = os.open(
                source_name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=dir_fd,
            )
            quarantine_fd = os.open(
                quarantine_name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=dir_fd,
            )
            source_st = os.fstat(source_fd)
            quarantine_st = os.fstat(quarantine_fd)
            if (
                source_st.st_dev != quarantine_st.st_dev
                or source_st.st_ino != quarantine_st.st_ino
                or not stat.S_ISREG(source_st.st_mode)
                or source_st.st_uid != uid
                or stat.S_IMODE(source_st.st_mode) != 0o600
                or source_st.st_nlink != 2
                or source_st.st_size != expected_size
                or not stat.S_ISREG(quarantine_st.st_mode)
                or quarantine_st.st_uid != uid
                or stat.S_IMODE(quarantine_st.st_mode) != 0o600
                or quarantine_st.st_nlink != 2
                or quarantine_st.st_size != expected_size
            ):
                return False
            payload = read_exact_fd(source_fd, expected_size)
            if (
                len(payload) != expected_size
                or os.read(source_fd, 1)
                or hashlib.sha256(payload).hexdigest() != expected_digest
            ):
                return False
        except FileNotFoundError:
            return False
        except OSError:
            return False
        finally:
            if source_fd >= 0:
                os.close(source_fd)
            if quarantine_fd >= 0:
                os.close(quarantine_fd)
        try:
            os.unlink(source_name, dir_fd=dir_fd)
            os.fsync(dir_fd)
        except OSError:
            on_error(reason)
        if not file_has_exact_payload(
            dir_fd,
            quarantine_name,
            expected_size,
            expected_digest,
            allow_link_count={1},
        ):
            on_error(reason)
        return True

    def reconcile_atomic_temps(dir_fd: int, on_error) -> None:
        try:
            names = os.listdir(dir_fd)
        except OSError:
            on_error("atomic-temp-scan")
        if len(names) > 256:
            on_error("atomic-temp-count")
        for temp_name in names:
            parsed = parse_atomic_temp_name(temp_name)
            if parsed is None:
                continue
            kind, final_name, expected_size, expected_digest = parsed
            if not atomic_final_name_matches_kind(kind, final_name):
                continue
            if expected_size <= 0 or expected_size > 262144:
                continue
            if not file_has_exact_payload(
                dir_fd,
                temp_name,
                expected_size,
                expected_digest,
                allow_link_count={1, 2},
            ):
                quarantine_owned_atomic_temp(
                    dir_fd,
                    temp_name,
                    kind,
                    expected_size,
                    expected_digest,
                    on_error,
                )
                continue
            if file_has_exact_payload(
                dir_fd,
                final_name,
                expected_size,
                expected_digest,
                allow_link_count={1, 2},
            ):
                try:
                    os.unlink(temp_name, dir_fd=dir_fd)
                    os.fsync(dir_fd)
                except OSError:
                    on_error("atomic-temp-unlink")
                continue
            try:
                os.stat(final_name, dir_fd=dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                try:
                    os.link(
                        temp_name,
                        final_name,
                        src_dir_fd=dir_fd,
                        dst_dir_fd=dir_fd,
                        follow_symlinks=False,
                    )
                    os.fsync(dir_fd)
                    os.unlink(temp_name, dir_fd=dir_fd)
                    os.fsync(dir_fd)
                except FileExistsError:
                    continue
                except OSError:
                    on_error("atomic-temp-publish")
                if not file_has_exact_payload(
                    dir_fd,
                    final_name,
                    expected_size,
                    expected_digest,
                    allow_link_count={1},
                ):
                    on_error("atomic-temp-final")
            except OSError:
                on_error("atomic-temp-final-stat")

    def quarantine_owned_atomic_temp(
        dir_fd: int,
        temp_name: str,
        kind: str,
        expected_size: int,
        expected_digest: str,
        on_error,
    ) -> None:
        fd = -1
        try:
            fd = os.open(
                temp_name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=dir_fd,
            )
            st = os.fstat(fd)
            if (
                not stat.S_ISREG(st.st_mode)
                or st.st_uid != uid
                or stat.S_IMODE(st.st_mode) != 0o600
                or st.st_nlink not in {1, 2}
                or st.st_size < 0
                or st.st_size > expected_size
                or expected_size > 262144
            ):
                return
            payload = read_exact_fd(fd, st.st_size)
            if len(payload) != st.st_size or os.read(fd, 1):
                return
            actual_digest = hashlib.sha256(payload).hexdigest()
        except OSError:
            return
        finally:
            if fd >= 0:
                os.close(fd)
        quarantine_name = (
            f".acgs-clean-sibling.preserved.atomic.{kind}."
            f"{expected_digest}.{actual_digest}.bad"
        )
        if not re.fullmatch(
            r"\.acgs-clean-sibling\.preserved\.atomic\."
            r"(intent|ledger|complete)\.[0-9a-f]{64}\.[0-9a-f]{64}\.bad",
            quarantine_name,
        ):
            return
        if st.st_nlink == 2:
            reconcile_same_inode_quarantine_link(
                dir_fd,
                temp_name,
                quarantine_name,
                st.st_size,
                actual_digest,
                "atomic-temp-quarantine",
                on_error,
            )
            return
        try:
            os.link(
                temp_name,
                quarantine_name,
                src_dir_fd=dir_fd,
                dst_dir_fd=dir_fd,
                follow_symlinks=False,
            )
            os.fsync(dir_fd)
        except FileExistsError:
            if reconcile_same_inode_quarantine_link(
                dir_fd,
                temp_name,
                quarantine_name,
                st.st_size,
                actual_digest,
                "atomic-temp-quarantine",
                on_error,
            ):
                return
            if not file_has_exact_payload(
                dir_fd,
                quarantine_name,
                st.st_size,
                actual_digest,
                allow_link_count={1},
            ):
                return
        except OSError:
            return
        try:
            os.unlink(temp_name, dir_fd=dir_fd)
            os.fsync(dir_fd)
        except OSError:
            on_error("atomic-temp-quarantine")

    def quarantine_owned_regular_file(
        dir_fd: int,
        final_name: str,
        reason: str,
        on_error,
        *,
        max_size: int,
    ) -> None:
        if "/" in final_name or final_name in {"", ".", ".."}:
            on_error(reason)
        fd = -1
        try:
            fd = os.open(
                final_name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=dir_fd,
            )
            st = os.fstat(fd)
            if (
                not stat.S_ISREG(st.st_mode)
                or st.st_uid != uid
                or stat.S_IMODE(st.st_mode) != 0o600
                or st.st_nlink not in {1, 2}
                or st.st_size < 0
                or st.st_size > max_size
            ):
                on_error(reason)
            payload = read_exact_fd(fd, st.st_size)
            if len(payload) != st.st_size or os.read(fd, 1):
                on_error(reason)
            digest = hashlib.sha256(payload).hexdigest()
        except OSError:
            on_error(reason)
        finally:
            if fd >= 0:
                os.close(fd)
        quarantine_name = (
            f".acgs-clean-sibling.preserved.{final_name}.{st.st_size}.{digest}.bad"
        )
        if parse_atomic_temp_name(quarantine_name) is not None:
            on_error(reason)
        if not re.fullmatch(
            rf"\.acgs-clean-sibling\.preserved\.{re.escape(final_name)}\.[0-9]+\.[0-9a-f]{{64}}\.bad",
            quarantine_name,
        ):
            on_error(reason)
        if st.st_nlink == 2:
            if reconcile_same_inode_quarantine_link(
                dir_fd,
                final_name,
                quarantine_name,
                st.st_size,
                digest,
                reason,
                on_error,
            ):
                return
            on_error(reason)
        try:
            os.link(
                final_name,
                quarantine_name,
                src_dir_fd=dir_fd,
                dst_dir_fd=dir_fd,
                follow_symlinks=False,
            )
            os.fsync(dir_fd)
        except FileExistsError:
            if reconcile_same_inode_quarantine_link(
                dir_fd,
                final_name,
                quarantine_name,
                st.st_size,
                digest,
                reason,
                on_error,
            ):
                return
            if not file_has_exact_payload(
                dir_fd,
                quarantine_name,
                st.st_size,
                digest,
                allow_link_count={1},
            ):
                on_error(reason)
        except OSError:
            on_error(reason)
        try:
            os.unlink(final_name, dir_fd=dir_fd)
            os.fsync(dir_fd)
        except OSError:
            on_error(reason)

    def atomic_publish_no_replace(
        dir_fd: int,
        final_name: str,
        payload: bytes,
        kind: str,
        reason: str,
        on_error,
    ) -> None:
        if "/" in final_name or final_name in {"", ".", ".."}:
            on_error(reason)
        if len(payload) <= 0 or len(payload) > 262144:
            on_error(reason)
        if not atomic_final_name_matches_kind(kind, final_name):
            on_error(reason)
        reconcile_atomic_temps(dir_fd, on_error)
        if file_has_exact_payload(
            dir_fd,
            final_name,
            len(payload),
            hashlib.sha256(payload).hexdigest(),
            allow_link_count={1},
        ):
            return
        try:
            os.stat(final_name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError:
            on_error(reason)
        else:
            quarantine_owned_regular_file(
                dir_fd,
                final_name,
                reason,
                on_error,
                max_size=262144,
            )
        temp_name = atomic_temp_name(kind, final_name, payload)
        temp_fd = -1
        fault = ""  # TEST_ATOMIC_FAULT_MARKER
        try:
            temp_fd = os.open(
                temp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=dir_fd,
            )
            if fault == f"{kind}:after-temp-create":
                on_error(f"{reason}-after-temp-create")
            if fault == f"{kind}:partial-write":
                partial = payload[: max(1, len(payload) // 2)]
                write_all_fd(temp_fd, partial, reason, on_error)
                fdatasync_file(temp_fd)
                on_error(f"{reason}-partial-write")
            write_all_fd(temp_fd, payload, reason, on_error)
            fdatasync_file(temp_fd)
            if fault == f"{kind}:after-file-fsync":
                on_error(f"{reason}-after-file-fsync")
        except OSError:
            on_error(reason)
        finally:
            if temp_fd >= 0:
                os.close(temp_fd)
        try:
            os.link(
                temp_name,
                final_name,
                src_dir_fd=dir_fd,
                dst_dir_fd=dir_fd,
                follow_symlinks=False,
            )
            os.fsync(dir_fd)
            if fault == f"{kind}:after-atomic-publish":
                on_error(f"{reason}-after-atomic-publish")
            os.unlink(temp_name, dir_fd=dir_fd)
            os.fsync(dir_fd)
            if fault == f"{kind}:after-dir-fsync":
                on_error(f"{reason}-after-dir-fsync")
        except FileExistsError:
            pass
        except OSError:
            on_error(reason)
        verify_final_atomic_payload(dir_fd, final_name, payload, reason, on_error)

    def read_committed_ledger(proof_label_value: str) -> dict[str, str] | None:
        if recovery_fd < 0:
            return None
        ledger_fd = -1
        record_fd = -1
        try:
            ledger_fd = os.open(
                "acgs-clean-sibling-recovery-ledger",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=recovery_fd,
            )
            ledger_st = os.fstat(ledger_fd)
            if (
                ledger_st.st_uid != uid
                or stat.S_IMODE(ledger_st.st_mode) != 0o700
                or ledger_st.st_nlink < 1
            ):
                fail("cleanup refused recovery ledger directory identity")
            record_fd = os.open(
                f"{proof_label_value}.committed",
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=ledger_fd,
            )
            record_st = os.fstat(record_fd)
            if (
                not stat.S_ISREG(record_st.st_mode)
                or record_st.st_uid != uid
                or stat.S_IMODE(record_st.st_mode) != 0o600
                or record_st.st_nlink != 1
                or record_st.st_size <= 0
                or record_st.st_size > 262144
            ):
                fail("cleanup refused recovery ledger file identity")
            record = os.read(record_fd, record_st.st_size + 1)
            if len(record) != record_st.st_size or os.read(record_fd, 1):
                fail("cleanup refused recovery ledger size")
            return parse_committed_ledger_record(record, proof_label_value)
        except FileNotFoundError:
            return None
        except OSError:
            fail("cleanup refused recovery ledger open")
        finally:
            if record_fd >= 0:
                os.close(record_fd)
            if ledger_fd >= 0:
                os.close(ledger_fd)

    def completed_ledger_record_exists(proof_label_value: str) -> bool:
        if recovery_fd < 0:
            return False
        ledger_fd = -1
        complete_fd = -1
        complete_record = (
            b"completed_recovery_record=1\n"
            + f"proof_label={proof_label_value}\n".encode("ascii")
        )
        try:
            ledger_fd = os.open(
                "acgs-clean-sibling-recovery-ledger",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=recovery_fd,
            )
            ledger_st = os.fstat(ledger_fd)
            if (
                ledger_st.st_uid != uid
                or stat.S_IMODE(ledger_st.st_mode) != 0o700
                or ledger_st.st_nlink < 1
            ):
                fail("cleanup refused recovery ledger directory identity")
            complete_fd = os.open(
                f"{proof_label_value}.complete",
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=ledger_fd,
            )
            complete_st = os.fstat(complete_fd)
            if (
                not stat.S_ISREG(complete_st.st_mode)
                or complete_st.st_uid != uid
                or stat.S_IMODE(complete_st.st_mode) != 0o600
                or complete_st.st_nlink != 1
                or complete_st.st_size != len(complete_record)
            ):
                fail("cleanup refused recovery ledger complete identity")
            complete_payload = os.read(complete_fd, complete_st.st_size + 1)
            if complete_payload != complete_record or os.read(complete_fd, 1):
                fail("cleanup refused recovery ledger complete content")
            return True
        except FileNotFoundError:
            return False
        except OSError:
            fail("cleanup refused recovery ledger complete open")
        finally:
            if complete_fd >= 0:
                os.close(complete_fd)
            if ledger_fd >= 0:
                os.close(ledger_fd)

    def committed_ledger_appears_complete(proof_label_value: str) -> bool:
        ledger_fd = -1
        record_fd = -1
        try:
            ledger_fd = os.open(
                "acgs-clean-sibling-recovery-ledger",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=recovery_fd,
            )
            record_fd = os.open(
                f"{proof_label_value}.committed",
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=ledger_fd,
            )
            st = os.fstat(record_fd)
            if (
                not stat.S_ISREG(st.st_mode)
                or st.st_uid != uid
                or stat.S_IMODE(st.st_mode) != 0o600
                or st.st_nlink != 1
                or st.st_size <= 0
                or st.st_size > 262144
            ):
                return False
            payload = os.read(record_fd, st.st_size + 1)
            return (
                len(payload) == st.st_size
                and payload.endswith(b"\n")
                and b"\nintent_payload_manifest_b64=" in payload
            )
        except OSError:
            return False
        finally:
            if record_fd >= 0:
                os.close(record_fd)
            if ledger_fd >= 0:
                os.close(ledger_fd)

    def restore_committed_intents_before_parse() -> None:
        if recovery_fd < 0:
            return
        reconcile_atomic_temps(recovery_fd, fail)
        existing_names = [name for name in list_recovery_names() if name.endswith(".intent")]
        ledger_names: list[str] = []
        ledger_fd = -1
        try:
            ledger_fd = os.open(
                "acgs-clean-sibling-recovery-ledger",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=recovery_fd,
            )
            reconcile_atomic_temps(ledger_fd, fail)
            ledger_names = sorted(os.listdir(ledger_fd), key=os.fsencode)
        except FileNotFoundError:
            ledger_names = []
        except OSError:
            fail("cleanup refused recovery ledger scan")
        finally:
            if ledger_fd >= 0:
                os.close(ledger_fd)
        committed = [name for name in ledger_names if name.endswith(".committed")]
        if committed:
            if len(committed) != 1:
                fail("cleanup refused ambiguous recovery ledger records")
            proof_label_value = committed[0].removesuffix(".committed")
            if not re.fullmatch(rf"acp-postgres-gate-{uid}-[0-9a-f]{{32}}", proof_label_value):
                return
            if not existing_names and completed_ledger_record_exists(proof_label_value):
                return
            if existing_names and not committed_ledger_appears_complete(proof_label_value):
                return
            ledger_record = read_committed_ledger(proof_label_value)
            if ledger_record is None:
                return
            payloads = parse_ledger_payload_manifest(
                ledger_record["intent_payload_manifest_b64"],
                int(ledger_record["intent_count"]),
                proof_label_value,
                ledger_record["packet_sha256"],
            )
            if not set(existing_names).issubset(payloads):
                fail("cleanup refused recovery ledger partial intent set")
            for existing_name in existing_names:
                expected_payload = payloads[existing_name]
                expected_digest = hashlib.sha256(expected_payload).hexdigest()
                if file_has_exact_payload(
                    recovery_fd,
                    existing_name,
                    len(expected_payload),
                    expected_digest,
                    allow_link_count={1},
                ):
                    continue
                try:
                    read_intent_file(existing_name)
                except SystemExit:
                    pass
                else:
                    fail("cleanup refused recovery ledger intent content")
                quarantine_owned_regular_file(
                    recovery_fd,
                    existing_name,
                    "cleanup refused recovery ledger intent content",
                    fail,
                    max_size=2048,
                )
            for name, payload in payloads.items():
                if file_has_exact_payload(
                    recovery_fd,
                    name,
                    len(payload),
                    hashlib.sha256(payload).hexdigest(),
                    allow_link_count={1},
                ):
                    continue
                try:
                    os.stat(name, dir_fd=recovery_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                except OSError:
                    fail("cleanup refused recovery ledger intent stat")
                else:
                    fail("cleanup refused recovery ledger intent content")
                atomic_publish_no_replace(
                    recovery_fd,
                    name,
                    payload,
                    "intent",
                    "cleanup refused recovery ledger intent restore",
                    fail,
                )
            try:
                os.fsync(recovery_fd)
            except OSError:
                fail("cleanup refused recovery ledger intent fsync")
            intent_identity_by_name.clear()
            intent_payload_by_name.clear()
            return
        proof_labels: set[str] = set()
        for existing_name in existing_names:
            parsed_existing = read_intent_file(existing_name)
            proof_labels.add(parsed_existing.get("proof_label", ""))
        intent_identity_by_name.clear()
        intent_payload_by_name.clear()
        if existing_names and len(proof_labels) != 1:
            return
        proof_label_value = ""
        if existing_names:
            proof_label_value = next(iter(proof_labels))
        else:
            ledger_fd = -1
            try:
                ledger_fd = os.open(
                    "acgs-clean-sibling-recovery-ledger",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=recovery_fd,
                )
                reconcile_atomic_temps(ledger_fd, fail)
                ledger_names = sorted(os.listdir(ledger_fd), key=os.fsencode)
            except FileNotFoundError:
                return
            except OSError:
                fail("cleanup refused recovery ledger scan")
            finally:
                if ledger_fd >= 0:
                    os.close(ledger_fd)
            committed = [name for name in ledger_names if name.endswith(".committed")]
            if not committed:
                return
            if len(committed) != 1:
                fail("cleanup refused ambiguous recovery ledger records")
            proof_label_value = committed[0].removesuffix(".committed")
            if completed_ledger_record_exists(proof_label_value):
                return
        if not re.fullmatch(rf"acp-postgres-gate-{uid}-[0-9a-f]{{32}}", proof_label_value):
            return
        ledger_record = read_committed_ledger(proof_label_value)
        if ledger_record is None:
            return
        payloads = parse_ledger_payload_manifest(
            ledger_record["intent_payload_manifest_b64"],
            int(ledger_record["intent_count"]),
            proof_label_value,
            ledger_record["packet_sha256"],
        )
        if not set(existing_names).issubset(payloads):
            fail("cleanup refused recovery ledger partial intent set")
        for existing_name in existing_names:
            expected_payload = payloads[existing_name]
            try:
                fd = os.open(
                    existing_name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=recovery_fd,
                )
            except OSError:
                fail("cleanup refused recovery ledger intent open")
            try:
                st = os.fstat(fd)
                if (
                    not stat.S_ISREG(st.st_mode)
                    or st.st_uid != uid
                    or stat.S_IMODE(st.st_mode) != 0o600
                    or st.st_nlink != 1
                    or st.st_size != len(expected_payload)
                ):
                    fail("cleanup refused recovery ledger intent identity")
                current_payload = os.read(fd, len(expected_payload) + 1)
                if current_payload != expected_payload or os.read(fd, 1):
                    fail("cleanup refused recovery ledger intent content")
            finally:
                os.close(fd)
        if sorted(existing_names, key=os.fsencode) == sorted(payloads, key=os.fsencode):
            return
        for name, payload in payloads.items():
            try:
                current = os.stat(name, dir_fd=recovery_fd, follow_symlinks=False)
            except FileNotFoundError:
                atomic_publish_no_replace(
                    recovery_fd,
                    name,
                    payload,
                    "intent",
                    "cleanup refused recovery ledger intent restore",
                    fail,
                )
            except OSError:
                fail("cleanup refused recovery ledger intent stat")
            else:
                if (
                    not stat.S_ISREG(current.st_mode)
                    or current.st_uid != uid
                    or stat.S_IMODE(current.st_mode) != 0o600
                    or current.st_nlink != 1
                    or current.st_size != len(payload)
                ):
                    fail("cleanup refused recovery ledger intent identity")
                try:
                    fd = os.open(
                        name,
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=recovery_fd,
                    )
                    try:
                        existing_payload = os.read(fd, len(payload) + 1)
                        if existing_payload != payload or os.read(fd, 1):
                            fail("cleanup refused recovery ledger intent content")
                    finally:
                        os.close(fd)
                except OSError:
                    fail("cleanup refused recovery ledger intent open")
        try:
            os.fsync(recovery_fd)
        except OSError:
            fail("cleanup refused recovery ledger intent fsync")
        intent_identity_by_name.clear()
        intent_payload_by_name.clear()

    restore_committed_intents_before_parse()

    def parse_recovery_intents() -> tuple[dict[str, str] | None, list[tuple[str, str, str]], list[tuple[str, str, str]], list[str]]:
        if recovery_fd < 0:
            return None, [], [], []
        names = list_recovery_names()
        intent_files = [name for name in names if name.endswith(".intent")]
        if len(intent_files) > 64:
            fail("cleanup refused too many PostgreSQL recovery intents")
        if not intent_files:
            return None, [], [], []
        groups: dict[str, dict[str, object]] = {}
        for name in intent_files:
            parsed_intent = read_intent_file(name)
            phase_value = parsed_intent.get("phase", "")
            nonce_value = parsed_intent.get("proof_nonce", "")
            proof_value = parsed_intent.get("proof_label", "")
            server_value = parsed_intent.get("server_name", "")
            if not re.fullmatch(r"[0-9a-f]{32}", nonce_value):
                fail("cleanup refused PostgreSQL recovery intent nonce")
            expected_label = f"acp-postgres-gate-{uid}-{nonce_value}"
            if proof_value != expected_label or server_value != f"{expected_label}-server":
                fail("cleanup refused PostgreSQL recovery intent binding")
            group = groups.setdefault(
                proof_value,
                {
                    "nonce": nonce_value,
                    "server": None,
                    "clients": set(),
                    "files": [],
                    "bridge": None,
                },
            )
            if group["nonce"] != nonce_value:
                fail("cleanup refused PostgreSQL recovery intent cross nonce")
            group["files"].append(name)  # type: ignore[index]
            if phase_value == "server-intent":
                intent_version = parsed_intent.get("intent_version")
                v1_required_keys = [
                    "intent_version",
                    "phase",
                    "proof_nonce",
                    "proof_label",
                    "server_name",
                    "record_path",
                    "server_cidfile",
                    "server_namefile",
                ]
                v2_required_keys = [
                    "intent_version",
                    "schema",
                    "phase",
                    "proof_nonce",
                    "proof_label",
                    "server_name",
                    "record_path",
                    "server_cidfile",
                    "server_namefile",
                    "socket_bridge_basename",
                    "socket_bridge_identity",
                    "socket_bridge_marker_sha256",
                    "socket_bridge_mnt_id",
                ]
                if intent_version not in {"1", "2"}:
                    fail("cleanup refused PostgreSQL server intent version")
                if intent_version == "1" and list(parsed_intent) != v1_required_keys:
                    fail("cleanup refused PostgreSQL server intent grammar")
                if intent_version == "2":
                    if parsed_intent.get("schema") != "acgs-postgres-recovery-intent/server/v2":
                        fail("cleanup refused PostgreSQL server intent schema")
                    if list(parsed_intent) != v2_required_keys:
                        fail("cleanup refused PostgreSQL server intent grammar")
                if name != f"{proof_value}-server.intent":
                    fail("cleanup refused PostgreSQL server intent filename")
                if group["server"] is not None:
                    fail("cleanup refused duplicate PostgreSQL server intent")
                if intent_version == "2":
                    state_dir_value = os.path.dirname(parsed_intent["server_namefile"])
                    if (
                        os.path.basename(parsed_intent["server_cidfile"]) != "server.cid"
                        or os.path.basename(parsed_intent["server_namefile"]) != "server.name"
                        or os.path.dirname(parsed_intent["server_cidfile"]) != state_dir_value
                    ):
                        fail("cleanup refused PostgreSQL server intent live record binding")
                if (
                    parsed_intent["record_path"] != parsed_intent["server_namefile"]
                    or not safe_under_tmp_root(parsed_intent["server_cidfile"])
                    or not safe_under_tmp_root(parsed_intent["server_namefile"])
                ):
                    fail("cleanup refused PostgreSQL server intent path binding")
                if intent_version == "2":
                    bridge_basename = parsed_intent["socket_bridge_basename"]
                    bridge_identity = parsed_intent["socket_bridge_identity"]
                    bridge_marker_sha256 = parsed_intent["socket_bridge_marker_sha256"]
                    bridge_mnt_id = parsed_intent["socket_bridge_mnt_id"]
                    if bridge_basename != f"{proof_value}-socket-bridge":
                        fail("cleanup refused PostgreSQL server intent bridge binding")
                    if not re.fullmatch(r"[0-9]+:[0-9]+:[0-9]+:1777", bridge_identity):
                        fail("cleanup refused PostgreSQL server intent bridge identity")
                    if not re.fullmatch(r"[0-9a-f]{64}", bridge_marker_sha256):
                        fail("cleanup refused PostgreSQL server intent bridge marker")
                    if not bridge_mnt_id.isdigit():
                        fail("cleanup refused PostgreSQL server intent bridge mount")
                    group["bridge"] = {
                        "socket_bridge_basename": bridge_basename,
                        "socket_bridge_identity": bridge_identity,
                        "socket_bridge_marker_sha256": bridge_marker_sha256,
                        "socket_bridge_mnt_id": bridge_mnt_id,
                    }
                group["server"] = parsed_intent["server_name"]
            elif phase_value == "client-intent":
                required_keys = [
                    "intent_version",
                    "phase",
                    "proof_nonce",
                    "proof_label",
                    "server_name",
                    "client_name",
                    "record_path",
                    "client_cidfile",
                    "client_namefile",
                ]
                if list(parsed_intent) != required_keys:
                    fail("cleanup refused PostgreSQL client intent grammar")
                if parsed_intent.get("intent_version") != "1":
                    fail("cleanup refused PostgreSQL client intent version")
                client_name = parsed_intent["client_name"]
                if not re.fullmatch(rf"{re.escape(proof_value)}-client-[0-9]+-[0-9]+", client_name):
                    fail("cleanup refused PostgreSQL client intent name")
                if name != f"{client_name}.intent":
                    fail("cleanup refused PostgreSQL client intent filename")
                if (
                    parsed_intent["record_path"] != parsed_intent["client_namefile"]
                    or not safe_under_tmp_root(parsed_intent["client_cidfile"])
                    or not safe_under_tmp_root(parsed_intent["client_namefile"])
                ):
                    fail("cleanup refused PostgreSQL client intent path binding")
                clients = group["clients"]
                assert isinstance(clients, set)
                if client_name in clients:
                    fail("cleanup refused duplicate PostgreSQL client intent")
                clients.add(client_name)
            else:
                fail("cleanup refused PostgreSQL recovery intent phase")
        if len(groups) != 1:
            fail("cleanup refused ambiguous PostgreSQL recovery intent groups")
        proof_label_value, group_value = next(iter(groups.items()))
        server_name_value = group_value["server"]
        if not isinstance(server_name_value, str):
            fail("cleanup refused missing PostgreSQL server intent")
        nonce_value = str(group_value["nonce"])
        bridge_value = group_value.get("bridge")
        if isinstance(bridge_value, dict):
            intent_bridge_packet.update(
                {
                    "proof_nonce": nonce_value,
                    "proof_label": proof_label_value,
                    "server_name": server_name_value,
                    "socket_bridge_basename": bridge_value["socket_bridge_basename"],
                    "socket_bridge_identity": bridge_value["socket_bridge_identity"],
                    "socket_bridge_marker_sha256": bridge_value["socket_bridge_marker_sha256"],
                    "socket_bridge_mnt_id": bridge_value["socket_bridge_mnt_id"],
                    "recovery_root_mnt_id": bridge_value["socket_bridge_mnt_id"],
                }
            )
            base_packet = {
                "contract_version": "2",
                "schema": "acgs-postgres-recovery-contract/v2",
                "external_cleanup_uncertain": "1",
                "cleanup_status": "2",
                "proof_nonce": nonce_value,
                "proof_label": proof_label_value,
                "server_name": server_name_value,
                **bridge_value,
                "recovery_root_mnt_id": bridge_value["socket_bridge_mnt_id"],
            }
        else:
            base_packet = {
                "external_cleanup_uncertain": "1",
                "cleanup_status": "2",
                "proof_nonce": nonce_value,
                "proof_label": proof_label_value,
                "server_name": server_name_value,
            }
        servers = [(server_name_value, server_name_value, "main")]
        clients = [
            (client_name, client_name, "trusted-broker")
            for client_name in sorted(group_value["clients"])  # type: ignore[arg-type]
        ]
        return base_packet, servers, clients, sorted(group_value["files"])  # type: ignore[arg-type]

    intent_packet, intent_server_records, intent_client_records, intent_names = parse_recovery_intents()
    if not contracts:
        if intent_packet is not None:
            parsed = intent_packet
            nonce = parsed["proof_nonce"]
            proof_label = parsed["proof_label"]
            server_name = parsed["server_name"]
            if parsed.get("contract_version") == "2":
                payload_lines = [
                    "contract_version=2",
                    "schema=acgs-postgres-recovery-contract/v2",
                    "external_cleanup_uncertain=1",
                    "cleanup_status=2",
                    f"proof_nonce={nonce}",
                    f"proof_label={proof_label}",
                    f"server_name={server_name}",
                    f"socket_bridge_basename={parsed['socket_bridge_basename']}",
                    f"socket_bridge_identity={parsed['socket_bridge_identity']}",
                    f"socket_bridge_marker_sha256={parsed['socket_bridge_marker_sha256']}",
                    f"socket_bridge_mnt_id={parsed['socket_bridge_mnt_id']}",
                    f"recovery_root_mnt_id={parsed['recovery_root_mnt_id']}",
                ]
            else:
                payload_lines = [
                    "external_cleanup_uncertain=1",
                    "cleanup_status=2",
                    f"proof_nonce={nonce}",
                    f"proof_label={proof_label}",
                    f"server_name={server_name}",
                ]
            payload = ("\n".join(payload_lines) + "\n").encode("ascii")
            contract = os.path.join(recovery_root, intent_names[0])
            text = payload.decode("ascii")
            lines = text.splitlines()
            # Fall through into the common retained-packet writer below. Intent
            # records remain linked until stable exact-label absence is proven.
        elif not nonce_files:
            raise SystemExit(0)
        else:
            if len(nonce_files) != 1:
                fail("cleanup refused duplicate recovery nonce records")
            nonce_path = nonce_files[0]
            state_dir = os.path.dirname(nonce_path)

            def read_state_file(path: str, label: str, required: bool) -> bytes:
                try:
                    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                except FileNotFoundError:
                    if not required:
                        return b""
                    fail(f"cleanup refused missing recovery {label}")
                except OSError as exc:
                    fail(f"cleanup refused recovery {label} open: {exc}")
                try:
                    before = os.fstat(fd)
                    if (
                        not stat.S_ISREG(before.st_mode)
                        or before.st_uid != uid
                        or stat.S_IMODE(before.st_mode) != 0o600
                        or before.st_nlink != 1
                        or before.st_size > 1024
                    ):
                        fail(f"cleanup refused recovery {label} identity")
                    path_stat = os.stat(path, follow_symlinks=False)
                    if (
                        before.st_dev,
                        before.st_ino,
                        before.st_uid,
                        stat.S_IMODE(before.st_mode),
                        before.st_nlink,
                        before.st_size,
                    ) != (
                        path_stat.st_dev,
                        path_stat.st_ino,
                        path_stat.st_uid,
                        stat.S_IMODE(path_stat.st_mode),
                        path_stat.st_nlink,
                        path_stat.st_size,
                    ):
                        fail(f"cleanup refused recovery {label} path binding")
                    data = os.read(fd, before.st_size + 1)
                    if len(data) != before.st_size or os.read(fd, 1):
                        fail(f"cleanup refused recovery {label} size")
                    after = os.fstat(fd)
                    if (
                        after.st_dev,
                        after.st_ino,
                        after.st_uid,
                        stat.S_IMODE(after.st_mode),
                        after.st_nlink,
                        after.st_size,
                    ) != (
                        before.st_dev,
                        before.st_ino,
                        before.st_uid,
                        stat.S_IMODE(before.st_mode),
                        before.st_nlink,
                        before.st_size,
                    ):
                        fail(f"cleanup refused recovery {label} changed during read")
                    return data
                finally:
                    os.close(fd)

            nonce_raw = read_state_file(nonce_path, "proof nonce", True)
            try:
                nonce_text = nonce_raw.decode("ascii")
            except UnicodeDecodeError:
                fail("cleanup refused recovery nonce grammar")
            if not re.fullmatch(r"[0-9a-f]{32}\n", nonce_text):
                fail("cleanup refused recovery nonce grammar")
            nonce = nonce_text.strip()
            proof_label = f"acp-postgres-gate-{uid}-{nonce}"
            server_name = f"{proof_label}-server"
            server_name_raw = read_state_file(os.path.join(state_dir, "server.name"), "server name", False)
            if server_name_raw:
                try:
                    server_name_text = server_name_raw.decode("ascii")
                except UnicodeDecodeError:
                    fail("cleanup refused recovery server name grammar")
                if server_name_text != server_name + "\n":
                    fail("cleanup refused recovery server name binding")
            server_cid = ""
            server_cid_raw = read_state_file(os.path.join(state_dir, "server.cid"), "server cid", False)
            if server_cid_raw:
                try:
                    server_cid_text = server_cid_raw.decode("ascii")
                except UnicodeDecodeError:
                    fail("cleanup refused recovery cid grammar")
                if not re.fullmatch(r"[0-9a-f]{12,64}\n", server_cid_text):
                    fail("cleanup refused recovery cid grammar")
                server_cid = server_cid_text.strip()
            lines = [
                "external_cleanup_uncertain=1",
                "cleanup_status=2",
                f"proof_nonce={nonce}",
                f"proof_label={proof_label}",
                f"server_name={server_name}",
            ]
            if server_cid:
                lines.append(f"server_cid={server_cid}")
            payload = ("\n".join(lines) + "\n").encode("ascii")
            contracts = [nonce_path]
            contract = nonce_path
            text = payload.decode("ascii")
            lines = text.splitlines()
            parsed = {line.split("=", 1)[0]: line.split("=", 1)[1] for line in lines}
            # Fall through into the common retained-packet writer below.
    else:
        if len(contracts) != 1:
            fail("cleanup refused duplicate recovery contracts")
        contract = contracts[0]
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in contract):
            fail("cleanup refused recovery contract path")
        try:
            contract_fd = os.open(contract, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as exc:
            fail(f"cleanup refused recovery contract open: {exc}")
        try:
            before = os.fstat(contract_fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != uid
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or before.st_size > 1024
            ):
                fail("cleanup refused recovery contract identity")
            path_stat = os.stat(contract, follow_symlinks=False)
            if (
                before.st_dev,
                before.st_ino,
                before.st_uid,
                stat.S_IMODE(before.st_mode),
                before.st_nlink,
                before.st_size,
            ) != (
                path_stat.st_dev,
                path_stat.st_ino,
                path_stat.st_uid,
                stat.S_IMODE(path_stat.st_mode),
                path_stat.st_nlink,
                path_stat.st_size,
            ):
                fail("cleanup refused recovery contract path binding")
            payload = os.read(contract_fd, before.st_size + 1)
            if len(payload) != before.st_size or os.read(contract_fd, 1):
                fail("cleanup refused recovery contract size")
            after = os.fstat(contract_fd)
            if (
                after.st_dev,
                after.st_ino,
                after.st_uid,
                stat.S_IMODE(after.st_mode),
                after.st_nlink,
                after.st_size,
            ) != (
                before.st_dev,
                before.st_ino,
                before.st_uid,
                stat.S_IMODE(before.st_mode),
                before.st_nlink,
                before.st_size,
            ):
                fail("cleanup refused recovery contract changed during read")
        finally:
            os.close(contract_fd)
        try:
            text = payload.decode("ascii")
        except UnicodeDecodeError:
            fail("cleanup refused recovery contract grammar")
        lines = text.splitlines()
        if text != "\n".join(lines) + "\n":
            fail("cleanup refused recovery contract grammar")
        parsed: dict[str, str] = {}
        for line in lines:
            if "=" not in line:
                fail("cleanup refused recovery contract grammar")
            key, value = line.split("=", 1)
            if key in parsed:
                fail("cleanup refused duplicate recovery contract keys")
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
                fail("cleanup refused recovery contract grammar")
            parsed[key] = value
    legacy_required = [
        "external_cleanup_uncertain",
        "cleanup_status",
        "proof_nonce",
        "proof_label",
        "server_name",
    ]
    legacy_optional = ["server_cid"]
    v2_base = [
        "contract_version",
        "schema",
        "external_cleanup_uncertain",
        "cleanup_status",
        "proof_nonce",
        "proof_label",
        "server_name",
    ]
    parsed_keys = list(parsed)
    is_v2_contract = False
    if parsed_keys == legacy_required or parsed_keys == legacy_required + legacy_optional:
        is_v2_contract = False
    else:
        if parsed_keys[: len(v2_base)] != v2_base:
            fail("cleanup refused recovery contract grammar")
        is_v2_contract = True
        if parsed["contract_version"] != "2":
            fail("cleanup refused recovery contract version")
        if parsed["schema"] != "acgs-postgres-recovery-contract/v2":
            fail("cleanup refused recovery contract schema")
        allowed_tail = [
            "socket_bridge_creation_uncertain",
            "server_cid",
            "socket_bridge_basename",
            "socket_bridge_identity",
            "socket_bridge_marker_sha256",
            "socket_bridge_mnt_id",
            "recovery_root_mnt_id",
        ]
        tail = parsed_keys[len(v2_base):]
        cursor = 0
        if cursor < len(tail) and tail[cursor] == "socket_bridge_creation_uncertain":
            cursor += 1
        if cursor < len(tail) and tail[cursor] == "server_cid":
            cursor += 1
        bridge_tail = tail[cursor:]
        incomplete_bridge_tail = ["socket_bridge_basename", "recovery_root_mnt_id"]
        if bridge_tail and bridge_tail not in (allowed_tail[2:], incomplete_bridge_tail):
            fail("cleanup refused recovery contract grammar")
        if any(key not in allowed_tail for key in tail):
            fail("cleanup refused recovery contract grammar")
    nonce = parsed["proof_nonce"]
    proof_label = parsed["proof_label"]
    server_name = parsed["server_name"]
    server_cid = parsed.get("server_cid", "")
    bridge_creation_uncertain = parsed.get("socket_bridge_creation_uncertain", "0")
    bridge_basename = parsed.get("socket_bridge_basename", "")
    bridge_identity = parsed.get("socket_bridge_identity", "")
    bridge_marker_sha256 = parsed.get("socket_bridge_marker_sha256", "")
    bridge_mnt_id = parsed.get("socket_bridge_mnt_id", "")
    recovery_root_mnt_id = parsed.get("recovery_root_mnt_id", "")
    if parsed["external_cleanup_uncertain"] != "1":
        fail("cleanup refused recovery contract certainty")
    if not re.fullmatch(r"[0-9]+", parsed["cleanup_status"]):
        fail("cleanup refused recovery contract cleanup status")
    if not re.fullmatch(r"[0-9a-f]{32}", nonce):
        fail("cleanup refused recovery contract nonce")
    expected_label = f"acp-postgres-gate-{uid}-{nonce}"
    if proof_label != expected_label or server_name != f"{expected_label}-server":
        fail("cleanup refused recovery contract binding")
    if server_cid and not re.fullmatch(r"[0-9a-f]{12,64}", server_cid):
        fail("cleanup refused recovery contract cid")
    if is_v2_contract:
        if "socket_bridge_creation_uncertain" in parsed and bridge_creation_uncertain != "1":
            fail("cleanup refused recovery contract bridge certainty")
        if bridge_basename and bridge_basename != f"{proof_label}-socket-bridge":
            fail("cleanup refused recovery contract bridge binding")
        bridge_values = [bridge_basename, bridge_identity, bridge_marker_sha256, bridge_mnt_id, recovery_root_mnt_id]
        creation_uncertain_incomplete = (
            bridge_creation_uncertain == "1"
            and bool(bridge_basename)
            and not bridge_identity
            and not bridge_marker_sha256
            and not bridge_mnt_id
            and bool(recovery_root_mnt_id)
        )
        if any(bridge_values) and not creation_uncertain_incomplete:
            if not all(bridge_values):
                fail("cleanup refused recovery contract bridge metadata")
            if not re.fullmatch(r"[0-9]+:[0-9]+:[0-9]+:1777", bridge_identity):
                fail("cleanup refused recovery contract bridge identity")
            if not re.fullmatch(r"[0-9a-f]{64}", bridge_marker_sha256):
                fail("cleanup refused recovery contract bridge marker")
            if not bridge_mnt_id.isdigit() or not recovery_root_mnt_id.isdigit():
                fail("cleanup refused recovery contract bridge mount")
            if bridge_mnt_id != recovery_root_mnt_id:
                fail("cleanup refused recovery contract bridge mount")
        if creation_uncertain_incomplete and not recovery_root_mnt_id.isdigit():
            fail("cleanup refused recovery contract bridge mount")
        if all(bridge_values):
            if not intent_bridge_packet:
                # A contract alone is not deletion authority for bridge state.
                pass
            else:
                for key in (
                    "proof_nonce",
                    "proof_label",
                    "server_name",
                    "socket_bridge_basename",
                    "socket_bridge_identity",
                    "socket_bridge_marker_sha256",
                    "socket_bridge_mnt_id",
                    "recovery_root_mnt_id",
                ):
                    if parsed.get(key, "") != intent_bridge_packet.get(key, ""):
                        fail("cleanup refused recovery contract intent equivalence")
    packet = payload

    def read_state_file(path: str, label: str, required: bool) -> str:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            if not required:
                return ""
            fail(f"cleanup refused missing recovery {label}")
        except OSError as exc:
            fail(f"cleanup refused recovery {label} open: {exc}")
        try:
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != uid
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or before.st_size > 1024
            ):
                fail(f"cleanup refused recovery {label} identity")
            path_stat = os.stat(path, follow_symlinks=False)
            if (
                before.st_dev,
                before.st_ino,
                before.st_uid,
                stat.S_IMODE(before.st_mode),
                before.st_nlink,
                before.st_size,
            ) != (
                path_stat.st_dev,
                path_stat.st_ino,
                path_stat.st_uid,
                stat.S_IMODE(path_stat.st_mode),
                path_stat.st_nlink,
                path_stat.st_size,
            ):
                fail(f"cleanup refused recovery {label} path binding")
            raw = os.read(fd, before.st_size + 1)
            if len(raw) != before.st_size or os.read(fd, 1):
                fail(f"cleanup refused recovery {label} size")
            after = os.fstat(fd)
            if (
                after.st_dev,
                after.st_ino,
                after.st_uid,
                stat.S_IMODE(after.st_mode),
                after.st_nlink,
                after.st_size,
            ) != (
                before.st_dev,
                before.st_ino,
                before.st_uid,
                stat.S_IMODE(before.st_mode),
                before.st_nlink,
                before.st_size,
            ):
                fail(f"cleanup refused recovery {label} changed during read")
        finally:
            os.close(fd)
        try:
            text_value = raw.decode("ascii")
        except UnicodeDecodeError:
            fail(f"cleanup refused recovery {label} grammar")
        if not text_value.endswith("\n") or text_value.count("\n") != 1:
            fail(f"cleanup refused recovery {label} grammar")
        value = text_value[:-1]
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            fail(f"cleanup refused recovery {label} grammar")
        return value

    state_dir = os.path.dirname(contract)
    server_records: list[tuple[str, str, str]] = []
    server_records.extend(intent_server_records)
    if server_cid:
        server_records.append((server_cid, server_name, "main"))
    else:
        cid_from_file = read_state_file(os.path.join(state_dir, "server.cid"), "server cid", False)
        if cid_from_file:
            if not re.fullmatch(r"[0-9a-f]{12,64}", cid_from_file):
                fail("cleanup refused recovery cid grammar")
            server_records.append((cid_from_file, server_name, "main"))
    name_from_file = read_state_file(os.path.join(state_dir, "server.name"), "server name", False)
    if name_from_file:
        if name_from_file != server_name:
            fail("cleanup refused recovery server name binding")
        server_records.append((server_name, server_name, "main"))

    client_records: list[tuple[str, str, str]] = []
    client_records.extend(intent_client_records)
    client_dir = os.path.join(state_dir, "client")
    if os.path.isdir(client_dir) and not os.path.islink(client_dir):
        for name in sorted(os.listdir(client_dir)):
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
                fail("cleanup refused recovery client record grammar")
            path = os.path.join(client_dir, name)
            if name.endswith(".cid"):
                expected_name = name[:-4]
                if not re.fullmatch(
                    rf"{re.escape(proof_label)}-client-[0-9]+-[0-9]+",
                    expected_name,
                ):
                    fail("cleanup refused recovery client name grammar")
                value = read_state_file(path, "client cid", True)
                if not re.fullmatch(r"[0-9a-f]{12,64}", value):
                    fail("cleanup refused recovery client cid grammar")
                client_records.append((value, expected_name, "trusted-broker"))
            elif name.endswith(".name"):
                expected_name = name[:-5]
                if not re.fullmatch(
                    rf"{re.escape(proof_label)}-client-[0-9]+-[0-9]+",
                    expected_name,
                ):
                    fail("cleanup refused recovery client name grammar")
                value = read_state_file(path, "client name", True)
                if value != expected_name:
                    fail("cleanup refused recovery client name binding")
                client_records.append((value, expected_name, "trusted-broker"))

    def retain_packet(reason: str) -> None:
        retained_dir_name = f"acgs-clean-sibling-retained-recovery-{nonce}"
        retained_file_name = "recovery-contract.env"
        packet_sha = hashlib.sha256(packet).hexdigest()
        try:
            os.mkdir(retained_dir_name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            fail("cleanup refused existing recovery packet")
        except OSError as exc:
            fail(f"cleanup refused recovery packet directory: {exc}")
        retained_dir_fd = -1
        retained_fd = -1
        try:
            retained_dir_fd = os.open(
                retained_dir_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            retained_stat = os.fstat(retained_dir_fd)
            if (
                retained_stat.st_uid != uid
                or stat.S_IMODE(retained_stat.st_mode) != 0o700
                or retained_stat.st_nlink < 1
            ):
                fail("cleanup refused recovery packet directory identity")
            retained_fd = os.open(
                retained_file_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=retained_dir_fd,
            )
            os.write(retained_fd, packet)
            os.fsync(retained_fd)
            written = os.fstat(retained_fd)
            if (
                not stat.S_ISREG(written.st_mode)
                or written.st_uid != uid
                or stat.S_IMODE(written.st_mode) != 0o600
                or written.st_nlink != 1
                or written.st_size != len(packet)
            ):
                fail("cleanup refused recovery packet file identity")
            os.fsync(retained_dir_fd)
        except OSError as exc:
            fail(f"cleanup refused recovery packet write: {exc}")
        finally:
            if retained_fd >= 0:
                os.close(retained_fd)
            if retained_dir_fd >= 0:
                os.close(retained_dir_fd)
        retained_path = os.path.join(tmp_parent, retained_dir_name, retained_file_name)
        print(
            "cleanup retained external recovery packet: "
            f"path={retained_path} sha256={packet_sha} reason={reason}",
            file=sys.stderr,
        )
        raise SystemExit(2)

    def enforce_intent_contract_version_class_before_mutation() -> None:
        if intent_names:
            intent_is_v2 = bool(intent_bridge_packet)
            if intent_is_v2:
                if (
                    not is_v2_contract
                    or bridge_creation_uncertain == "1"
                    or not all(
                        [
                            bridge_basename,
                            bridge_identity,
                            bridge_marker_sha256,
                            bridge_mnt_id,
                            recovery_root_mnt_id,
                        ]
                    )
                ):
                    retain_packet("intent-contract-version-mismatch")
            elif is_v2_contract:
                retain_packet("intent-contract-version-mismatch")
        elif is_v2_contract:
            retain_packet("contract-only-v2")

    enforce_intent_contract_version_class_before_mutation()

    def fd_mnt_id(fd: int) -> str:
        with open(f"/proc/self/fdinfo/{fd}", encoding="utf-8") as fdinfo:
            for line in fdinfo:
                if line.startswith("mnt_id:"):
                    value = line.split(":", 1)[1].strip()
                    if not value.isdigit():
                        retain_packet("socket-bridge-mntid")
                    return value
        retain_packet("socket-bridge-mntid")

    def cleanup_socket_bridge_if_authorized() -> None:
        if not is_v2_contract:
            return
        bridge_values = [
            bridge_basename,
            bridge_identity,
            bridge_marker_sha256,
            bridge_mnt_id,
            recovery_root_mnt_id,
        ]
        if bridge_creation_uncertain == "1" and not all(bridge_values):
            retain_packet("socket-bridge-creation-uncertain")
        if not any(bridge_values):
            retain_packet("socket-bridge-incomplete")
        if not all(bridge_values):
            retain_packet("socket-bridge-incomplete")
        if not intent_bridge_packet:
            retain_packet("socket-bridge-intent-missing")
        if recovery_fd < 0:
            retain_packet("socket-bridge-recovery-fd-missing")
        if bridge_mnt_id != recovery_root_mnt_id:
            retain_packet("socket-bridge-runner-mnt-mismatch")
        if bridge_basename != f"{proof_label}-socket-bridge":
            retain_packet("socket-bridge-name")
        expected_identity_without_mode = bridge_identity.rsplit(":", 1)[0]
        dir_fd = -1
        try:
            root_before = os.fstat(recovery_fd)
            root_local_mnt = fd_mnt_id(recovery_fd)
            if root_before.st_uid != uid or stat.S_IMODE(root_before.st_mode) != 0o700:
                retain_packet("socket-bridge-root-identity")
            try:
                dir_fd = os.open(
                    bridge_basename,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=recovery_fd,
                )
            except FileNotFoundError:
                # Idempotent completion after a prior authenticated bridge
                # rmdir is safe only on the full v2 intent/contract path and
                # only after exact-label Docker absence has already stabilized.
                if intent_bridge_packet:
                    return
                retain_packet("socket-bridge-missing")
            except OSError:
                retain_packet("socket-bridge-open")
            before_dir = os.fstat(dir_fd)
            dir_identity_without_mode = f"{before_dir.st_dev}:{before_dir.st_ino}:{before_dir.st_uid}"
            if dir_identity_without_mode != expected_identity_without_mode:
                retain_packet("socket-bridge-identity")
            if before_dir.st_uid != uid or stat.S_IMODE(before_dir.st_mode) not in {0o1777, 0o700}:
                retain_packet("socket-bridge-mode")
            if fd_mnt_id(dir_fd) != root_local_mnt:
                retain_packet("socket-bridge-cleanup-mnt-mismatch")
            expected_entries = {
                ".acgs-postgres-socket-bridge.v2": "marker",
                ".s.PGSQL.5432": "socket",
                ".s.PGSQL.5432.lock": "lock",
            }
            listed_names = os.listdir(dir_fd)
            if len(listed_names) > len(expected_entries):
                retain_packet("socket-bridge-entry-count")
            names = sorted(listed_names, key=os.fsencode)
            if any(name not in expected_entries for name in names):
                retain_packet("socket-bridge-unknown-entry")
            validated: list[tuple[str, tuple[int, int, int, int, int, int]]] = []
            for name in names:
                try:
                    before = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                except OSError:
                    retain_packet("socket-bridge-entry-stat")
                if before.st_nlink != 1:
                    retain_packet("socket-bridge-entry-link")
                kind = expected_entries[name]
                if kind == "marker":
                    if (
                        not stat.S_ISREG(before.st_mode)
                        or before.st_uid != uid
                        or stat.S_IMODE(before.st_mode) != 0o444
                    ):
                        retain_packet("socket-bridge-marker-identity")
                    if before.st_size <= 0 or before.st_size > 4096:
                        retain_packet("socket-bridge-marker-size")
                    marker_fd = -1
                    try:
                        marker_fd = os.open(
                            name,
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=dir_fd,
                        )
                        opened = os.fstat(marker_fd)
                        if (
                            opened.st_dev != before.st_dev
                            or opened.st_ino != before.st_ino
                            or opened.st_uid != before.st_uid
                            or opened.st_nlink != before.st_nlink
                            or stat.S_IMODE(opened.st_mode) != stat.S_IMODE(before.st_mode)
                            or not stat.S_ISREG(opened.st_mode)
                        ):
                            retain_packet("socket-bridge-marker-open")
                        payload_bytes = os.read(marker_fd, before.st_size + 1)
                        if len(payload_bytes) != before.st_size or os.read(marker_fd, 1):
                            retain_packet("socket-bridge-marker-size")
                        if hashlib.sha256(payload_bytes).hexdigest() != bridge_marker_sha256:
                            retain_packet("socket-bridge-marker-digest")
                    except OSError:
                        retain_packet("socket-bridge-marker-open")
                    finally:
                        if marker_fd >= 0:
                            os.close(marker_fd)
                elif kind == "socket":
                    if not stat.S_ISSOCK(before.st_mode) or before.st_uid != 999:
                        retain_packet("socket-bridge-socket-identity")
                elif kind == "lock":
                    if (
                        not stat.S_ISREG(before.st_mode)
                        or before.st_uid != 999
                        or before.st_size > 1024
                        or stat.S_IMODE(before.st_mode) & 0o022
                    ):
                        retain_packet("socket-bridge-lock-identity")
                else:
                    retain_packet("socket-bridge-entry-kind")
                validated.append(
                    (
                        name,
                        (
                            before.st_dev,
                            before.st_ino,
                            before.st_uid,
                            stat.S_IFMT(before.st_mode),
                            stat.S_IMODE(before.st_mode),
                            before.st_nlink,
                            before.st_size,
                        ),
                    )
                )
            try:
                os.fchmod(dir_fd, 0o700)
            except OSError:
                retain_packet("socket-bridge-harden")
            hardened = os.fstat(dir_fd)
            if (
                f"{hardened.st_dev}:{hardened.st_ino}:{hardened.st_uid}" != expected_identity_without_mode
                or stat.S_IMODE(hardened.st_mode) != 0o700
                or fd_mnt_id(dir_fd) != root_local_mnt
            ):
                retain_packet("socket-bridge-harden-identity")
            for name, expected_identity in validated:
                try:
                    current = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                except OSError:
                    retain_packet("socket-bridge-entry-restat")
                current_identity = (
                    current.st_dev,
                    current.st_ino,
                    current.st_uid,
                    stat.S_IFMT(current.st_mode),
                    stat.S_IMODE(current.st_mode),
                    current.st_nlink,
                    current.st_size,
                )
                if current_identity != expected_identity:
                    retain_packet("socket-bridge-entry-changed")
                try:
                    os.unlink(name, dir_fd=dir_fd)
                except OSError:
                    retain_packet("socket-bridge-entry-unlink")
            try:
                os.fsync(dir_fd)
                rebound_fd = os.open(
                    bridge_basename,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=recovery_fd,
                )
                try:
                    rebound = os.fstat(rebound_fd)
                    if (
                        f"{rebound.st_dev}:{rebound.st_ino}:{rebound.st_uid}"
                        != expected_identity_without_mode
                        or fd_mnt_id(rebound_fd) != root_local_mnt
                    ):
                        retain_packet("socket-bridge-rebound")
                finally:
                    os.close(rebound_fd)
                os.rmdir(bridge_basename, dir_fd=recovery_fd)
                removed = os.fstat(dir_fd)
                if removed.st_nlink != 0:
                    retain_packet("socket-bridge-rmdir")
                try:
                    os.stat(bridge_basename, dir_fd=recovery_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    retain_packet("socket-bridge-rmdir")
                os.fsync(recovery_fd)
            except OSError:
                retain_packet("socket-bridge-remove")
            root_after = os.fstat(recovery_fd)
            if (
                root_after.st_dev != root_before.st_dev
                or root_after.st_ino != root_before.st_ino
                or root_after.st_uid != root_before.st_uid
                or stat.S_IMODE(root_after.st_mode) != stat.S_IMODE(root_before.st_mode)
                or fd_mnt_id(recovery_fd) != root_local_mnt
            ):
                retain_packet("socket-bridge-root-changed")
        finally:
            if dir_fd >= 0:
                os.close(dir_fd)

    docker_bin = shutil.which("docker")
    if not docker_bin or not os.path.isabs(docker_bin):
        retain_packet("docker-unavailable")

    def docker(args: list[str], timeout_seconds: float = 10.0) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                [docker_bin, *args],
                stdin=subprocess.DEVNULL,
                text=True,
                capture_output=True,
                check=False,
                timeout=timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired):
            retain_packet("docker-timeout")

    def inspect(ref: str) -> tuple[str, str, str, str, str]:
        if not re.fullmatch(r"[0-9a-f]{12,64}", ref) and not re.fullmatch(
            rf"{re.escape(proof_label)}-(server|client-[0-9]+-[0-9]+)",
            ref,
        ):
            retain_packet("docker-ref-grammar")
        result = docker([
            "inspect",
            "--format",
            '{{.Id}}|{{.Name}}|{{index .Config.Labels "acgs.postgres.proof"}}|{{index .Config.Labels "acgs.postgres.server"}}|{{index .Config.Labels "acgs.postgres.client"}}',
            ref,
        ])
        if result.returncode == 1:
            retain_packet("docker-inspect-listed-missing")
        if result.returncode != 0:
            retain_packet("docker-inspect")
        output = result.stdout
        if output.count("\n") != 1 or "\r" in output:
            retain_packet("docker-inspect-output")
        parts = output.rstrip("\n").split("|")
        if len(parts) != 5:
            retain_packet("docker-inspect-output")
        inspected_id, inspected_name, inspected_proof, server_role, client_role = parts
        if not re.fullmatch(r"[0-9a-f]{12,64}", inspected_id):
            retain_packet("docker-inspect-id")
        if inspected_proof != proof_label:
            retain_packet("docker-inspect-proof")
        return inspected_id, inspected_name, inspected_proof, server_role, client_role

    def validate_inspected_role(
        inspected: tuple[str, str, str, str, str],
        expected_name: str,
        expected_role: str,
        reason_suffix: str,
    ) -> str:
        inspected_id, inspected_name, _, server_role, client_role = inspected
        if inspected_name != f"/{expected_name}":
            retain_packet(f"docker-name-mismatch{reason_suffix}")
        if expected_role == "main":
            if expected_name != server_name or server_role != "main" or client_role != "":
                retain_packet(f"docker-role-mismatch{reason_suffix}")
        elif expected_role == "trusted-broker":
            if client_role != "trusted-broker" or server_role != "":
                retain_packet(f"docker-role-mismatch{reason_suffix}")
        else:
            retain_packet(f"docker-role-mismatch{reason_suffix}")
        return inspected_id

    def remove_validated(inspected_id: str) -> None:
        removed = docker(["rm", "-f", inspected_id], timeout_seconds=30.0)
        if removed.returncode != 0:
            retain_packet("docker-rm")

    listed = docker(["ps", "-aq", "--filter", f"label=acgs.postgres.proof={proof_label}"])
    if listed.returncode != 0:
        retain_packet("docker-ps")
    if "\r" in listed.stdout:
        retain_packet("docker-ps-output")
    listed_ids = [line for line in listed.stdout.splitlines() if line]
    for listed_id in listed_ids:
        if not re.fullmatch(r"[0-9a-f]{12,64}", listed_id):
            retain_packet("docker-ps-id")
        inspected = inspect(listed_id)
        inspected_id, inspected_name, _, server_role, client_role = inspected
        if server_role == "main":
            if client_role != "":
                retain_packet("docker-inventory-role")
            if inspected_name != f"/{server_name}":
                retain_packet("docker-inventory-server-name")
            validate_inspected_role(inspected, server_name, "main", "")
            remove_validated(inspected_id)
        elif client_role == "trusted-broker":
            if server_role != "":
                retain_packet("docker-inventory-role")
            client_name = inspected_name.removeprefix("/")
            if not re.fullmatch(rf"{re.escape(proof_label)}-client-[0-9]+-[0-9]+", client_name):
                retain_packet("docker-inventory-client-name")
            validate_inspected_role(inspected, client_name, "trusted-broker", "")
            remove_validated(inspected_id)
        else:
            retain_packet("docker-inventory-role")

    def list_exact_label_ids(phase: str) -> list[str]:
        listed_result = docker(["ps", "-aq", "--filter", f"label=acgs.postgres.proof={proof_label}"])
        if listed_result.returncode != 0:
            retain_packet(f"docker-ps-{phase}")
        if "\r" in listed_result.stdout:
            retain_packet(f"docker-ps-output-{phase}")
        ids = [line for line in listed_result.stdout.splitlines() if line]
        for item in ids:
            if not re.fullmatch(r"[0-9a-f]{12,64}", item):
                retain_packet(f"docker-ps-id-{phase}")
        return ids

    def remove_label_inventory(phase: str) -> bool:
        removed_any = False
        for listed_id in list_exact_label_ids(phase):
            inspected = inspect(listed_id)
            inspected_id, inspected_name, _, server_role, client_role = inspected
            if server_role == "main":
                if client_role != "":
                    retain_packet(f"docker-inventory-role-{phase}")
                if inspected_name != f"/{server_name}":
                    retain_packet(f"docker-inventory-server-name-{phase}")
                validate_inspected_role(inspected, server_name, "main", f"-{phase}")
                remove_validated(inspected_id)
                removed_any = True
            elif client_role == "trusted-broker":
                if server_role != "":
                    retain_packet(f"docker-inventory-role-{phase}")
                client_name = inspected_name.removeprefix("/")
                declared_clients = {record[1] for record in intent_client_records}
                if intent_names and client_name not in declared_clients:
                    retain_packet(f"docker-inventory-undeclared-client-{phase}")
                if not re.fullmatch(rf"{re.escape(proof_label)}-client-[0-9]+-[0-9]+", client_name):
                    retain_packet(f"docker-inventory-client-name-{phase}")
                validate_inspected_role(inspected, client_name, "trusted-broker", f"-{phase}")
                remove_validated(inspected_id)
                removed_any = True
            else:
                retain_packet(f"docker-inventory-role-{phase}")
        return removed_any

    if intent_names:
        stable_started: float | None = None
        deadline = time.monotonic() + INTENT_STABLE_ABSENCE_SECONDS * 2.0 + 10.0
        while True:
            if remove_label_inventory("intent-stable"):
                stable_started = None
            elif stable_started is None:
                stable_started = time.monotonic()
            elif time.monotonic() - stable_started >= INTENT_STABLE_ABSENCE_SECONDS:
                break
            if time.monotonic() >= deadline:
                retain_packet("docker-intent-stable-timeout")
            time.sleep(INTENT_POLL_SECONDS)
        if recovery_fd < 0:
            retain_packet("intent-recovery-fd-missing")
        try:
            current_intent_names = sorted(
                name for name in list_recovery_names() if name.endswith(".intent")
            )
        except OSError:
            retain_packet("intent-rescan")
        if current_intent_names != intent_names:
            retain_packet("intent-rescan-mismatch")

        cleanup_socket_bridge_if_authorized()

        def restore_validated_intents() -> None:
            if recovery_fd < 0:
                retain_packet("intent-restore-recovery-fd-missing")
            for restored_name in intent_names:
                try:
                    os.stat(restored_name, dir_fd=recovery_fd, follow_symlinks=False)
                    continue
                except FileNotFoundError:
                    pass
                except OSError:
                    retain_packet("intent-restore-stat")
                payload = intent_payload_by_name.get(restored_name)
                if payload is None:
                    retain_packet("intent-restore-payload")
                atomic_publish_no_replace(
                    recovery_fd,
                    restored_name,
                    payload,
                    "intent",
                    "intent-restore",
                    retain_packet,
                )
            try:
                os.fsync(recovery_fd)
            except OSError:
                retain_packet("intent-restore-fsync")
        def commit_recovery_ledger() -> None:
            ledger_dir = "acgs-clean-sibling-recovery-ledger"
            ledger_file = f"{proof_label}.committed"
            ledger_fd = -1
            record_fd = -1
            intent_manifest = "\n".join(
                f"{name}:{':'.join(str(part) for part in intent_identity_by_name[name])}"
                for name in intent_names
            )
            intent_manifest_sha256 = hashlib.sha256(
                (intent_manifest + "\n").encode("ascii")
            ).hexdigest()
            intent_payload_manifest_b64 = canonical_intent_payload_manifest_b64(intent_names)
            try:
                try:
                    os.mkdir(ledger_dir, 0o700, dir_fd=recovery_fd)
                except FileExistsError:
                    pass
                ledger_fd = os.open(
                    ledger_dir,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=recovery_fd,
                )
                reconcile_atomic_temps(ledger_fd, retain_packet)
                ledger_st = os.fstat(ledger_fd)
                if (
                    ledger_st.st_uid != uid
                    or stat.S_IMODE(ledger_st.st_mode) != 0o700
                    or ledger_st.st_nlink < 1
                ):
                    retain_packet("intent-ledger-directory-identity")
                record = (
                    b"committed_recovery_record=1\n"
                    + f"proof_label={proof_label}\n".encode("ascii")
                    + f"intent_count={len(intent_names)}\n".encode("ascii")
                    + f"packet_sha256={hashlib.sha256(packet).hexdigest()}\n".encode("ascii")
                    + f"intent_manifest_sha256={intent_manifest_sha256}\n".encode("ascii")
                    + f"intent_payload_manifest_b64={intent_payload_manifest_b64}\n".encode("ascii")
                )
                try:
                    record_fd = os.open(
                        ledger_file,
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=ledger_fd,
                    )
                except FileNotFoundError:
                    atomic_publish_no_replace(
                        ledger_fd,
                        ledger_file,
                        record,
                        "ledger",
                        "intent-ledger",
                        retain_packet,
                    )
                    record_fd = os.open(
                        ledger_file,
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=ledger_fd,
                    )
                try:
                    existing_st = os.fstat(record_fd)
                    if (
                        not stat.S_ISREG(existing_st.st_mode)
                        or existing_st.st_uid != uid
                        or stat.S_IMODE(existing_st.st_mode) != 0o600
                        or existing_st.st_size <= 0
                        or existing_st.st_size > 262144
                    ):
                        retain_packet("intent-ledger-existing-identity")
                    replace_existing_ledger = existing_st.st_nlink == 2
                    if existing_st.st_nlink not in {1, 2}:
                        retain_packet("intent-ledger-existing-identity")
                    existing = os.read(record_fd, existing_st.st_size + 1)
                    if os.read(record_fd, 1):
                        retain_packet("intent-ledger-existing-content")
                    if existing != record:
                        try:
                            existing_record = parse_committed_ledger_record(existing, proof_label)
                        except SystemExit:
                            replace_existing_ledger = True
                        else:
                            if (
                                existing_record["intent_count"] != str(len(intent_names))
                                or existing_record["packet_sha256"] != hashlib.sha256(packet).hexdigest()
                                or existing_record["intent_payload_manifest_b64"] != intent_payload_manifest_b64
                            ):
                                replace_existing_ledger = True
                    if replace_existing_ledger:
                        os.close(record_fd)
                        record_fd = -1
                        quarantine_owned_regular_file(
                            ledger_fd,
                            ledger_file,
                            "intent-ledger-existing-content",
                            retain_packet,
                            max_size=262144,
                        )
                        atomic_publish_no_replace(
                            ledger_fd,
                            ledger_file,
                            record,
                            "ledger",
                            "intent-ledger",
                            retain_packet,
                        )
                        record_fd = os.open(
                            ledger_file,
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=ledger_fd,
                        )
                        if not file_has_exact_payload(
                            ledger_fd,
                            ledger_file,
                            len(record),
                            hashlib.sha256(record).hexdigest(),
                            allow_link_count={1},
                        ):
                            retain_packet("intent-ledger-existing-content")
                except OSError:
                    retain_packet("intent-ledger-existing-open")
                os.fsync(ledger_fd)
                os.fsync(recovery_fd)
            except OSError:
                retain_packet("intent-ledger-commit")
            finally:
                if record_fd >= 0:
                    os.close(record_fd)
                if ledger_fd >= 0:
                    os.close(ledger_fd)

        def mark_recovery_ledger_complete() -> None:
            ledger_dir = "acgs-clean-sibling-recovery-ledger"
            complete_file = f"{proof_label}.complete"
            ledger_fd = -1
            complete_fd = -1
            complete_record = (
                b"completed_recovery_record=1\n"
                + f"proof_label={proof_label}\n".encode("ascii")
            )
            try:
                ledger_fd = os.open(
                    ledger_dir,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=recovery_fd,
                )
                ledger_st = os.fstat(ledger_fd)
                if (
                    ledger_st.st_uid != uid
                    or stat.S_IMODE(ledger_st.st_mode) != 0o700
                    or ledger_st.st_nlink < 1
                ):
                    retain_packet("intent-ledger-directory-identity")
                atomic_publish_no_replace(
                    ledger_fd,
                    complete_file,
                    complete_record,
                    "complete",
                    "intent-ledger-complete",
                    retain_packet,
                )
                try:
                    complete_fd = os.open(
                        complete_file,
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=ledger_fd,
                    )
                    existing_st = os.fstat(complete_fd)
                    if (
                        not stat.S_ISREG(existing_st.st_mode)
                        or existing_st.st_uid != uid
                        or stat.S_IMODE(existing_st.st_mode) != 0o600
                        or existing_st.st_nlink != 1
                        or existing_st.st_size != len(complete_record)
                    ):
                        retain_packet("intent-ledger-complete-identity")
                    existing = os.read(complete_fd, existing_st.st_size + 1)
                    if existing != complete_record or os.read(complete_fd, 1):
                        retain_packet("intent-ledger-complete-content")
                except OSError:
                    retain_packet("intent-ledger-complete-open")
                os.fsync(ledger_fd)
                os.fsync(recovery_fd)
            except OSError:
                retain_packet("intent-ledger-complete")
            finally:
                if complete_fd >= 0:
                    os.close(complete_fd)
                if ledger_fd >= 0:
                    os.close(ledger_fd)
        commit_recovery_ledger()
        for name in intent_names:
            expected_identity = intent_identity_by_name.get(name)
            if expected_identity is None:
                retain_packet("intent-unlink-unvalidated")
            try:
                before_unlink = os.stat(name, dir_fd=recovery_fd, follow_symlinks=False)
                fd = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                    dir_fd=recovery_fd,
                )
            except OSError:
                retain_packet("intent-unlink-stat")
            try:
                opened_unlink = os.fstat(fd)
                payload = os.read(fd, opened_unlink.st_size + 1)
                if len(payload) != opened_unlink.st_size or os.read(fd, 1):
                    retain_packet("intent-unlink-size")
                digest = hashlib.sha256(payload).hexdigest()
                after_unlink_path = os.stat(name, dir_fd=recovery_fd, follow_symlinks=False)
                exact_identity = (
                    opened_unlink.st_dev,
                    opened_unlink.st_ino,
                    opened_unlink.st_uid,
                    stat.S_IMODE(opened_unlink.st_mode),
                    opened_unlink.st_nlink,
                    opened_unlink.st_size,
                    digest,
                )
                path_identity = (
                    before_unlink.st_dev,
                    before_unlink.st_ino,
                    before_unlink.st_uid,
                    stat.S_IMODE(before_unlink.st_mode),
                    before_unlink.st_nlink,
                    before_unlink.st_size,
                    digest,
                )
                after_path_identity = (
                    after_unlink_path.st_dev,
                    after_unlink_path.st_ino,
                    after_unlink_path.st_uid,
                    stat.S_IMODE(after_unlink_path.st_mode),
                    after_unlink_path.st_nlink,
                    after_unlink_path.st_size,
                    digest,
                )
                if (
                    exact_identity != expected_identity
                    or path_identity != expected_identity
                    or after_path_identity != expected_identity
                ):
                    retain_packet("intent-unlink-identity")
            finally:
                os.close(fd)
            try:
                os.unlink(name, dir_fd=recovery_fd)
            except OSError:
                retain_packet("intent-unlink")
        try:
            os.fsync(recovery_fd)
        except OSError:
            restore_validated_intents()
            retain_packet("intent-post-unlink-fsync")
        try:
            remaining_intents = sorted(
                name for name in list_recovery_names() if name.endswith(".intent")
            )
        except OSError:
            retain_packet("intent-post-unlink-rescan")
        if remaining_intents:
            restore_validated_intents()
            retain_packet("intent-post-unlink-leftover")
        mark_recovery_ledger_complete()
    else:
        final = docker(["ps", "-aq", "--filter", f"label=acgs.postgres.proof={proof_label}"])
        if final.returncode != 0:
            retain_packet("docker-ps-final")
        if any(line for line in final.stdout.splitlines()):
            retain_packet("docker-leftover")
        cleanup_socket_bridge_if_authorized()
    raise SystemExit(0)
finally:
    if recovery_fd >= 0:
        os.close(recovery_fd)
    os.close(root_fd)
    os.close(parent_fd)
PY
}

clean_sibling_cleanup() {
  local status="$1"
  local quota_detach_failed="${2:-0}"
  local quota_cleanup_unsafe="${3:-0}"
  local cleanup_status=0
  local worktree_still_registered=0
  local current_parent_entries=''
  local current_parent_stat=''
  local path_label=''
  local path_value=''
  local worktree_list=''
  local current_admin_identity=''
  local current_registry_identity=''
  local current_registry_entries=''
  local current_worktree_paths=''
  local postgres_recovery_basename=''
  local postgres_recovery_suffix=''
  local quota_recovery_ledger_relpath=''
  local admin_registry_entry=''
  local admin_registry_found_path=''
  local linked_gitfile_found_path=''
  local admin_registry_root=''
  local admin_sentinel_found_path=''
  local dotglob_was_set=0
  local nullglob_was_set=0

  CLEAN_SIBLING_FAILURE_STAGE=''
  clean_sibling_note_failure_stage() {
    local stage="$1"
    if [[ "$cleanup_status" == 0 && -z "${CLEAN_SIBLING_FAILURE_STAGE:-}" ]]; then
      CLEAN_SIBLING_FAILURE_STAGE="$stage"
    fi
  }

  case "$quota_detach_failed" in
    0 | 1) ;;
    *)
      printf 'cleanup refused invalid quota detach flag\n' >&2
      return 2
      ;;
  esac
  case "$quota_cleanup_unsafe" in
    0 | 1) ;;
    *)
      printf 'cleanup refused invalid quota artifact cleanup flag\n' >&2
      return 2
      ;;
  esac

  for path_label in SOURCE_REPO TMP_PARENT TMP_ROOT ACGS_POSTGRES_RECOVERY_ROOT WORKTREE SOURCE_COMMON_GITDIR WORKTREE_ADMIN_GITDIR WORKTREE_GITFILE_PATH WORKTREE_ADMIN_SENTINEL_PATH; do
    path_value="${!path_label-}"
    if [[ -n "$path_value" ]]; then
      clean_sibling_reject_control_path "$path_label" "$path_value" || return 2
    fi
  done
  if [[ "$quota_detach_failed" == 1 ]]; then
    printf 'cleanup refused to remove owned root while quota filesystem remains mounted\n' >&2
    if [[ -n "${TMP_PARENT:-}" && -n "${TMP_PARENT_FD:-}" && -n "${TMP_PARENT_STAT_BEFORE:-}" ]]; then
      current_parent_stat="$(stat -c '%d:%i:%u:%a' -- "$TMP_PARENT" 2>/dev/null || true)"
      if [[ "$current_parent_stat" != "$TMP_PARENT_STAT_BEFORE" ]]; then
        printf 'caller TMPDIR device/inode/owner/mode changed across proof\n' >&2
      fi
    fi
    return 2
  fi
  if [[ "$quota_cleanup_unsafe" == 1 ]]; then
    printf 'cleanup refused to remove owned root after unsafe quota artifact cleanup\n' >&2
    if [[ -n "${TMP_PARENT:-}" && -n "${TMP_PARENT_FD:-}" && -n "${TMP_PARENT_STAT_BEFORE:-}" ]]; then
      current_parent_stat="$(stat -c '%d:%i:%u:%a' -- "$TMP_PARENT" 2>/dev/null || true)"
      if [[ "$current_parent_stat" != "$TMP_PARENT_STAT_BEFORE" ]]; then
        printf 'caller TMPDIR device/inode/owner/mode changed across proof\n' >&2
      fi
    fi
    return 2
  fi
  if [[ "$status" -eq 0 ]]; then
    if [[ -z "${SOURCE_REPO:-}" ]] ||
      [[ "$(realpath -e "${BASH_SOURCE[1]:-}" 2>/dev/null || true)" != \
        "$SOURCE_REPO/scripts/evidence/prove_clean_sibling.sh" ]]; then
      clean_sibling_note_failure_stage cleanup-owned-resources
      cleanup_status=2
    fi
    if [[ "${PROOF_COMPLETE:-0}" != 1 || "${WORKTREE_ADDED:-0}" != 1 ||
      -z "${TMP_PARENT_FD:-}" || -z "${TMP_ROOT:-}" || -z "${TMP_ROOT_INODE:-}" ||
      -z "${OWNER_MARKER:-}" || -z "${WORKTREE:-}" ]]; then
      clean_sibling_note_failure_stage cleanup-owned-resources
      cleanup_status=2
    fi
  fi
  if [[ "$WORKTREE_ADDED" == 1 ]] && [[ -n "$WORKTREE" ]]; then
    clean_sibling_initialize_worktree_gitfile_witness || return 2
  fi
  if [[ "${WORKTREE_GITFILE_RETENTION_REQUIRED:-0}" == 1 ||
    -n "${WORKTREE_GITFILE_FD:-}" || -n "${WORKTREE_GITFILE_CONTENT_B64:-}" ]]; then
    if [[ -n "${WORKTREE_GITFILE_FD:-}" ]]; then
      clean_sibling_record_worktree_gitfile_pre_detach_witness || return 2
      clean_sibling_close_worktree_gitfile_pre_detach_witness || return 2
    elif [[ -n "${WORKTREE_GITFILE_PRE_DETACH_WITNESS:-}" ]]; then
      :
    else
      return 2
    fi
  fi

  if ! clean_sibling_retain_recovery_contracts; then
    clean_sibling_note_failure_stage cleanup-owned-resources
    cleanup_status=2
    worktree_still_registered=1
  fi
  if [[ "$worktree_still_registered" == 1 ]]; then
    :
  else
    if [[ -n "${ACGS_POSTGRES_RECOVERY_ROOT:-}" ]]; then
      case "$ACGS_POSTGRES_RECOVERY_ROOT" in
        "$TMP_PARENT"/*) ;;
        *)
          printf 'cleanup refused for unowned PostgreSQL recovery path: %s\n' \
            "$ACGS_POSTGRES_RECOVERY_ROOT" >&2
          clean_sibling_note_failure_stage cleanup-owned-resources
          cleanup_status=2
          ;;
      esac
      postgres_recovery_basename="${ACGS_POSTGRES_RECOVERY_ROOT##*/}"
      case "$postgres_recovery_basename" in
        acgs-p0-evidence.postgres-recovery.*)
          postgres_recovery_suffix="${postgres_recovery_basename#acgs-p0-evidence.postgres-recovery.}"
          ;;
        acgs-p1-migration.postgres-recovery.*)
          postgres_recovery_suffix="${postgres_recovery_basename#acgs-p1-migration.postgres-recovery.}"
          ;;
        acgs-p1-scope.postgres-recovery.*)
          postgres_recovery_suffix="${postgres_recovery_basename#acgs-p1-scope.postgres-recovery.}"
          ;;
        acgs-p1-ledger.postgres-recovery.*)
          postgres_recovery_suffix="${postgres_recovery_basename#acgs-p1-ledger.postgres-recovery.}"
          ;;
        acgs-p1-trust.postgres-recovery.*)
          postgres_recovery_suffix="${postgres_recovery_basename#acgs-p1-trust.postgres-recovery.}"
          ;;
        acgs-p2-tenant-bootstrap.postgres-recovery.*)
          postgres_recovery_suffix="${postgres_recovery_basename#acgs-p2-tenant-bootstrap.postgres-recovery.}"
          ;;
        acgs-p2-register.postgres-recovery.*)
          postgres_recovery_suffix="${postgres_recovery_basename#acgs-p2-register.postgres-recovery.}"
          ;;
        acgs-p2-idempotency.postgres-recovery.*)
          postgres_recovery_suffix="${postgres_recovery_basename#acgs-p2-idempotency.postgres-recovery.}"
          ;;
        acgs-p2-vertical-gate.postgres-recovery.*)
          postgres_recovery_suffix="${postgres_recovery_basename#acgs-p2-vertical-gate.postgres-recovery.}"
          ;;
        acgs-p3-policy.postgres-recovery.*)
          postgres_recovery_suffix="${postgres_recovery_basename#acgs-p3-policy.postgres-recovery.}"
          ;;
        acgs-p3-mutations.postgres-recovery.*)
          postgres_recovery_suffix="${postgres_recovery_basename#acgs-p3-mutations.postgres-recovery.}"
          ;;
        acgs-p3-approval.postgres-recovery.*)
          postgres_recovery_suffix="${postgres_recovery_basename#acgs-p3-approval.postgres-recovery.}"
          ;;
        acgs-p3-approval-003b.postgres-recovery.*)
          postgres_recovery_suffix="${postgres_recovery_basename#acgs-p3-approval-003b.postgres-recovery.}"
          ;;
        acgs-p3-approval-003c.postgres-recovery.*)
          postgres_recovery_suffix="${postgres_recovery_basename#acgs-p3-approval-003c.postgres-recovery.}"
          ;;
        acgs-p4-enrollment.postgres-recovery.*)
          postgres_recovery_suffix="${postgres_recovery_basename#acgs-p4-enrollment.postgres-recovery.}"
          ;;
        *)
          postgres_recovery_suffix=''
          ;;
      esac
      if [[ -n "$postgres_recovery_suffix" &&
        "$postgres_recovery_suffix" =~ ^[A-Za-z0-9]{8}$ ]]; then
          if [[ -n "${ACGS_POSTGRES_RECOVERY_ROOT_INODE:-}" ]]; then
            clean_sibling_remove_owned_root "$TMP_PARENT_FD" "$ACGS_POSTGRES_RECOVERY_ROOT" \
              "$ACGS_POSTGRES_RECOVERY_ROOT_DEVICE:$ACGS_POSTGRES_RECOVERY_ROOT_INODE:$ACGS_POSTGRES_RECOVERY_ROOT_UID:700" \
              "$$" "${ACGS_POSTGRES_RECOVERY_ROOT_MNT_ID:-}" || {
              clean_sibling_note_failure_stage cleanup-owned-resources
              cleanup_status=2
            }
          else
            clean_sibling_note_failure_stage cleanup-owned-resources
            cleanup_status=2
          fi
      else
        if [[ "$cleanup_status" == 0 ]]; then
          printf 'cleanup refused for unowned PostgreSQL recovery path: %s\n' \
            "$ACGS_POSTGRES_RECOVERY_ROOT" >&2
        fi
        clean_sibling_note_failure_stage cleanup-owned-resources
        cleanup_status=2
      fi
    fi
  fi
  if [[ -n "${ACGS_POSTGRES_RECOVERY_ROOT:-}" ]]; then
    [[ ! -e "$ACGS_POSTGRES_RECOVERY_ROOT" && ! -L "$ACGS_POSTGRES_RECOVERY_ROOT" ]] || {
      clean_sibling_note_failure_stage cleanup-owned-root-reappeared
      cleanup_status=2
    }
  fi
  if [[ "$worktree_still_registered" == 1 ]]; then
    :
  elif [[ -n "$TMP_ROOT" ]] && [[ -n "${TMP_ROOT_INODE:-}" ]]; then
    case "$TMP_ROOT" in
      "$TMP_PARENT"/acgs-p0-evidence.* | "$TMP_PARENT"/acgs-p1-migration.* | \
        "$TMP_PARENT"/acgs-p1-scope.* | "$TMP_PARENT"/acgs-p1-ledger.* | \
        "$TMP_PARENT"/acgs-p1-trust.* | \
        "$TMP_PARENT"/acgs-p2-tenant-bootstrap.* | "$TMP_PARENT"/acgs-p2-register.* | \
        "$TMP_PARENT"/acgs-p2-idempotency.* | "$TMP_PARENT"/acgs-p2-vertical-gate.* | \
        "$TMP_PARENT"/acgs-p3-policy.* | "$TMP_PARENT"/acgs-p3-mutations.* | \
        "$TMP_PARENT"/acgs-p3-approval.* | \
        "$TMP_PARENT"/acgs-p3-approval-003b.* | \
        "$TMP_PARENT"/acgs-p3-approval-003c.* | \
        "$TMP_PARENT"/acgs-p4-enrollment.*)
        if [[ -n "${ACGS_QUOTA_RECOVERY_BUNDLE_NAME:-}" ]]; then
          quota_recovery_ledger_relpath="trusted-ledger/quota-artifact-recovery-${ACGS_QUOTA_RECOVERY_BUNDLE_NAME#.acgs-quota-artifact-recovery-}"
        fi
        clean_sibling_remove_owned_root "$TMP_PARENT_FD" "$TMP_ROOT" \
          "$TMP_ROOT_DEVICE:$TMP_ROOT_INODE:$TMP_ROOT_UID:700" "$$" \
          "${TMP_ROOT_MNT_ID:-}" \
          "${ACGS_QUOTA_RECOVERY_BUNDLE_FD:-}" \
          "${ACGS_QUOTA_RECOVERY_BUNDLE_IDENTITY:-}" \
          "${ACGS_QUOTA_RECOVERY_BUNDLE_SHA256:-}" \
          "$quota_recovery_ledger_relpath" || {
          clean_sibling_note_failure_stage cleanup-owned-resources
          cleanup_status=2
        }
        ;;
      *)
        printf 'cleanup refused for unowned path: %s\n' "$TMP_ROOT" >&2
        clean_sibling_note_failure_stage cleanup-owned-resources
        cleanup_status=2
        ;;
    esac
  elif [[ -n "$TMP_ROOT" ]] && [[ -d "$TMP_ROOT" ]] && [[ ! -L "$TMP_ROOT" ]] &&
    [[ -z "$(find "$TMP_ROOT" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
    # The EXIT trap is installed before the marker is written.  In that tiny
    # interval only the freshly-created empty directory may be removed.
    rmdir -- "$TMP_ROOT" || {
      clean_sibling_note_failure_stage cleanup-owned-resources
      cleanup_status=2
    }
  elif [[ -n "$TMP_ROOT" ]]; then
    printf 'cleanup refused because ownership marker changed: %s\n' "$TMP_ROOT" >&2
    clean_sibling_note_failure_stage cleanup-owned-resources
    cleanup_status=2
  fi
  if [[ -n "$TMP_ROOT" ]]; then
    [[ ! -e "$TMP_ROOT" && ! -L "$TMP_ROOT" ]] || {
      clean_sibling_note_failure_stage cleanup-owned-root-reappeared
      cleanup_status=2
    }
  fi
  if [[ "$cleanup_status" == 0 ]] && [[ "$WORKTREE_ADDED" == 1 ]] && [[ -n "$WORKTREE" ]]; then
    clean_sibling_record_worktree_absence_proof || {
      clean_sibling_note_failure_stage cleanup-owned-root-reappeared
      cleanup_status=2
    }
  fi
  if [[ "$WORKTREE_ADDED" == 1 ]] && [[ -n "$WORKTREE" ]]; then
    if [[ "$cleanup_status" == 0 ]]; then
      if ! clean_sibling_remove_registered_worktree; then
        clean_sibling_note_failure_stage cleanup-owned-git-deregister
        cleanup_status=2
      fi
    fi
    if [[ "${WORKTREE_POST_REMOVE_GITFILE_VALIDATED:-0}" != 1 ]]; then
      clean_sibling_note_failure_stage cleanup-owned-registration
      cleanup_status=2
    fi
    worktree_still_registered=0
    if worktree_list="$(git -C "$SOURCE_REPO" worktree list --porcelain)" &&
      clean_sibling_worktree_list_contains "$worktree_list" "$WORKTREE"; then
      worktree_still_registered=1
      clean_sibling_note_failure_stage cleanup-owned-registration
      cleanup_status=2
    fi
  fi
  current_parent_stat="$(stat -c '%d:%i:%u:%a' -- "$TMP_PARENT" 2>/dev/null || true)"
  if [[ -z "${TMP_PARENT_STAT_BEFORE:-}" ]] ||
    [[ "$current_parent_stat" != "$TMP_PARENT_STAT_BEFORE" ]]; then
    printf 'caller TMPDIR device/inode/owner/mode changed across proof\n' >&2
    clean_sibling_note_failure_stage cleanup-owned-parent-snapshot
    cleanup_status=2
  fi
  if ! current_parent_entries="$(clean_sibling_snapshot_direct_entries \
    "$TMP_PARENT_FD" "$TMP_PARENT_STAT_BEFORE" "$TMP_PARENT" \
    "${ACGS_QUOTA_RECOVERY_BUNDLE_NAME:-}" \
    "${ACGS_QUOTA_RECOVERY_BUNDLE_IDENTITY:-}" \
      "${ACGS_QUOTA_RECOVERY_BUNDLE_SHA256:-}")"; then
    printf 'caller TMPDIR direct entries snapshot refused across proof\n' >&2
    clean_sibling_note_failure_stage cleanup-owned-parent-snapshot
    cleanup_status=2
  elif [[ -z "${TMP_PARENT_ENTRIES_BEFORE:-}" ]] ||
    [[ "$current_parent_entries" != "$TMP_PARENT_ENTRIES_BEFORE" ]]; then
    printf 'caller TMPDIR direct entries changed across proof\n' >&2
    clean_sibling_note_failure_stage cleanup-owned-parent-snapshot
    cleanup_status=2
  fi
  if [[ "$WORKTREE_ADDED" == 1 ]] && [[ -n "$WORKTREE" ]]; then
    if ! worktree_list="$(git -C "$SOURCE_REPO" worktree list --porcelain)"; then
      printf 'cleanup refused because worktree registry query failed: %s\n' "$WORKTREE" >&2
      clean_sibling_note_failure_stage cleanup-owned-registration
      cleanup_status=2
    elif clean_sibling_worktree_list_contains "$worktree_list" "$WORKTREE"; then
      printf 'cleanup refused to delete still-registered worktree root: %s\n' "$WORKTREE" >&2
      clean_sibling_note_failure_stage cleanup-owned-registration
      cleanup_status=2
    fi
    [[ ! -e "$WORKTREE" && ! -L "$WORKTREE" ]] || {
      printf 'owned proof worktree reappeared during cleanup: %s\n' "$WORKTREE" >&2
      clean_sibling_note_failure_stage cleanup-owned-root-reappeared
      cleanup_status=2
    }
  fi
  if [[ "$WORKTREE_ADDED" == 1 ]] && [[ -n "${WORKTREE_ADMIN_GITDIR:-}" ]]; then
    case "$WORKTREE_ADMIN_GITDIR" in
      "$SOURCE_COMMON_GITDIR"/worktrees/*) ;;
      *)
        printf 'cleanup refused because worktree admin gitdir is outside source registry: %s\n' \
          "$WORKTREE_ADMIN_GITDIR" >&2
        clean_sibling_note_failure_stage cleanup-owned-registration
        cleanup_status=2
        ;;
    esac
    if [[ -e "$WORKTREE_ADMIN_GITDIR" || -L "$WORKTREE_ADMIN_GITDIR" ]]; then
      current_admin_identity="$(stat -c '%d:%i:%u' -- "$WORKTREE_ADMIN_GITDIR" 2>/dev/null || true)"
      if [[ -n "${WORKTREE_ADMIN_GITDIR_IDENTITY:-}" ]] &&
        [[ "$current_admin_identity" == "$WORKTREE_ADMIN_GITDIR_IDENTITY" ]]; then
        printf 'cleanup refused because worktree admin registration remains: %s\n' \
          "$WORKTREE_ADMIN_GITDIR" >&2
      else
        printf 'cleanup refused because worktree admin registration identity changed: %s\n' \
          "$WORKTREE_ADMIN_GITDIR" >&2
      fi
      clean_sibling_note_failure_stage cleanup-owned-registration
      cleanup_status=2
    fi
    if [[ -n "${WORKTREE_ADMIN_SENTINEL_PATH:-}" ]] &&
      [[ -e "$WORKTREE_ADMIN_SENTINEL_PATH" || -L "$WORKTREE_ADMIN_SENTINEL_PATH" ]]; then
      if [[ -z "${WORKTREE_ADMIN_SENTINEL_IDENTITY:-}" ]] ||
        [[ "$(stat -c '%d:%i:%u' -- "$WORKTREE_ADMIN_SENTINEL_PATH" 2>/dev/null || true)" != \
          "$WORKTREE_ADMIN_SENTINEL_IDENTITY" ]]; then
        printf 'cleanup refused because worktree admin sentinel identity changed: %s\n' \
          "$WORKTREE_ADMIN_SENTINEL_PATH" >&2
      else
        printf 'cleanup refused because worktree admin sentinel remains: %s\n' \
          "$WORKTREE_ADMIN_SENTINEL_PATH" >&2
      fi
      clean_sibling_note_failure_stage cleanup-owned-registration
      cleanup_status=2
    fi
    admin_registry_root="$SOURCE_COMMON_GITDIR/worktrees"
    if [[ ! -d "$admin_registry_root" || -L "$admin_registry_root" ]]; then
      printf 'cleanup refused because worktree registry enumeration failed: %s\n' \
        "$admin_registry_root" >&2
      clean_sibling_note_failure_stage cleanup-owned-entry-registry
      cleanup_status=2
    elif [[ -n "${WORKTREE_ADMIN_GITDIR_IDENTITY:-}" ]]; then
      if [[ -n "${WORKTREE_REGISTRY_ROOT_IDENTITY:-}" ]]; then
        current_registry_identity="$(stat -c '%d:%i:%u' -- "$admin_registry_root" 2>/dev/null || true)"
        if [[ "$current_registry_identity" != "$WORKTREE_REGISTRY_ROOT_IDENTITY" ]]; then
          printf 'cleanup refused because worktree registry identity changed: %s\n' \
            "$admin_registry_root" >&2
          clean_sibling_note_failure_stage cleanup-owned-entry-registry
          cleanup_status=2
        fi
      fi
      shopt -q dotglob && dotglob_was_set=1 || dotglob_was_set=0
      shopt -q nullglob && nullglob_was_set=1 || nullglob_was_set=0
      shopt -s dotglob nullglob
      for admin_registry_entry in "$admin_registry_root"/*; do
        if ! clean_sibling_reject_control_path \
          WORKTREE_ADMIN_REGISTRY_ENTRY "$admin_registry_entry"; then
          clean_sibling_note_failure_stage cleanup-owned-entry-registry
          cleanup_status=2
          continue
        fi
        if [[ ! -d "$admin_registry_entry" || -L "$admin_registry_entry" ]]; then
          printf 'cleanup refused because worktree registry entry is not a directory: %s\n' \
            "$admin_registry_entry" >&2
          clean_sibling_note_failure_stage cleanup-owned-entry-registry
          cleanup_status=2
          continue
        fi
        current_admin_identity="$(stat -c '%d:%i:%u' -- "$admin_registry_entry" 2>/dev/null || true)"
        if [[ -z "$current_admin_identity" ]]; then
          printf 'cleanup refused because worktree registry enumeration failed: %s\n' \
            "$admin_registry_entry" >&2
          clean_sibling_note_failure_stage cleanup-owned-entry-registry
          cleanup_status=2
          continue
        fi
        if [[ "$current_admin_identity" == "$WORKTREE_ADMIN_GITDIR_IDENTITY" ]]; then
          admin_registry_found_path="$admin_registry_entry"
        fi
      done
      if [[ "$dotglob_was_set" == 0 ]]; then shopt -u dotglob; fi
      if [[ "$nullglob_was_set" == 0 ]]; then shopt -u nullglob; fi
      if [[ -n "$admin_registry_found_path" ]]; then
        if [[ "$admin_registry_found_path" == "$WORKTREE_ADMIN_GITDIR" ]]; then
          printf 'cleanup refused because worktree admin registration remains: %s\n' \
            "$admin_registry_found_path" >&2
        else
          printf 'cleanup refused because worktree admin registration relocated: %s\n' \
            "$admin_registry_found_path" >&2
        fi
        clean_sibling_note_failure_stage cleanup-owned-registration
        cleanup_status=2
      fi
      if [[ -n "${WORKTREE_REGISTRY_ROOT_IDENTITY:-}" ]] &&
        [[ -n "${WORKTREE_ADMIN_SENTINEL:-}" ]]; then
        if ! admin_sentinel_found_path="$(clean_sibling_find_admin_sentinel \
          "$admin_registry_root" "$WORKTREE_REGISTRY_ROOT_IDENTITY" \
          "$WORKTREE_ADMIN_SENTINEL")"; then
          clean_sibling_note_failure_stage cleanup-owned-entry-registry
          cleanup_status=2
          admin_sentinel_found_path=''
        fi
        if [[ -n "$admin_sentinel_found_path" ]]; then
          if [[ "$admin_sentinel_found_path" == "$WORKTREE_ADMIN_GITDIR" ]]; then
            printf 'cleanup refused because worktree admin registration remains: %s\n' \
              "$admin_sentinel_found_path" >&2
          else
            printf 'cleanup refused because worktree admin registration relocated: %s\n' \
              "$admin_sentinel_found_path" >&2
          fi
          clean_sibling_note_failure_stage cleanup-owned-registration
          cleanup_status=2
        fi
      fi
      if [[ -n "${WORKTREE_REGISTRY_ROOT_IDENTITY:-}" ]] &&
        [[ -n "${WORKTREE_GITFILE_IDENTITY:-}" ]]; then
        if ! linked_gitfile_found_path="$(clean_sibling_find_linked_gitfile_registration \
          "$admin_registry_root" "$WORKTREE_REGISTRY_ROOT_IDENTITY" \
          "$WORKTREE_GITFILE_IDENTITY")"; then
          clean_sibling_note_failure_stage cleanup-owned-entry-registry
          cleanup_status=2
          linked_gitfile_found_path=''
        fi
        if [[ -n "$linked_gitfile_found_path" ]]; then
          printf 'cleanup refused because linked worktree registration remains: %s\n' \
            "$linked_gitfile_found_path" >&2
          clean_sibling_note_failure_stage cleanup-owned-registration
          cleanup_status=2
        fi
      fi
    fi
  fi
  [[ "$(git -C "$SOURCE_REPO" status --porcelain=v1 --untracked-files=all)" == \
    "$SOURCE_STATUS_BEFORE" ]] || {
    printf 'source repository status changed across proof\n' >&2
    clean_sibling_note_failure_stage cleanup-owned-source-status
    cleanup_status=2
  }
  if [[ -n "$TMP_ROOT" ]]; then
    [[ ! -e "$TMP_ROOT" && ! -L "$TMP_ROOT" ]] || {
      printf 'owned proof root reappeared during cleanup: %s\n' "$TMP_ROOT" >&2
      clean_sibling_note_failure_stage cleanup-owned-root-reappeared
      cleanup_status=2
    }
  fi
  if [[ "$WORKTREE_ADDED" == 1 ]]; then
    if ! worktree_list="$(git -C "$SOURCE_REPO" worktree list --porcelain)"; then
      printf 'cleanup refused because final worktree registry query failed\n' >&2
      clean_sibling_note_failure_stage cleanup-owned-path-registry
      cleanup_status=2
    else
      current_worktree_paths="$(clean_sibling_worktree_paths_digest "$worktree_list")"
      if [[ -z "${WORKTREE_PATHS_BEFORE:-}" ]]; then
        WORKTREE_PATHS_BEFORE="$(clean_sibling_worktree_paths_digest "${WORKTREES_BEFORE:-}")"
      fi
      if [[ -z "${WORKTREE_PATHS_BEFORE:-}" ]] ||
        [[ "$current_worktree_paths" != "$WORKTREE_PATHS_BEFORE" ]]; then
        printf 'cleanup refused because worktree path registry changed across proof\n' >&2
        clean_sibling_note_failure_stage cleanup-owned-path-registry
        cleanup_status=2
      fi
    fi
    if [[ -z "${WORKTREE_REGISTRY_ENTRIES_BEFORE:-}" ]]; then
      printf 'cleanup refused because baseline worktree registry snapshot is missing\n' >&2
      clean_sibling_note_failure_stage cleanup-owned-entry-registry
      cleanup_status=2
    elif [[ -n "${WORKTREE_REGISTRY_ROOT:-}" ]]; then
      if ! current_registry_entries="$(clean_sibling_snapshot_worktree_registry \
        "$WORKTREE_REGISTRY_ROOT" "${WORKTREE_REGISTRY_ROOT_IDENTITY:-}")"; then
        clean_sibling_note_failure_stage cleanup-owned-entry-registry
        cleanup_status=2
        current_registry_entries=''
      elif [[ "$current_registry_entries" != "$WORKTREE_REGISTRY_ENTRIES_BEFORE" ]]; then
        printf 'cleanup refused because worktree registry entries changed across proof\n' >&2
        clean_sibling_note_failure_stage cleanup-owned-entry-registry
        cleanup_status=2
      fi
    else
      printf 'cleanup refused because worktree registry root is missing\n' >&2
      clean_sibling_note_failure_stage cleanup-owned-entry-registry
      cleanup_status=2
    fi
  fi
  [[ "$cleanup_status" -eq 0 ]] || status=2
  return "$status"
}
