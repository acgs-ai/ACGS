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
import hashlib
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
  local snapshot_python="${SNAPSHOT_PYTHON:-/usr/bin/python3}"
  local fd_target=''

  [[ "$gitfile_fd" =~ ^[0-9]+$ ]] || return 2
  [[ "$gitfile_path" == /* ]] || return 2
  fd_target="$(/usr/bin/readlink "/proc/$$/fd/$gitfile_fd" 2>/dev/null || true)"
  [[ "$fd_target" == "$gitfile_path" ]] || {
    printf 'cleanup refused because retained worktree gitfile moved/replaced: %s\n' \
      "$gitfile_path" >&2
    return 2
  }
  "$snapshot_python" - "$gitfile_fd" "$gitfile_path" <<'PY'
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
try:
    fd_stat = os.fstat(fd)
    path_stat = os.stat(path, follow_symlinks=False)
    if stat.S_ISLNK(path_stat.st_mode):
        fail("cleanup refused because worktree gitfile path is a symlink")
    if (fd_stat.st_dev, fd_stat.st_ino, fd_stat.st_uid) != (
            path_stat.st_dev, path_stat.st_ino, path_stat.st_uid):
        fail("cleanup refused because retained worktree gitfile path changed")
    if not stat.S_ISREG(fd_stat.st_mode):
        fail("cleanup refused because retained worktree gitfile is not a regular file")
    if fd_stat.st_uid != os.getuid():
        fail("cleanup refused because retained worktree gitfile owner changed")
    if fd_stat.st_mode != path_stat.st_mode:
        fail("cleanup refused because retained worktree gitfile mode changed")
    if fd_stat.st_nlink != path_stat.st_nlink:
        fail("cleanup refused because retained worktree gitfile link count changed")
    if fd_stat.st_nlink != 1:
        fail("cleanup refused because retained worktree gitfile link count changed")
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
  current="$(clean_sibling_capture_retained_gitfile "$gitfile_fd" "$gitfile_path")" ||
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

clean_sibling_snapshot_direct_entries() {
  local root_fd="$1"
  local expected_identity="$2"
  local directory="$3"
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
    "$root_fd" "$expected_identity" "$directory" <<'PY'
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


def field(tag: bytes, payload: bytes) -> bytes:
    return tag + struct.pack(">Q", len(payload)) + payload


def encode_meta(value: os.stat_result) -> bytes:
    return b"".join(struct.pack(">Q", part) for part in metadata(value))


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
root_fd = -1
try:
    root_fd = os.dup(fd_number)
    root_before = os.fstat(root_fd)
    path_before = os.stat(path, follow_symlinks=False)
    if root_identity(root_before) != expected or root_identity(path_before) != expected:
        fail("caller directory path no longer refers to authenticated descriptor")
    names = sorted((entry.name for entry in os.scandir(root_fd)), key=os.fsencode)
    snapshot = b"".join(snapshot_entry(root_fd, name) for name in names)
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
  local parent_fd="$1" root="$2" expected="$3" marker_pid="$4"
  PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX='' /usr/bin/python3 - \
    "$parent_fd" "$root" "$expected" "$marker_pid" <<'PY'
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
name = os.path.basename(root)
if os.path.dirname(root) != os.readlink(f"/proc/self/fd/{parent_fd}"):
    fail("root is outside authenticated parent")
fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=parent_fd)
st = os.fstat(fd)
identity = (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))
if identity != expected:
    fail("root identity changed")
marker_fd = os.open(".acgs-clean-sibling-owned", os.O_RDONLY | os.O_NOFOLLOW,
                    dir_fd=fd)
try:
    marker_st = os.fstat(marker_fd)
    if (not stat.S_ISREG(marker_st.st_mode) or marker_st.st_nlink != 1 or
            marker_st.st_uid != st.st_uid or os.read(marker_fd, 128) != marker_pid):
        fail("ownership marker changed")
finally:
    os.close(marker_fd)
tomb = f".acgs-cleanup-{secrets.token_hex(16)}"
os.rename(name, tomb, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
try:
    moved = os.stat(tomb, dir_fd=parent_fd, follow_symlinks=False)
    moved_identity = (moved.st_dev, moved.st_ino, moved.st_uid,
                      stat.S_IMODE(moved.st_mode))
    if moved_identity != expected or os.fstat(fd).st_ino != moved.st_ino:
        # The atomic rename captured a substituted path. Put it back without
        # deleting any of its bytes; never fall through to recursive removal.
        try:
            os.rename(tomb, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        except OSError:
            pass
        fail("root substituted at teardown boundary")

    def empty(directory_fd: int) -> None:
        for child in list(os.listdir(directory_fd)):
            child_st = os.stat(child, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(child_st.st_mode):
                child_fd = os.open(child, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY,
                                   dir_fd=directory_fd)
                try:
                    empty(child_fd)
                finally:
                    os.close(child_fd)
                os.rmdir(child, dir_fd=directory_fd)
            else:
                os.unlink(child, dir_fd=directory_fd)

    empty(fd)
    if os.fstat(fd).st_ino != moved.st_ino:
        fail("root descriptor changed during teardown")
finally:
    os.close(fd)
os.rmdir(tomb, dir_fd=parent_fd)
PY
}

clean_sibling_cleanup() {
  local status="$1"
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
  local admin_registry_entry=''
  local admin_registry_found_path=''
  local linked_gitfile_found_path=''
  local admin_registry_root=''
  local admin_sentinel_found_path=''
  local dotglob_was_set=0
  local nullglob_was_set=0

  for path_label in SOURCE_REPO TMP_PARENT TMP_ROOT WORKTREE SOURCE_COMMON_GITDIR WORKTREE_ADMIN_GITDIR WORKTREE_GITFILE_PATH WORKTREE_ADMIN_SENTINEL_PATH; do
    path_value="${!path_label-}"
    if [[ -n "$path_value" ]]; then
      clean_sibling_reject_control_path "$path_label" "$path_value" || return 2
    fi
  done
  if [[ "${WORKTREE_GITFILE_RETENTION_REQUIRED:-0}" == 1 ||
    -n "${WORKTREE_GITFILE_FD:-}" || -n "${WORKTREE_GITFILE_CONTENT_B64:-}" ]]; then
    clean_sibling_validate_retained_gitfile \
      "${WORKTREE_GITFILE_FD:-}" \
      "$WORKTREE_GITFILE_PATH" \
      "$WORKTREE_GITFILE_IDENTITY" \
      "${WORKTREE_GITFILE_MODE:-}" \
      "${WORKTREE_GITFILE_LINKS:-}" \
      "${WORKTREE_GITFILE_SIZE:-}" \
      "${WORKTREE_GITFILE_SHA256:-}" \
      "${WORKTREE_GITFILE_CONTENT_B64:-}" || return 2
  fi

  if [[ -n "$WORKTREE" ]]; then
    rm -rf --one-file-system -- \
      "$WORKTREE/.pytest_cache" "$WORKTREE/.ruff_cache" "$WORKTREE/tests/__pycache__"
  fi
  if [[ "$WORKTREE_ADDED" == 1 ]] && [[ -n "$WORKTREE" ]]; then
    worktree_still_registered=1
    if ! worktree_list="$(git -C "$SOURCE_REPO" worktree list --porcelain)"; then
      printf 'cleanup refused because worktree registry query failed: %s\n' "$WORKTREE" >&2
      cleanup_status=2
    elif clean_sibling_worktree_list_contains "$worktree_list" "$WORKTREE"; then
      if ! git -C "$SOURCE_REPO" worktree remove --force "$WORKTREE" >/dev/null 2>&1; then
        printf 'cleanup retry after worktree removal failure: %s\n' "$WORKTREE" >&2
        cleanup_status=2
        git -C "$SOURCE_REPO" worktree remove --force "$WORKTREE" >/dev/null 2>&1 || true
      fi
      if ! worktree_list="$(git -C "$SOURCE_REPO" worktree list --porcelain)"; then
        printf 'cleanup refused because worktree registry query failed: %s\n' "$WORKTREE" >&2
        cleanup_status=2
      elif ! clean_sibling_worktree_list_contains "$worktree_list" "$WORKTREE"; then
        worktree_still_registered=0
      fi
    else
      worktree_still_registered=0
    fi
    if [[ "$worktree_still_registered" == 1 ]]; then
      printf 'cleanup refused to delete still-registered worktree root: %s\n' "$WORKTREE" >&2
      cleanup_status=2
    fi
  fi
  if [[ "$worktree_still_registered" == 1 ]]; then
    :
  elif [[ -n "$TMP_ROOT" ]] && [[ -n "${TMP_ROOT_INODE:-}" ]]; then
    case "$TMP_ROOT" in
      "$TMP_PARENT"/acgs-p0-evidence.* | "$TMP_PARENT"/acgs-p1-migration.* | \
        "$TMP_PARENT"/acgs-p1-scope.* | "$TMP_PARENT"/acgs-p1-ledger.* | \
        "$TMP_PARENT"/acgs-p1-trust.* | \
        "$TMP_PARENT"/acgs-p2-tenant-bootstrap.* | "$TMP_PARENT"/acgs-p2-register.* | \
        "$TMP_PARENT"/acgs-p2-idempotency.*)
        clean_sibling_remove_owned_root "$TMP_PARENT_FD" "$TMP_ROOT" \
          "$TMP_ROOT_DEVICE:$TMP_ROOT_INODE:$TMP_ROOT_UID:700" "$$" || cleanup_status=2
        ;;
      *)
        printf 'cleanup refused for unowned path: %s\n' "$TMP_ROOT" >&2
        cleanup_status=2
        ;;
    esac
  elif [[ -n "$TMP_ROOT" ]] && [[ -d "$TMP_ROOT" ]] && [[ ! -L "$TMP_ROOT" ]] &&
    [[ -z "$(find "$TMP_ROOT" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
    # The EXIT trap is installed before the marker is written.  In that tiny
    # interval only the freshly-created empty directory may be removed.
    rmdir -- "$TMP_ROOT" || cleanup_status=2
  elif [[ -n "$TMP_ROOT" ]]; then
    printf 'cleanup refused because ownership marker changed: %s\n' "$TMP_ROOT" >&2
    cleanup_status=2
  fi
  if [[ -n "$TMP_ROOT" ]]; then
    [[ ! -e "$TMP_ROOT" && ! -L "$TMP_ROOT" ]] || cleanup_status=2
  fi
  current_parent_stat="$(stat -c '%d:%i:%u:%a' -- "$TMP_PARENT" 2>/dev/null || true)"
  if [[ -z "${TMP_PARENT_STAT_BEFORE:-}" ]] ||
    [[ "$current_parent_stat" != "$TMP_PARENT_STAT_BEFORE" ]]; then
    printf 'caller TMPDIR device/inode/owner/mode changed across proof\n' >&2
    cleanup_status=2
  fi
  current_parent_entries="$(clean_sibling_snapshot_direct_entries \
    "$TMP_PARENT_FD" "$TMP_PARENT_STAT_BEFORE" "$TMP_PARENT" 2>/dev/null || true)"
  if [[ -z "${TMP_PARENT_ENTRIES_BEFORE:-}" ]] ||
    [[ "$current_parent_entries" != "$TMP_PARENT_ENTRIES_BEFORE" ]]; then
    printf 'caller TMPDIR direct entries changed across proof\n' >&2
    cleanup_status=2
  fi
  if [[ "$WORKTREE_ADDED" == 1 ]] && [[ -n "$WORKTREE" ]]; then
    if ! worktree_list="$(git -C "$SOURCE_REPO" worktree list --porcelain)"; then
      printf 'cleanup refused because worktree registry query failed: %s\n' "$WORKTREE" >&2
      cleanup_status=2
    elif clean_sibling_worktree_list_contains "$worktree_list" "$WORKTREE"; then
      printf 'cleanup refused to delete still-registered worktree root: %s\n' "$WORKTREE" >&2
      cleanup_status=2
    fi
    [[ ! -e "$WORKTREE" && ! -L "$WORKTREE" ]] || {
      printf 'owned proof worktree reappeared during cleanup: %s\n' "$WORKTREE" >&2
      cleanup_status=2
    }
  fi
  if [[ "$WORKTREE_ADDED" == 1 ]] && [[ -n "${WORKTREE_ADMIN_GITDIR:-}" ]]; then
    case "$WORKTREE_ADMIN_GITDIR" in
      "$SOURCE_COMMON_GITDIR"/worktrees/*) ;;
      *)
        printf 'cleanup refused because worktree admin gitdir is outside source registry: %s\n' \
          "$WORKTREE_ADMIN_GITDIR" >&2
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
      cleanup_status=2
    fi
    admin_registry_root="$SOURCE_COMMON_GITDIR/worktrees"
    if [[ ! -d "$admin_registry_root" || -L "$admin_registry_root" ]]; then
      printf 'cleanup refused because worktree registry enumeration failed: %s\n' \
        "$admin_registry_root" >&2
      cleanup_status=2
    elif [[ -n "${WORKTREE_ADMIN_GITDIR_IDENTITY:-}" ]]; then
      if [[ -n "${WORKTREE_REGISTRY_ROOT_IDENTITY:-}" ]]; then
        current_registry_identity="$(stat -c '%d:%i:%u' -- "$admin_registry_root" 2>/dev/null || true)"
        if [[ "$current_registry_identity" != "$WORKTREE_REGISTRY_ROOT_IDENTITY" ]]; then
          printf 'cleanup refused because worktree registry identity changed: %s\n' \
            "$admin_registry_root" >&2
          cleanup_status=2
        fi
      fi
      shopt -q dotglob && dotglob_was_set=1 || dotglob_was_set=0
      shopt -q nullglob && nullglob_was_set=1 || nullglob_was_set=0
      shopt -s dotglob nullglob
      for admin_registry_entry in "$admin_registry_root"/*; do
        if ! clean_sibling_reject_control_path \
          WORKTREE_ADMIN_REGISTRY_ENTRY "$admin_registry_entry"; then
          cleanup_status=2
          continue
        fi
        if [[ ! -d "$admin_registry_entry" || -L "$admin_registry_entry" ]]; then
          printf 'cleanup refused because worktree registry entry is not a directory: %s\n' \
            "$admin_registry_entry" >&2
          cleanup_status=2
          continue
        fi
        current_admin_identity="$(stat -c '%d:%i:%u' -- "$admin_registry_entry" 2>/dev/null || true)"
        if [[ -z "$current_admin_identity" ]]; then
          printf 'cleanup refused because worktree registry enumeration failed: %s\n' \
            "$admin_registry_entry" >&2
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
        cleanup_status=2
      fi
      if [[ -n "${WORKTREE_REGISTRY_ROOT_IDENTITY:-}" ]] &&
        [[ -n "${WORKTREE_ADMIN_SENTINEL:-}" ]]; then
        if ! admin_sentinel_found_path="$(clean_sibling_find_admin_sentinel \
          "$admin_registry_root" "$WORKTREE_REGISTRY_ROOT_IDENTITY" \
          "$WORKTREE_ADMIN_SENTINEL")"; then
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
          cleanup_status=2
        fi
      fi
      if [[ -n "${WORKTREE_REGISTRY_ROOT_IDENTITY:-}" ]] &&
        [[ -n "${WORKTREE_GITFILE_IDENTITY:-}" ]]; then
        if ! linked_gitfile_found_path="$(clean_sibling_find_linked_gitfile_registration \
          "$admin_registry_root" "$WORKTREE_REGISTRY_ROOT_IDENTITY" \
          "$WORKTREE_GITFILE_IDENTITY")"; then
          cleanup_status=2
          linked_gitfile_found_path=''
        fi
        if [[ -n "$linked_gitfile_found_path" ]]; then
          printf 'cleanup refused because linked worktree registration remains: %s\n' \
            "$linked_gitfile_found_path" >&2
          cleanup_status=2
        fi
      fi
    fi
  fi
  [[ "$(git -C "$SOURCE_REPO" status --porcelain=v1 --untracked-files=all)" == \
    "$SOURCE_STATUS_BEFORE" ]] || {
    printf 'source repository status changed across proof\n' >&2
    cleanup_status=2
  }
  if [[ -n "$TMP_ROOT" ]]; then
    [[ ! -e "$TMP_ROOT" && ! -L "$TMP_ROOT" ]] || {
      printf 'owned proof root reappeared during cleanup: %s\n' "$TMP_ROOT" >&2
      cleanup_status=2
    }
  fi
  if [[ "$WORKTREE_ADDED" == 1 ]]; then
    if ! worktree_list="$(git -C "$SOURCE_REPO" worktree list --porcelain)"; then
      printf 'cleanup refused because final worktree registry query failed\n' >&2
      cleanup_status=2
    else
      current_worktree_paths="$(clean_sibling_worktree_paths_digest "$worktree_list")"
      if [[ -z "${WORKTREE_PATHS_BEFORE:-}" ]]; then
        WORKTREE_PATHS_BEFORE="$(clean_sibling_worktree_paths_digest "${WORKTREES_BEFORE:-}")"
      fi
      if [[ -z "${WORKTREE_PATHS_BEFORE:-}" ]] ||
        [[ "$current_worktree_paths" != "$WORKTREE_PATHS_BEFORE" ]]; then
        printf 'cleanup refused because worktree path registry changed across proof\n' >&2
        cleanup_status=2
      fi
    fi
    if [[ -z "${WORKTREE_REGISTRY_ENTRIES_BEFORE:-}" ]]; then
      printf 'cleanup refused because baseline worktree registry snapshot is missing\n' >&2
      cleanup_status=2
    elif [[ -n "${WORKTREE_REGISTRY_ROOT:-}" ]]; then
      if ! current_registry_entries="$(clean_sibling_snapshot_worktree_registry \
        "$WORKTREE_REGISTRY_ROOT" "${WORKTREE_REGISTRY_ROOT_IDENTITY:-}")"; then
        cleanup_status=2
        current_registry_entries=''
      elif [[ "$current_registry_entries" != "$WORKTREE_REGISTRY_ENTRIES_BEFORE" ]]; then
        printf 'cleanup refused because worktree registry entries changed across proof\n' >&2
        cleanup_status=2
      fi
    else
      printf 'cleanup refused because worktree registry root is missing\n' >&2
      cleanup_status=2
    fi
  fi
  if [[ -n "${WORKTREE_GITFILE_FD:-}" ]]; then
    exec {WORKTREE_GITFILE_FD}<&- || cleanup_status=2
    WORKTREE_GITFILE_FD=''
  fi
  local launcher_attested=0
  if [[ "${ACGS_STATIC_LAUNCHED:-}" == 1 ]] &&
    [[ "${ACGS_STATIC_PARENT_PID:-}" =~ ^[1-9][0-9]*$ ]] &&
    [[ "${ACGS_CLEAN_SIBLING_STATIC_LAUNCHER:-}" == \
      98d9040015eb17931e17b45e00b5f49f2451326372d5107a3a280f1cb3aaf3fc ]] &&
    [[ "$(/usr/bin/readlink -f "/proc/$ACGS_STATIC_PARENT_PID/exe" 2>/dev/null || true)" == \
      /usr/bin/busybox ]] &&
    [[ "$(/usr/bin/sha256sum "/proc/$ACGS_STATIC_PARENT_PID/exe" 2>/dev/null | \
      /usr/bin/awk '{print $1}')" == \
      98d9040015eb17931e17b45e00b5f49f2451326372d5107a3a280f1cb3aaf3fc ]]; then
    launcher_attested=1
  fi
  if [[ "$status" -eq 0 && "$cleanup_status" -eq 0 && "$PROOF_COMPLETE" -eq 1 ]] &&
    [[ "$launcher_attested" == 1 ]]; then
    case "${NODE_ID:-P0-EVIDENCE-000}:${TRANSCRIPT_RECORDS:-}:${ASSIGNED_BOOTSTRAPS:-}" in
      P0-EVIDENCE-000:10:EVID+CP+GZ)
        printf 'CLEAN_SIBLING_TECHNICAL=PASS P=%s T=%s R=%s records=10 assignments=EVID+CP+GZ attestations=pending-independent-lanes\n' \
          "$P" "$T" "$R"
        ;;
      P1-MIGRATION-001:6:EVID+CP)
        printf 'CLEAN_SIBLING_TECHNICAL=PASS P=%s T=%s R=%s records=6 assignments=EVID+CP attestations=pending-independent-lanes\n' \
          "$P" "$T" "$R"
        ;;
      P1-SCOPE-002:6:EVID+CP)
        printf 'CLEAN_SIBLING_TECHNICAL=PASS P=%s T=%s R=%s records=6 assignments=EVID+CP attestations=pending-independent-lanes\n' \
          "$P" "$T" "$R"
        ;;
      P1-LEDGER-003:6:EVID+CP)
        printf 'CLEAN_SIBLING_TECHNICAL=PASS P=%s T=%s R=%s records=6 assignments=EVID+CP attestations=pending-independent-lanes\n' \
          "$P" "$T" "$R"
        ;;
      P1-TRUST-004:11:EVID+CP+GZ)
        printf 'CLEAN_SIBLING_TECHNICAL=PASS P=%s T=%s R=%s records=11 assignments=EVID+CP+GZ attestations=pending-independent-lanes\n' \
          "$P" "$T" "$R"
        ;;
      P2-TENANT-BOOTSTRAP-000:11:EVID+CP+GZ)
        printf 'CLEAN_SIBLING_TECHNICAL=PASS P=%s T=%s R=%s records=11 assignments=EVID+CP+GZ attestations=pending-independent-lanes\n' \
          "$P" "$T" "$R"
        ;;
      P2-REGISTER-001:11:EVID+CP+GZ)
        printf 'CLEAN_SIBLING_TECHNICAL=PASS P=%s T=%s R=%s records=11 assignments=EVID+CP+GZ attestations=pending-independent-lanes\n' \
          "$P" "$T" "$R"
        ;;
      P2-IDEMPOTENCY-002:6:EVID+CP)
        printf 'CLEAN_SIBLING_TECHNICAL=PASS P=%s T=%s R=%s records=6 assignments=EVID+CP attestations=pending-independent-lanes\n' \
          "$P" "$T" "$R"
        ;;
      P2-VERTICAL-GATE-003:12:EVID+CP+GZ)
        printf 'CLEAN_SIBLING_TECHNICAL=PASS P=%s T=%s R=%s records=12 assignments=EVID+CP+GZ attestations=pending-independent-lanes\n' \
          "$P" "$T" "$R"
        ;;
      *)
        cleanup_status=2
        ;;
    esac
  elif [[ "$status" -eq 0 ]]; then
    status=2
  fi
  [[ "$cleanup_status" -eq 0 ]] || status=2
  return "$status"
}
