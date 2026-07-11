#!/usr/bin/env bash
# Cleanup primitive shared by the clean-sibling prover and its failure tests.

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
  PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX= "$snapshot_python" - \
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

clean_sibling_cleanup() {
  local status="$1"
  local cleanup_status=0
  local current_parent_entries=''
  local current_parent_stat=''

  if [[ -n "$WORKTREE" ]]; then
    rm -rf --one-file-system -- \
      "$WORKTREE/.pytest_cache" "$WORKTREE/.ruff_cache" "$WORKTREE/tests/__pycache__"
  fi
  if [[ "$WORKTREE_ADDED" == 1 ]] && [[ -n "$WORKTREE" ]] &&
    git -C "$SOURCE_REPO" worktree list --porcelain | grep -Fqx "worktree $WORKTREE"; then
    if ! git -C "$SOURCE_REPO" worktree remove --force "$WORKTREE" >/dev/null 2>&1; then
      printf 'cleanup retry after worktree removal failure: %s\n' "$WORKTREE" >&2
      cleanup_status=2
      git -C "$SOURCE_REPO" worktree remove --force "$WORKTREE" >/dev/null 2>&1 || true
    fi
  fi
  if [[ -n "$TMP_ROOT" ]] && [[ -f "$OWNER_MARKER" ]] && [[ ! -L "$OWNER_MARKER" ]] &&
    [[ "$(stat -c '%h:%u' -- "$OWNER_MARKER" 2>/dev/null || true)" == "1:$TMP_ROOT_UID" ]] &&
    [[ "$(cat "$OWNER_MARKER" 2>/dev/null || true)" == "$$" ]] &&
    [[ "$(stat -c '%d:%i:%u:%a' -- "$TMP_ROOT" 2>/dev/null || true)" == \
      "$TMP_ROOT_DEVICE:$TMP_ROOT_INODE:$TMP_ROOT_UID:700" ]]; then
    case "$TMP_ROOT" in
      "$TMP_PARENT"/acgs-p0-evidence.*)
        rm -rf --one-file-system -- "$TMP_ROOT" || cleanup_status=2
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
  [[ "$(git -C "$SOURCE_REPO" worktree list --porcelain)" == "$WORKTREES_BEFORE" ]] || {
    printf 'worktree registrations changed across proof\n' >&2
    cleanup_status=2
  }
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
  if [[ "$status" -eq 0 && "$cleanup_status" -eq 0 && "$PROOF_COMPLETE" -eq 1 ]] &&
    [[ "$TRANSCRIPT_RECORDS" == 10 ]]; then
    printf 'CLEAN_SIBLING_TECHNICAL=PASS P=%s T=%s R=%s records=10 assignments=EVID+CP+GZ attestations=pending-independent-lanes\n' \
      "$P" "$T" "$R"
  elif [[ "$status" -eq 0 ]]; then
    status=2
  fi
  [[ "$cleanup_status" -eq 0 ]] || status=2
  return "$status"
}
