#!/bin/bash

# Verifier entrypoint. Runs in the verifier container, not the agent's, and sees only the paths
# declared in `artifacts`. Everything it needs is baked into tests/Dockerfile; nothing is
# fetched here. The archive the graded runs talk to is started by this script from the copy in
# this image, against sets the agent has never had access to.

set -uo pipefail
# The image's working directory is inside the tree every build below deletes and recreates,
# which would leave this shell without a valid cwd.
cd /
mkdir -p /logs/verifier
echo 0 > /logs/verifier/reward.txt
exec 2>&1

# Root runs this script and later runs pytest, after agent-authored code has run as the build
# user. Anything root starts by name is looked up on PATH, so every directory on PATH has to be
# one the build user cannot write to. PATH is pinned rather than inherited and each entry is
# checked before anything untrusted runs; if one fails the run is abandoned with reward 0.
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
hash -r
for d in ${PATH//:/ }; do
  real="$(/usr/bin/readlink -f "$d" 2>/dev/null)" || continue
  [ -d "$real" ] || continue
  owner="$(/usr/bin/stat -c %u "$real")"
  mode="$(/usr/bin/stat -c %a "$real")"
  if [ "$owner" != "0" ] || [ $(( 8#$mode & 8#022 )) -ne 0 ]; then
    echo "FATAL: $d (-> $real) is on root's PATH but is owner $owner mode $mode; a file planted there would be run as root."
    echo 0 > /logs/verifier/reward.txt
    exit 0
  fi
done
echo "every directory on root's PATH is root-owned and closed to writing by anyone else"

ZIG=/usr/local/lib/python3.13/site-packages/ziglang/zig
if [ ! -x "$ZIG" ]; then
  echo "FATAL: no Zig compiler at $ZIG"
  echo 0 > /logs/verifier/reward.txt
  exit 0
fi

/usr/bin/install -d -m 700 -o root -g root /opt/run
chown -R runner:runner /app/flowkit 2>/dev/null || true

as_runner() {
  setpriv --clear-groups --no-new-privs --reuid runner --regid runner "$@"
}

# One graded run is told where its archive is by name and not by address. SPEC.md says
# ARCHIVE_HOST is the host name or address of the archive, so a tool that insists on a dotted
# quad is reading more into that variable than it is given. The name is put into this
# container's hosts file before anything untrusted runs.
ARCHIVE_BY_NAME=archive.flows.internal
printf '%s\t%s\n' 127.0.0.4 "$ARCHIVE_BY_NAME" >> /etc/hosts
if ! /usr/bin/getent hosts "$ARCHIVE_BY_NAME" >/dev/null 2>&1; then
  echo "FATAL: $ARCHIVE_BY_NAME does not resolve in this container, so the named run cannot be graded."
  echo 0 > /logs/verifier/reward.txt
  exit 0
fi
echo "one graded run is reached by name: $ARCHIVE_BY_NAME -> 127.0.0.4"

# Close the verifier's own code, the sets, the service and the reward directory to the build
# user before anything untrusted runs. `ls` needs read permission on the directory itself,
# which is the right probe; `test -d` only needs search permission on the parent.
chmod 700 /tests /logs/verifier /opt/truth /opt/archive /opt/run 2>/dev/null || true
if as_runner bash -c 'test -r /tests/test_outputs.py || ls /opt/truth || ls /opt/archive' >/dev/null 2>&1; then
  echo "FATAL: /tests, the sets or the service are still reachable by the unprivileged build user."
  echo 0 > /logs/verifier/reward.txt
  exit 0
fi
echo "verifier files closed to the unprivileged build user"

# A root-owned pristine copy of the collected sources. Every build starts from this, so nothing
# a run leaves behind can change what the next one compiles.
rm -rf /opt/src_pristine
cp -a /app/flowkit /opt/src_pristine
chown -R root:root /opt/src_pristine
chmod -R go-w /opt/src_pristine

# Every mount point that is a real filesystem: proc, sysfs, cgroup, devpts and mqueue hold
# nothing a program can be started from.
scratch_roots() {
  local dev mnt fstype rest
  while read -r dev mnt fstype rest; do
    case "$fstype" in
      proc|sysfs|cgroup|cgroup2|devpts|mqueue|securityfs|debugfs|tracefs|binfmt_misc|configfs|fusectl|pstore|bpf|hugetlbfs|autofs|nsfs|rpc_pipefs) continue ;;
    esac
    case "$mnt" in /proc|/proc/*|/sys|/sys/*) continue ;; esac
    printf '%s\n' "$mnt"
  done < /proc/mounts
}

# While the tool runs, nothing else on the box may be executed by the build user: every
# regular file with a group or other execute bit, on every real mount, loses those bits. The
# tool is a static binary the build user owns, so it keeps its own execute bit and needs no
# loader. The modes are saved and put back afterwards, and by the EXIT trap if this script
# dies in between, so log collection never finds a box with no usable shell.
EXEC_SAVED=""
close_exec() {
  local roots left
  roots="$(scratch_roots)"
  EXEC_SAVED="$(echo "$roots" | /usr/bin/xargs -d '\n' -I{} /usr/bin/find {} -xdev -type f -perm /011 \
                   -printf '%m %p\n' 2>/dev/null)"
  echo "$EXEC_SAVED" | /usr/bin/cut -d' ' -f2- | /usr/bin/xargs -d '\n' -r /usr/bin/chmod go-x 2>/dev/null || true
  left="$(echo "$roots" | /usr/bin/xargs -d '\n' -I{} /usr/bin/find {} -xdev -type f -perm /011 2>/dev/null)"
  echo "programs closed to the build user while the tool runs: $(echo "$EXEC_SAVED" | /usr/bin/grep -c .) files lost their group and other execute bits;" \
       "still executable by it: $(echo "$left" | /usr/bin/grep -c .)" $(echo "$left" | /usr/bin/tr '\n' ' ')
}
open_exec() {
  local m
  [ -n "${EXEC_SAVED:-}" ] || return 0
  for m in $(echo "$EXEC_SAVED" | /usr/bin/cut -d' ' -f1 | /usr/bin/sort -u); do
    echo "$EXEC_SAVED" | /usr/bin/awk -v m="$m" '$1 == m { print substr($0, length(m) + 2) }' \
      | /usr/bin/xargs -d '\n' -r /usr/bin/chmod "$m" 2>/dev/null || true
  done
  EXEC_SAVED=""
}

# The interpreters on the box by real path, closed while the Zig compiles: the build has no
# business running python or perl.
INTERP="$(for t in python3 python3.13 pip perl awk mawk; do
            p="$(command -v "$t" 2>/dev/null)" && readlink -f "$p"; done | sort -u)"
close_interp() { for f in $INTERP; do /usr/bin/chmod 750 "$f" 2>/dev/null || true; done; }
open_interp()  { for f in $INTERP; do /usr/bin/chmod 755 "$f" 2>/dev/null || true; done; }
trap 'open_exec; open_interp' EXIT

echo ok > /opt/run/build_check.txt

# Compile the collected sources. The build starts from the root-owned copy, the sources are
# stamped, and the output directory and the compiler's caches are emptied, so the binary that
# runs is always a fresh build of what the agent left in src. What is compiled is Zig and
# nothing else, by construction: every path under src that is not a .zig file is deleted, and
# the compiler is given main.zig as the root with no other flag, so a build.zig, an object,
# an archive or a source in another language left beside the sources never reaches it. The
# binary has to be a regular file the build produced. Everything else under the tree then
# loses its execute bits, so a helper compiled beforehand and committed beside the sources is
# inert. The build is bounded by the 900 seconds the spec states.
build_tool() {
  local status
  /usr/bin/find /tmp -mindepth 1 -maxdepth 1 ! -name 'pytest_cache' -exec /usr/bin/rm -rf {} + 2>/dev/null || true
  /usr/bin/rm -rf /home/runner
  /usr/bin/install -d -o runner -g runner -m 755 /home/runner /home/runner/zig-global /home/runner/zig-local
  /usr/bin/rm -rf /app/flowkit
  /usr/bin/cp -a /opt/src_pristine /app/flowkit
  /usr/bin/rm -rf /app/flowkit/bin /app/flowkit/.zig-cache /app/flowkit/zig-out /app/flowkit/src/.zig-cache /app/flowkit/src/zig-out
  /usr/bin/find /app/flowkit/src -type l -delete 2>/dev/null || true
  /usr/bin/find /app/flowkit/src ! -type d ! -name '*.zig' -delete 2>/dev/null || true
  /usr/bin/find /app/flowkit/src -mindepth 1 -type d -empty -delete 2>/dev/null || true
  echo "collected Zig files: $(/usr/bin/find /app/flowkit/src -type f -name '*.zig' | /usr/bin/wc -l);" \
       "anything else left under src after the sweep: $(/usr/bin/find /app/flowkit/src ! -type d ! -name '*.zig' | /usr/bin/wc -l)"
  /usr/bin/install -d -o runner -g runner -m 755 /app/flowkit/bin
  /usr/bin/chown -R runner:runner /app/flowkit
  /usr/bin/find /app/flowkit/src -type f -exec /usr/bin/touch {} + 2>/dev/null || true

  close_interp
  setsid /usr/bin/timeout --signal=KILL 900 \
    setpriv --clear-groups --no-new-privs --reuid runner --regid runner \
    env -C /app/flowkit HOME=/home/runner ZIG_GLOBAL_CACHE_DIR=/home/runner/zig-global ZIG_LOCAL_CACHE_DIR=/home/runner/zig-local \
      "$ZIG" build-exe /app/flowkit/src/main.zig -O ReleaseSafe -femit-bin=/app/flowkit/bin/flowkit
  status=$?
  echo "zig exit status: $status"
  open_interp
  as_runner bash -c 'kill -9 -1' 2>/dev/null || true
  [ "$status" -eq 0 ] || echo failed > /opt/run/build_check.txt
  if [ -L /app/flowkit/bin/flowkit ] || [ ! -f /app/flowkit/bin/flowkit ]; then
    echo "no regular binary was produced at /app/flowkit/bin/flowkit"
    echo failed > /opt/run/build_check.txt
    /usr/bin/rm -f /app/flowkit/bin/flowkit
  fi
  /usr/bin/find /app/flowkit -type f -perm /111 ! -samefile /app/flowkit/bin/flowkit -exec /usr/bin/chmod a-x {} + 2>/dev/null || true
}

SERVICE_PID=""
start_archive() {   # $1 set, $2 host, $3 port, $4 page size, $5 token style
  /usr/bin/rm -f /opt/run/ready
  /usr/local/bin/python3 /opt/archive/archive.py --data "/opt/truth/$1" \
      --host "$2" --port "$3" --page "$4" --token-style "$5" \
      --ready-file /opt/run/ready --log "/opt/run/archive_$1.log" >> "/opt/run/archive_$1.err" 2>&1 &
  SERVICE_PID=$!
  local i
  for i in $(/usr/bin/seq 1 300); do
    [ -f /opt/run/ready ] && return 0
    /usr/bin/sleep 0.1
  done
  echo "FATAL: the archive never came up on $2:$3"
  return 1
}

# `kill` here is the shell builtin on purpose: a builtin cannot be shadowed by anything
# planted on PATH.
stop_archive() {
  [ -n "$SERVICE_PID" ] || return 0
  kill -TERM "$SERVICE_PID" 2>/dev/null || true
  wait "$SERVICE_PID" 2>/dev/null
  SERVICE_PID=""
}

# $1 = host, $2 = port, $3 = where to capture stdout. Starts the binary the build produced,
# from the directory the spec documents, as the unprivileged build user, with every other
# program on the box closed to it for the seconds it runs. Each run is bounded by the wall
# clock the spec states: a tool that never finishes would otherwise hang the verifier rather
# than fail.
exec_tool() {
  local host="$1" port="$2" out="$3" pid
  close_exec
  setsid /usr/bin/timeout --signal=KILL 600 bash -c '
      cd /app/flowkit
      export HOME=/home/runner
      export ARCHIVE_HOST="$1" ARCHIVE_PORT="$2"
      exec setpriv --clear-groups --no-new-privs --reuid runner --regid runner /app/flowkit/bin/flowkit' \
      _ "$host" "$port" > "$out" &
  pid=$!
  wait "$pid"
  echo "run exit status: $? (archive $host:$port)"
  open_exec
  kill -TERM -- -"$pid" 2>/dev/null || true
  kill -KILL -- -"$pid" 2>/dev/null || true
  as_runner bash -c 'kill -9 -1' 2>/dev/null || true
  /usr/bin/chown root:root "$out" 2>/dev/null || true
  /usr/bin/chmod 600 "$out" 2>/dev/null || true
}

echo "=== the archive the agent's own environment serves, on another address and port, other page size and tokens ==="
build_tool
start_archive sample 127.0.0.2 9611 37 hex || { echo 0 > /logs/verifier/reward.txt; exit 0; }
exec_tool 127.0.0.2 9611 /opt/run/report_sample.json
stop_archive

echo "=== an archive the agent has never seen ==="
build_tool
start_archive hidden 127.0.0.1 9612 91 b64 || { echo 0 > /logs/verifier/reward.txt; exit 0; }
exec_tool 127.0.0.1 9612 /opt/run/report_hidden.json
stop_archive

echo "=== a small archive with no lateral movement, reached by name ==="
build_tool
start_archive edge 127.0.0.4 9613 5 plain || { echo 0 > /logs/verifier/reward.txt; exit 0; }
exec_tool "$ARCHIVE_BY_NAME" 9613 /opt/run/report_edge.json
stop_archive
printf '%s\n' "$ARCHIVE_BY_NAME" > /opt/run/named_host.txt

as_runner bash -c 'kill -9 -1' 2>/dev/null || true
echo "=== what the archive recorded ==="
for s in sample hidden edge; do
  echo "$s: $(/usr/bin/grep -c ' FETCH page ' /opt/run/archive_$s.log) pages served, $(/usr/bin/grep -c ' CASE' /opt/run/archive_$s.log) case lines, $(/usr/bin/grep -c 'bad-token\|unknown' /opt/run/archive_$s.log) refused"
done
/usr/bin/head -6 /opt/run/archive_sample.log

# By absolute path, and -P keeps the working directory off the module path.
/usr/local/bin/python3 -P -m pytest -o cache_dir=/tmp/pytest_cache \
  --ctrf /logs/verifier/ctrf.json /tests/test_outputs.py -rA
if [ "$?" -eq 0 ]; then echo 1 > /logs/verifier/reward.txt; else echo 0 > /logs/verifier/reward.txt; fi
exit 0
