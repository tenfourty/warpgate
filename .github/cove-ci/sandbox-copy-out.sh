#!/usr/bin/env bash
# sandbox-copy-out.sh CONTAINER SRC DEST -- copy SRC out of a compile
# container to DEST in the job container, and refuse anything that is not a
# plain file or directory. (runcove-ll9r, #34 round 2 N6)
#
# WHY. A compile container runs branch code (build.rs, the test suite, npm
# scripts). `docker cp CONTAINER:SRC DEST` copies a symlink AS a symlink, and
# DEST is in the JOB container, which holds the dind's client key under
# /certs. So a branch that leaves /tmp/sccache-stats.txt -> /certs/client/key.pem
# in its container gets the job's own key printed by the `cat` that follows the
# copy, or uploaded by upload-artifact, which follows links. The self-check
# cannot see this: the link is harmless inside the container, and only becomes
# the key once it lands next to /certs.
#
# So nothing reads what came out until it is known to hold no links: SRC is
# copied (docker cp never follows it), then every path that arrived is
# checked, and any symlink -- or anything that is neither a regular file nor a
# directory -- is removed, NAMED (its path only; it is never followed, and its
# target is never printed) and refused.
#
# Exit codes:
#   0   copied, and everything that arrived is plain files and directories;
#   1   the copy itself failed (SRC absent, container gone, or part-way):
#       whatever had arrived was deleted first, so nothing partial survives;
#       callers keep their "no stats came out" handling;
#   93  something that is not a plain file or directory came out (removed), or
#       the check could not look (find failed), or a malformed call. The
#       caller must stop: nothing after it may read DEST.
set -uo pipefail

[ $# -eq 3 ] && [ -n "$1" ] && [ -n "$2" ] && [ -n "$3" ] || {
  echo "sandbox-copy-out: REFUSE -- usage: sandbox-copy-out.sh CONTAINER SRC DEST (exit 93)" >&2; exit 93; }
NAME=$1 SRC=$2 DEST=$3

# DEST IS CHECKED BEFORE ANYTHING IS COPIED OR DELETED (#39 round 2, R2-2).
# The purge below deletes DEST, and on the failure path it runs even when
# nothing arrived. A DEST of `link//` made it follow the link and delete
# INSIDE the target (reproduced). Callers pass fixed paths, so this refuses
# rather than normalises: an absolute path, no trailing slash, not itself a
# symlink, and a parent that resolves to exactly itself (no symlinked
# component anywhere above it).
refuse_dest() { echo "::error::sandbox-copy-out: REFUSED (exit 93): DEST '$DEST' $1; nothing was copied or deleted (#39 round 2)."; exit 93; }
case "$DEST" in /*) ;; *) refuse_dest "is not an absolute path" ;; esac
case "$DEST" in */) refuse_dest "ends in '/'" ;; esac
[ -L "$DEST" ] && refuse_dest "is itself a symbolic link"
DEST_PARENT=${DEST%/*}; [ -n "$DEST_PARENT" ] || DEST_PARENT=/
resolved=$(realpath -e -- "$DEST_PARENT" 2>/dev/null) || refuse_dest "has a parent that does not exist or cannot be resolved"
[ "$resolved" = "$DEST_PARENT" ] || refuse_dest "has a parent that is not what it resolves to ($resolved): a symbolic link above it, or a non-canonical path"
unset resolved

ARRIVAL="$DEST"
purge() { if [ -L "$ARRIVAL" ]; then rm -f -- "$ARRIVAL"; else rm -rf -- "$ARRIVAL"; fi; }

# A FAILED COPY IS PURGED TOO (#39 round 1, F1). docker cp extracts entry by
# entry and returns the first error, so whatever came before the failing
# entry is already on disk -- say /out/a -> /certs/client/key.pem, followed by
# an entry that makes extraction fail. Returning 1 without looking left that
# link for upload-artifact to follow. Now anything at DEST is deleted (a link
# is removed, never followed) before the 1 is returned: a copy that failed
# delivers nothing at all.
if ! docker cp "$NAME:$SRC" "$DEST"; then
  purge
  echo "sandbox-copy-out: the copy of $NAME:$SRC failed; anything that had arrived at $DEST was deleted unread (exit 1)" >&2
  exit 1
fi

# WHAT ARRIVED is checked as one tree, file or directory alike, RECURSIVELY:
# anything that is not a plain file or a directory (a symlink at any depth, a
# device, a fifo, a socket), and any plain file with more than one link (a
# hardlink-shaped oddity), refuses. The danger is a link that arrives HERE,
# where /certs/client/key.pem is real -- inside the compile container it
# pointed at nothing. find's exit status is read: a find that failed has not
# looked, and "printed nothing" must never read as "nothing wrong".
#
# On a refusal the WHOLE ARRIVAL is deleted, not only the offending paths, so
# nothing of what came out is left for a later step to read.
if [ -L "$ARRIVAL" ]; then
  purge
  echo "::error::sandbox-copy-out: REFUSED (exit 93): $SRC came out of $NAME as a symbolic link; the arrival was deleted before anything read it (runcove-ll9r N6)."
  exit 93
fi
[ -e "$ARRIVAL" ] || { echo "::error::sandbox-copy-out: REFUSED (exit 93): docker cp exited 0 but nothing is at $DEST."; exit 93; }
bad=$(find "$ARRIVAL" \( \( ! -type f ! -type d \) -o \( -type f -links +1 \) \) -print 2>&1); frc=$?
if [ "$frc" -ne 0 ]; then
  purge
  echo "::error::sandbox-copy-out: REFUSED (exit 93): could not check what came out of $NAME into $DEST (find exit $frc); the arrival was deleted, since nothing may read what was not checked."
  exit 93
fi
if [ -n "$bad" ]; then
  purge
  echo "::error::sandbox-copy-out: REFUSED (exit 93): $(wc -l <<<"$bad") path(s) that are not plain single-link files or directories came out of $NAME into $DEST; the WHOLE arrival was deleted before anything read it (runcove-ll9r N6). Named, never followed:"
  # The names are the container's choice: printed as ONE %q-quoted string, so no name, not
  # even one holding a newline, can begin a line of the log (a workflow command must).
  printf '  %q\n' "$bad"
  exit 93
fi
# Say so, one line per copy, so the job log itself proves every copy-out went
# through this check (a silent success left the log with no evidence at all;
# the lead's read of build-image 5471).
nfiles=$(find "$ARRIVAL" -type f -print | wc -l) || {
  purge; echo "::error::sandbox-copy-out: REFUSED (exit 93): could not count what came out of $NAME into $DEST; the arrival was deleted."; exit 93; }
echo "sandbox-copy-out: $NAME:$SRC -> $DEST: $nfiles file(s), no links or special files"
exit 0
