#!/usr/bin/env bash
# sandbox-check-install.sh CONTAINER -- deliver sandbox-exec.sh,
# sandbox-self-check.sh and the job's key fingerprint into a created, not yet
# started, compile container at /sandbox-check, from THIS checkout.
# (runcove-ll9r, runcove-8zer)
#
# FROM THIS CHECKOUT, NEVER THE BRANCH'S. The two files are read from the
# directory this script lives in (our machinery, $WARPGATE_CI/scripts), never
# from the working directory, which in the compile steps is the branch tree
# under test: a branch that could supply its own wrapper could supply one
# that checks nothing. test_workflow_config.py pins every call to the literal
# "$WARPGATE_CI/scripts/sandbox-check-install.sh".
#
# /sandbox-check is outside /src, where the branch tree is copied, so no copy
# of the branch can land on top of it.
#
# THE FINGERPRINT (8zer) is the third file, `fp`: sandbox-fingerprint.sh's
# size and sha256 of the job's client key.pem and cert.pem, which the
# self-check searches the container's /src and /ci for. A file, not a
# `docker create -e`: an environment variable there would be the environment
# of the container's main process, where branch code runs; the file is read
# by sandbox-exec.sh, which deletes it before anything else runs, and handed
# only to the self-check. It is 0644 like the scripts: a hash, not the key,
# and 0600 would not stop the command anyway (it runs as the same user as the
# wrapper, which must read it). A job whose key cannot be read refuses 93
# here.
#
# The copy is VERIFIED, not trusted: `docker cp` exiting 0 is not proof that
# anything arrived (hardened-run.sh learned that the hard way), and a created
# container cannot be exec'd into. So every file is copied back out and
# compared byte for byte with what was sent.
#
# Exit 93 on anything it cannot establish: no container name, a source file
# missing here, no fingerprint, a copy that failed, or a copy-back that
# differs. The caller
# must not start the container then: its command would begin with a wrapper
# that is not there, or not ours.
set -uo pipefail

NAME="${1:-}"
[ -n "$NAME" ] || { echo "sandbox-check-install: REFUSE -- no container name given (exit 93)" >&2; exit 93; }
HERE="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
FILES=(sandbox-exec.sh sandbox-self-check.sh)
for f in "${FILES[@]}" sandbox-fingerprint.sh; do
  [ -r "$HERE/$f" ] || { echo "sandbox-check-install: REFUSE -- $HERE/$f is missing, so there is nothing of ours to install (exit 93)" >&2; exit 93; }
done
FP=$(bash "$HERE/sandbox-fingerprint.sh") || exit 93
[ -n "$FP" ] || { echo "sandbox-check-install: REFUSE -- sandbox-fingerprint.sh printed nothing (exit 93)" >&2; exit 93; }

STAGE=$(mktemp -d) || { echo "sandbox-check-install: REFUSE -- could not make a staging directory (exit 93)" >&2; exit 93; }
trap 'rm -rf "$STAGE"' EXIT
mkdir "$STAGE/out" "$STAGE/back" || exit 93
for f in "${FILES[@]}"; do cp "$HERE/$f" "$STAGE/out/$f" || exit 93; done
( umask 022; printf '%s\n' "$FP" > "$STAGE/out/fp" ) || exit 93
unset FP
FILES+=(fp)

if ! docker cp "$STAGE/out/." "$NAME:/sandbox-check"; then
  echo "sandbox-check-install: REFUSE -- docker cp into $NAME:/sandbox-check failed (exit 93)" >&2
  exit 93
fi
if ! docker cp "$NAME:/sandbox-check/." "$STAGE/back"; then
  echo "sandbox-check-install: REFUSE -- could not copy /sandbox-check back out of $NAME to verify it (exit 93)" >&2
  exit 93
fi
for f in "${FILES[@]}"; do
  if ! cmp -s "$STAGE/out/$f" "$STAGE/back/$f"; then
    echo "sandbox-check-install: REFUSE -- $NAME:/sandbox-check/$f is missing or differs from ours after the copy (exit 93)" >&2
    exit 93
  fi
done
echo "sandbox-check-install: verified ${#FILES[@]} file(s) at $NAME:/sandbox-check, from $HERE"
