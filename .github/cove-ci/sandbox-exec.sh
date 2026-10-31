#!/bin/sh
# sandbox-exec.sh -- COMMAND [ARG...] -- the container command of a
# compile container, wrapping the real one. (runcove-ll9r)
#
# TWO PIPELINES RUN THIS: warpgate's (build-image, build-macos, the weekly
# rebuild) and the Cloud Hypervisor one (ch-ci, ch-build.yml's static build;
# runcove-fiyg.15.1). A change here must pass both.
#
# WHY. hardened-run.sh runs sandbox-self-check.sh inside each sandbox before
# the command (runcove-djgz). The build-image compile containers (tests,
# advisories, release binary) are not hardened-run sandboxes: they are
# `docker create` + `docker cp` + `docker start -a`, and their command runs the
# moment they start, so there is no moment to exec a check first. They run
# the most branch code of anything here (build.rs, proc macros, the test
# suite), so this puts the same check in front of it, in the same container,
# with the same environment, before anything else runs.
#
# THE DELIVERED TREES (runcove-8zer): the working directory (the compile
# containers' -w /src, where the branch tree is copied) and /ci when present
# are searched for a copy of the job's client key or cert, by the fingerprint
# sandbox-check-install.sh left beside this script as `fp`. It is read with
# the shell's own `read`, the file is deleted at once (so the command, which
# runs as the same user, finds nothing to read), and the value is handed to
# the self-check alone, in its environment (SANDBOX_FP), never on a command
# line; the command below is exec'd without it. No fp file, one that cannot
# be deleted, or a working directory of /, is 93: the trees could not be
# searched, or the fingerprint would outlive the check.
#
# No cert path is passed in, unlike hardened-run (which hands the self-check
# the job's DOCKER_CERT_PATH as a second place to look): the self-check always
# looks under /certs, every dind job's DOCKER_CERT_PATH is /certs/client
# (test_workflow_config.py pins that), and a DOCKER_ or /certs token on a
# `docker create` line is exactly what the djgz sweeps refuse, rightly.
#
# Exit codes, the same as hardened-run.sh's for the same findings:
#   90  the self-check saw a DOCKER_* variable or a readable key/cert; it
#       names them (names and paths only) and COMMAND never runs.
#   93  nothing is known: no sandbox-self-check.sh or fp beside this script,
#       an fp that could not be deleted, a working directory of /, a self-check that was blind (its 2) or gave
#       no matching verdict line, or a malformed call. COMMAND never runs.
#   otherwise, COMMAND's own: on a clean check this script `exec`s it, so its
#       exit status and signals are COMMAND's, untouched.
#
# POSIX sh, and no external command before the check (`${0%/*}`, not
# dirname): the check must be able to run, or refuse, in any image.

[ "${1:-}" = "--" ] || {
  echo "sandbox-exec: REFUSE -- usage: sandbox-exec.sh -- COMMAND...; the command was NOT run (exit 93)" >&2
  exit 93; }
shift
[ $# -ge 1 ] || { echo "sandbox-exec: REFUSE -- no command given (exit 93)" >&2; exit 93; }

case "$0" in */*) here=${0%/*} ;; *) here=. ;; esac
self_check="$here/sandbox-self-check.sh"
[ -r "$self_check" ] || {
  echo "sandbox-exec: REFUSE -- no sandbox self-check at $self_check, so nothing is known about what the command would see; the command was NOT run (exit 93)" >&2
  exit 93; }

fp_file="$here/fp"
fp=""
[ -r "$fp_file" ] && { IFS= read -r fp < "$fp_file" || [ -n "$fp" ]; } && [ -n "$fp" ] || {
  echo "sandbox-exec: REFUSE -- no fingerprint of the job's key at $fp_file, so the delivered trees cannot be searched for it; the command was NOT run (exit 93)" >&2
  exit 93; }
rm -f "$fp_file" && [ ! -e "$fp_file" ] || {
  echo "sandbox-exec: REFUSE -- could not delete $fp_file after reading it, so the command would find the fingerprint; the command was NOT run (exit 93)" >&2
  exit 93; }
[ "$PWD" != / ] || {
  echo "sandbox-exec: REFUSE -- the working directory is /, which is not a delivered tree the self-check can search; the command was NOT run (exit 93)" >&2
  exit 93; }
if [ -d /ci ]; then
  out=$(SANDBOX_FP=$fp sh "$self_check" --tree "$PWD" --tree /ci 2>&1)
else
  out=$(SANDBOX_FP=$fp sh "$self_check" --tree "$PWD" 2>&1)
fi
rc=$?
unset fp
# The verdict is the self-check's last line and is required, as hardened-run
# requires it (#34 round 1, F4): an rc without its matching verdict means the
# script did not run to the end, which is not a finding and not clean.
verdict=${out##*"
"}
case "$rc:$verdict" in
  "0:SANDBOX-SELF-CHECK: verdict clean")
    echo "sandbox-exec: sandbox self-check passed: no DOCKER_* setting, no readable key or cert, no unix socket and no docker client files visible to the command" ;;
  "1:SANDBOX-SELF-CHECK: verdict seen")
    printf 'sandbox-exec: REFUSE -- this container can see a way to the dind (a docker setting, a key/cert, a socket or docker client files), so it is not a sandbox; the command was NOT run (runcove-ll9r, exit 90):\n%s\n' "$out" >&2
    exit 90 ;;
  *)
    printf 'sandbox-exec: REFUSE -- the sandbox self-check could not look or did not reach a verdict (exit %s), so nothing is known about what the command would see; the command was NOT run (exit 93):\n%s\n' "$rc" "$out" >&2
    exit 93 ;;
esac

exec "$@"
