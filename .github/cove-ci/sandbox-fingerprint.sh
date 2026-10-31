#!/usr/bin/env bash
# sandbox-fingerprint.sh -- print the fingerprint of the job's docker client
# key and cert, for sandbox-self-check.sh to search the delivered trees with.
# Runs in the JOB, never in a sandbox. (runcove-8zer)
#
# WHY. The self-check searches the trees delivered into a sandbox (the
# workdir, /ci, a compile container's /src) for a copy of the job's client
# credential. It cannot match by name or by PEM header: the Warpgate source
# holds 19 test and vendored private keys, and every check would refuse. So it
# matches by FINGERPRINT, and only the job can take one: the sandbox, by
# design, cannot read the key.
#
# OUTPUT, on stdout and nowhere else: "SIZE:SHA256 SIZE:SHA256" for key.pem
# and cert.pem (ca.pem is public, and matching it would flag a copy of the CA
# as if it were the key), or "none" when the job holds no client credential at
# all. A caller captures it into a variable and hands it on in the environment
# (SANDBOX_FP), never on a command line and never in a log: a hash of a key is
# not the key, but it is still nothing a log needs.
#
# WHERE the credential is, as docker's own client decides it:
#   * DOCKER_CERT_PATH, when set (every dind job: /certs/client);
#   * otherwise ~/.docker, when DOCKER_TLS_VERIFY is set or ~/.docker/key.pem
#     exists (docker's default certificate directory);
#   * otherwise there is none: "none".
#
# Exit 93 when there IS a credential directory and key.pem or cert.pem in it
# is not a readable file, or cannot be measured: "could not fingerprint" must
# never become "nothing to search for" (the lead's ruling on 8zer).
set -uo pipefail

dir=""
if [ -n "${DOCKER_CERT_PATH:-}" ]; then
  dir=$DOCKER_CERT_PATH
elif [ -n "${DOCKER_TLS_VERIFY:-}" ] || [ -e "${HOME:-/nonexistent}/.docker/key.pem" ] || [ -L "${HOME:-/nonexistent}/.docker/key.pem" ]; then
  dir="${HOME:-/nonexistent}/.docker"
else
  echo none
  exit 0
fi

fp=""
for f in key.pem cert.pem; do
  p="$dir/$f"
  if ! [ -f "$p" ] || ! [ -r "$p" ]; then
    echo "sandbox-fingerprint: REFUSE -- $p is not a readable file, so the trees delivered into the sandbox cannot be searched for a copy of it (exit 93)" >&2
    exit 93
  fi
  size=$(stat -L -c %s "$p") || { echo "sandbox-fingerprint: REFUSE -- could not measure $p (exit 93)" >&2; exit 93; }
  sum=$(sha256sum < "$p") || { echo "sandbox-fingerprint: REFUSE -- could not hash $p (exit 93)" >&2; exit 93; }
  sum=${sum%% *}
  if ! [[ "$size" =~ ^[0-9]+$ && "$sum" =~ ^[0-9a-f]{64}$ ]]; then
    echo "sandbox-fingerprint: REFUSE -- $p did not measure as a size and a sha256 (exit 93)" >&2
    exit 93
  fi
  fp="$fp${fp:+ }$size:$sum"
done
printf '%s\n' "$fp"
