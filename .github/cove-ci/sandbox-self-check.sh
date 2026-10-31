#!/bin/sh
# sandbox-self-check.sh [--tree DIR]... [PATH...] -- run INSIDE a hardened-run
# sandbox or a compile container, with the exact environment the check
# command will get, BEFORE that command runs. (runcove-djgz, runcove-8zer)
#
# TWO PIPELINES RUN THIS: warpgate's (hardened-run sandboxes and every
# compile container) and the Cloud Hypervisor one (ch-ci, ch-build.yml's
# static build, through sandbox-exec.sh; runcove-fiyg.15.1). A change here
# must pass both.
#
# WHY. In a dind job every check now runs in this sandbox, and the one thing
# the sandbox exists to withhold is the dind's client certificate: with it, the
# check's code could drive the privileged dind. #29's static scans look for the
# ways our own code might hand a container the certificate or a DOCKER_*
# setting, and its fourth review still found spellings and assignment paths
# they missed (an `env:` block, GITHUB_ENV, a sourced file, `printf -v`,
# `read`, a command substitution, `docker cp`). Enumerating spellings loses to
# the next spelling. This asks the question itself, from inside, however the
# value got there: can this sandbox SEE a way to the daemon?
#
# WHAT IT LOOKS FOR, and it reports only NAMES and PATHS, never a value or a
# file's content:
#   * any variable named DOCKER_* in its environment;
#   * any variable, whatever its name -- read from `env -0`, so a name that
#     is not a shell identifier (a-b, my.key) counts too -- holding a PEM
#     private key, or whose value IS the job's client key or cert (by
#     fingerprint, below) (8zer; #45 round 1, F2);
#   * any readable file at all under /certs (the dind's certs mount) or under
#     each PATH given (hardened-run.sh passes the job's DOCKER_CERT_PATH):
#     nothing there is anything a sandbox may read, so a key without an
#     extension, or under any other name, counts (8zer);
#   * a copy of the job's client key.pem or cert.pem anywhere under each
#     --tree DIR: the trees the caller DELIVERED into the sandbox (the
#     workdir, /ci). Matched by FINGERPRINT (size and sha256), never by name
#     or by a PEM header, because the Warpgate source legitimately holds 19
#     test and vendored private keys (tests/certs, tests/ssh-keys,
#     vendor/picky) and a name or header match there would refuse every
#     check. A renamed, extensionless or deeply nested copy of the REAL
#     credential is still found (8zer). The match is EXACT BYTES ONLY, by
#     design: a key+cert bundle, CRLF line endings, gzip or tar, base64, or a
#     body without its header is not detected, in a tree or in a variable (a
#     variable holding a private key is still caught by its PEM header in any
#     form that keeps the header). A verbatim copy -- `cp -r`/`docker cp` of
#     /certs, the likely accident -- is what this catches (#45 round 1, F3);
#   * any unix socket under /run, /var/run, /certs or a given PATH -- a
#     mounted docker.sock is the daemon with no certificate and no variable at
#     all (#34 round 1, F3);
#   * any readable file under $HOME/.docker or /root/.docker, docker's default
#     certificate and credential directory when DOCKER_CERT_PATH is unset (F3).
# Every search but /run's follows symlinks (find -L), so a linked file or a
# linked directory is looked through, and none has a depth limit: a docker
# context's TLS key sits five levels down (8zer).
#
# THE FINGERPRINT arrives in the environment variable SANDBOX_FP, never on a
# command line: "SIZE:SHA256 SIZE:SHA256" (key.pem, cert.pem), or "none" when
# the job holds no client credential at all. It is read and unset before
# anything else runs; the one find that needs it gets it back through the
# environment (FPS, FPH), again never in argv. Where it briefly EXISTS
# (#45 round 1, F5): `unset` does not scrub a process's initial environment
# block, so while this script runs the value stays in /proc/<pid>/environ of
# its own sh, find and inner sh; on the compile path it is also in
# /sandbox-check/fp until sandbox-exec.sh (PID 1) deletes it, and in the job's
# staging file until the installer's EXIT trap. No branch process is alive at
# any of those points, and it is a SHA-256 and a size, not the key. sandbox-fingerprint.sh makes it in
# the job; a job whose key it cannot read refuses 93 there, so "could not
# fingerprint" never becomes "skipped the trees". Given --tree and no
# fingerprint, this is BLIND (2), never clean.
#
# IT FAILS CLOSED WHEN IT CANNOT LOOK (#34 round 1, F2). Every tool it uses is
# checked first, and every `find` must exit 0: a find that errors prints
# nothing, and "nothing printed" is exactly what clean looks like. The first
# version read an erroring find, or a missing sed, as clean. Under a cert root
# or a tree even "Permission denied" is blind (a directory with x but no r
# hides a file that can still be opened by name), and so is a symlink loop;
# only /run and /var/run tolerate a denied listing. The well-known cert names
# are also tested directly, without listing anything.
#
# POSIX sh and busybox-safe on purpose: it runs in whatever image the sandbox
# is -- the toolchain image in production, alpine in the real-engine tests --
# so no bash, no GNU `find -readable` (readability is `[ -r ]` per file).
# Values are hashed with `printf` piped to sha256sum, and printf must be the
# shell's BUILTIN (checked), so a value is never in any process's argv.
# Roots are searched as "ROOT/" so a symlinked root is followed.
#
# It reports EVERY finding up to the first blind refusal (#45 round 2, G3):
# a finding never stops the search, but `blind` exits on the spot, so roots
# and trees after it are neither searched nor named. The exit is non-zero
# either way, so nothing runs.
#
# Exit codes: 0 nothing visible, the sandbox is certless; 1 something is
# visible (each is named) -- the caller then refuses and the command never
# runs; 2 this script could not look (a tool missing or failing, no usable
# fingerprint), which must never read as clean. The LAST line is always
# `SANDBOX-SELF-CHECK: verdict clean|seen|blind`, so a caller can tell this
# script's 1 from a `docker exec` that failed before it ran (F4).

blind() { echo "SANDBOX-SELF-CHECK: $*, so this check cannot vouch for what the command would see"; echo "SANDBOX-SELF-CHECK: verdict blind"; exit 2; }

# The fingerprint first: read, then out of the environment before any other
# command runs, so nothing this script starts inherits it by accident.
fp_given=${SANDBOX_FP+yes}
fp=${SANDBOX_FP:-}
unset SANDBOX_FP
# Byte lengths, not characters, for the length pre-filter below.
LC_ALL=C

for tool in env tr find sh stat sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || blind "no $tool in this sandbox"
done
# A value is hashed as `printf '%s' "$v" | sha256sum`. Only a builtin printf
# keeps the value out of every argv; an external one would be handed it.
case $(command -V printf 2>&1) in
  *builtin*) ;;
  *) blind "printf is not a shell builtin here, so hashing a variable would put its value on a command line" ;;
esac

trees=""
while [ "${1:-}" = "--tree" ]; do
  [ -n "${2:-}" ] || blind "--tree given with no directory"
  trees="$trees
$2"
  shift 2
done

# The fingerprint's shape: "none", or exactly two SIZE:SHA256 (key.pem,
# cert.pem). Anything else is not a fingerprint, and a tree cannot be searched
# with it.
fp_sizes="" fp_hashes="" fp_n=0
case $fp_given:$fp in
  :) [ -z "$trees" ] || blind "trees to search were given but no fingerprint of the job's client key and cert was handed in (SANDBOX_FP)" ;;
  yes:none) ;;
  *)
    for tok in $fp; do
      size=${tok%%:*} hash=${tok#*:}
      case $size in ''|*[!0-9]*) blind "the fingerprint handed in is malformed (a size that is not a number)" ;; esac
      case $hash in *[!0-9a-f]*) blind "the fingerprint handed in is malformed (a hash that is not hex)" ;; esac
      [ "${#hash}" -eq 64 ] || blind "the fingerprint handed in is malformed (a hash that is not sha256)"
      fp_sizes="$fp_sizes $size" fp_hashes="$fp_hashes $hash" fp_n=$((fp_n + 1))
    done
    [ "$fp_n" -eq 2 ] || blind "the fingerprint handed in is malformed ($fp_n entries, not the key's and the cert's)"
    ;;
esac
unset fp

found=0
# Every variable, from TWO lists of what this process was given, never from
# the shell's own variables: a name that is not a shell identifier (a-b,
# my.key, 1KEY) is no shell variable at all (#45 round 1, F2).
#   * `env -0`: what this shell hands its children. bash and busybox pass
#     such names through; dash (Debian's /bin/sh, so CI's) drops them at
#     startup -- it imports only identifier names -- so its children never
#     see them (suite 5580: the F2 arm was red under dash alone).
#   * /proc/$$/environ: the environment this shell was STARTED with, as the
#     kernel recorded it, whatever the shell then kept. A command started the
#     same way (hardened-run's `docker exec`) gets every one of these names.
# An entry (NAME=VALUE) in both is counted once; the same name with two
# values is scanned twice (G1). SANDBOX_FP is skipped by name before its
# value is read: it was unset above, but /proc keeps a process's initial
# environment.
# Each entry becomes one line: NUL -> newline, and a newline inside a value
# -> \001, put back before hashing. A value is never an argument: it goes
# through builtin printf and tr's stdin only.
# `-0` is a GNU coreutils and busybox extension, not POSIX: an env without it
# exits non-zero (GNU's is 125 for an unknown flag), and that is BLIND, never
# "no variables". So is either list being empty: an empty environment cannot
# be, since PATH at least is set for every command we run (#45 round 1, the
# cove seat's condition on F2). So is an unreadable /proc/$$/environ.
env -0 >/dev/null 2>&1 || blind "env -0 failed (an env without -0?), so the environment cannot be listed"
entries=$(env -0 | tr '\000\n' '\n\001') || blind "tr failed on the environment list"
penv="/proc/$$/environ"
[ -r "$penv" ] || blind "$penv is not readable, so the environment this shell was given cannot be listed"
pentries=$(tr '\000\n' '\n\001' < "$penv") || blind "could not read $penv"
nl='
'
names="" keyvars="" credvars="" v="" n="" seen="$nl"
# scan_line LINE: one NAME=VALUE entry; returns 1 for a line that is none.
scan_line() {
  case $1 in *=*) ;; *) return 1 ;; esac
  n=${1%%=*}
  [ -n "$n" ] || return 1
  [ "$n" != SANDBOX_FP ] || return 0
  # De-duplicated by the WHOLE entry, never by name (#45 round 2, G1): a name
  # this script assigns itself (hash, trees, found, fp_sizes, LC_ALL...) is
  # listed by env -0 with this script's value, while /proc keeps the one the
  # command is given, so both must be scanned.
  case $seen in *"$nl$1$nl"*) return 0 ;; esac
  seen="$seen$1$nl"
  v=${1#*=}
  case $n in DOCKER_*) names="$names $n" ;; esac
  case $v in *"-----BEGIN "*"PRIVATE KEY-----"*) keyvars="$keyvars $n" ;; esac
  if [ "$fp_n" -gt 0 ]; then
    # Only a value of the right length is hashed, with and without the
    # trailing newline a file has and a command substitution strips.
    len=${#v}
    for size in $fp_sizes; do
      if [ "$len" -eq "$size" ] || [ "$((len + 1))" -eq "$size" ]; then
        for form in '%s' '%s\n'; do
          # shellcheck disable=SC2059  # the format is one of the two above
          h=$(printf "$form" "$v" | tr '\001' '\n' | sha256sum) || blind "sha256sum failed on a variable's value"
          h=${h%% *}
          case " $fp_hashes " in *" $h "*) credvars="$credvars $n"; return 0 ;; esac
        done
      fi
    done
  fi
  return 0
}
n_env=0
while IFS= read -r l; do scan_line "$l" && n_env=$((n_env + 1)); done <<ENTRIES
$entries
ENTRIES
[ "$n_env" -gt 0 ] || blind "env -0 listed no variables at all, which cannot be (PATH at least is set)"
n_proc=0
while IFS= read -r l; do scan_line "$l" && n_proc=$((n_proc + 1)); done <<PENTRIES
$pentries
PENTRIES
[ "$n_proc" -gt 0 ] || blind "$penv lists no variables at all, which cannot be (PATH at least is set)"
unset v h entries pentries seen
if [ -n "$names" ]; then
  echo "SANDBOX-SELF-CHECK: docker setting(s) in the sandbox's environment:$names"
  found=1
fi
if [ -n "$keyvars" ]; then
  echo "SANDBOX-SELF-CHECK: a PEM private key in the sandbox's environment, in:$keyvars"
  found=1
fi
if [ -n "$credvars" ]; then
  echo "SANDBOX-SELF-CHECK: the job's client key or cert in the sandbox's environment, in:$credvars"
  found=1
fi

# known PATH...: each path that is a readable file, named -- WITHOUT listing
# anything. A directory with x but no r cannot be listed, yet a file in it can
# be opened by anyone who knows its name, and the cert files' names are known
# (#34 round 1, lead's F2 follow-up). So these are tested directly, whatever
# find can or cannot see.
known() {
  desc=$1; shift
  hits=""
  for f in "$@"; do [ -f "$f" ] && [ -r "$f" ] && hits="$hits $f"; done
  if [ -n "$hits" ]; then
    echo "SANDBOX-SELF-CHECK: $desc at a known path:$hits"
    found=1
  fi
}

# look MODE DESC ROOT FIND-PREDICATES...: every readable match under ROOT,
# named. find's exit status is read, and non-zero is BLIND. MODE lenient
# tolerates one error, "Permission denied", and is used ONLY for /run and
# /var/run: there an unlistable directory hides sockets the command cannot
# find either (a socket path is not a well-known secret). MODE strict, for
# every cert root (/certs, the given paths, ~/.docker, /root/.docker) and
# every tree, treats even "Permission denied" as blind: a directory with x
# but no r cannot be listed but its files can still be opened by a known
# name, so there an unlistable directory is exactly where a key could hide.
# Strict also FOLLOWS symlinks (find -L), so a linked key or a linked
# directory is seen, and a link loop is an error, so blind (8zer).
#
# The per-file test is $CHECK, run by the inner sh on each batch: "readable"
# (a readable file is a hit) or "fingerprint" (a readable file whose size and
# sha256 are the job's key's or cert's, from FPS/FPH in its environment).
# shellcheck disable=SC2016  # $f, $@ and $FP* are the inner sh's, not ours
INNER='
case $CHECK in
  readable)
    for f in "$@"; do [ -r "$f" ] && printf "HIT %s\n" "$f"; done
    exit 0 ;;
  fingerprint)
    st=$(stat -L -c "%s %n" "$@") || { echo "STATFAIL"; exit 1; }
    while IFS= read -r l; do
      s=${l%% *} f=${l#* }
      case " $FPS " in *" $s "*) ;; *) continue ;; esac
      [ -r "$f" ] || continue
      h=$(sha256sum < "$f") || { echo "HASHFAIL"; exit 1; }
      case " $FPH " in *" ${h%% *} "*) printf "HIT %s\n" "$f" ;; esac
    done <<STATOUT
$st
STATOUT
    exit 0 ;;
esac
echo "BADCHECK"; exit 1'
look() {
  mode=$1 desc=$2 root=$3 check=$4; shift 4
  [ -n "$root" ] && { [ -e "$root" ] || [ -L "$root" ]; } || return 0
  follow=""; [ "$mode" = strict ] && follow="-L"
  out=$(CHECK=$check FPS="$fp_sizes" FPH="$fp_hashes" \
        find $follow "$root/" "$@" -exec sh -c "$INNER" sh {} + 2>&1)
  rc=$?
  hits="" denied=0 other=0
  while IFS= read -r l; do
    case $l in
      "HIT "*) rest=${l#HIT }; rest=${rest#"$root/"}; rest=${rest#/}; hits="$hits $root/$rest" ;;
      *"Permission denied"*) denied=1 ;;
      "") ;;
      *) other=1 ;;
    esac
  done <<FINDOUT
$out
FINDOUT
  if [ -n "$hits" ]; then
    echo "SANDBOX-SELF-CHECK: $desc under $root:$hits"
    found=1
  fi
  if [ "$rc" -ne 0 ] || [ "$other" -eq 1 ]; then
    if [ "$mode" = strict ] || [ "$other" -eq 1 ] || [ "$denied" -eq 0 ]; then
      why="exit $rc"; [ "$denied" -eq 1 ] && why="$why, a directory it may not list"
      blind "find could not list everything under $root ($why)"
    fi
  fi
}

# The well-known names first, by direct test (no listing needed).
for d in /certs/client "$@"; do
  [ -n "$d" ] || continue
  known "readable key/cert file(s)" "$d/key.pem" "$d/cert.pem" "$d/ca.pem"
done
for d in "${HOME:-}/.docker" /root/.docker; do
  [ -n "$d" ] || continue
  known "readable docker client file(s)" "$d/key.pem" "$d/cert.pem" "$d/ca.pem" "$d/config.json"
done

for root in /certs "$@"; do
  look strict "readable file(s) in a cert directory" "$root" readable -type f
  look strict "unix socket(s)" "$root" readable -type s
done
for root in /run /var/run; do
  look lenient "unix socket(s)" "$root" readable -type s
done
look strict "readable docker client file(s)" "${HOME:-}/.docker" readable -type f
[ "${HOME:-}" = /root ] || look strict "readable docker client file(s)" /root/.docker readable -type f

# The delivered trees, by fingerprint. A file name holding a newline would
# split in stat's output and hide from the size filter, so any such name is
# blind rather than skipped.
nl='
'
if [ -n "$trees" ] && [ "$fp_n" -gt 0 ]; then
  while IFS= read -r t; do
    [ -n "$t" ] || continue
    # its errors are the next find's to report; only "any at all" is read here
    odd=$(find -L "$t/" -name "*$nl*" -print 2>/dev/null)
    [ -z "$odd" ] || blind "a file name under $t holds a newline, so the fingerprint search cannot vouch for it"
    look strict "a copy of the job's client key or cert" "$t" fingerprint -type f
  done <<TREES
$trees
TREES
elif [ -n "$trees" ]; then
  echo "SANDBOX-SELF-CHECK: the job holds no client key or cert (fingerprint 'none'), so the delivered trees have nothing to be searched for"
fi

if [ "$found" -eq 1 ]; then echo "SANDBOX-SELF-CHECK: verdict seen"; else echo "SANDBOX-SELF-CHECK: verdict clean"; fi
exit "$found"
