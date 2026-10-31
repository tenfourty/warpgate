#!/usr/bin/env bash
# v<upstream>-cove.<n>: upstream's version, then our own release counter on
# top of it. Replaces `git describe` output (e.g. v0.28.6-75-g50268b2d),
# which changes on every commit and which nothing can order -- measured
# 2026-09-18: Renovate authenticates, fetches, and proposes nothing, because
# "-75-g50268b2d" and "-81-ga71a1160" are not comparable.
#
# --validate and --is-release are deliberately the same test: a well-formed
# release tag IS what triggers the ARM build (see ci.yml). One regex, both
# branches use it below, so they cannot drift apart.
#
# Exit codes 89-99 join the same reserved "could not run safely" band as
# cache-env.sh, run-check.sh, hardened-run.sh and configure-cache.sh -- the
# thing never ran, rather than ran and failed. 93 keeps its meaning from
# those four scripts: a required argument (here, the subcommand or its
# operand) is missing or unrecognised. This script adds two more of its own
# (95, 96, below); the full, current registry of every code in the band is
# EXIT_CODES.md.
#   95 -- --next found no upstream vX.Y.Z tag reachable from HEAD, so there
#         is no base to build a version on.
#   96 -- --next could not establish that its view of existing <base>-cove.*
#         tags is complete before trusting an empty result to mean "no cove
#         release exists yet for this base". A shallow clone is one way to
#         be wrong about that (git rev-parse --is-shallow-repository); a
#         full, non-shallow clone whose fetch simply never brought tags (no
#         --tags, a checkout step that skipped them) is another, and looks
#         identical locally -- Round 1 review reproduced exactly that case
#         and got back an already-released cove.1. Local git state alone
#         cannot tell the two apart; only the remote's own tag list can, so
#         --next checks that too (git ls-remote against REMOTE, "origin" by
#         default -- override with VERSION_SH_REMOTE if that name doesn't
#         point at this fork; in this dev checkout, for instance, "origin"
#         is upstream's GitHub and the fork is "forge") before trusting
#         silence. Reissuing a version number that already exists publishes
#         over a release, so this refuses rather than guesses. A refusal
#         costs a rerun; a collision costs a release.
#
# --validate's and --sort-key's own 0/1 exits are a separate, narrower
# contract ("well-formed or not") that predates this file's use of the
# 89-99 band, and are unaffected by it.
#
# VERSION_SH_SHAPE (runcove-fiyg.15.2) says whose upstream versions these are,
# because the one thing that differs is how many parts upstream uses:
#   warpgate (unset or empty): vX.Y.Z-cove.<n>, as it always was.
#   ch      : Cloud Hypervisor's vX.Y (v53.0) or vX.Y.Z (v36.0.1) -- so the
#             describe glob takes two parts, and the base describe returns
#             must itself be exactly vX.Y or vX.Y.Z (95 otherwise).
# Anything else is 93: guessing a shape would validate the wrong tags.
set -uo pipefail

case "${VERSION_SH_SHAPE:-warpgate}" in
  warpgate)
    RE='^v[0-9]+\.[0-9]+\.[0-9]+-cove\.[1-9][0-9]*$'
    BASE_GLOB='v[0-9]*.[0-9]*.[0-9]*'
    BASE_RE='' ;;
  ch)
    RE='^v[0-9]+\.[0-9]+(\.[0-9]+)?-cove\.[1-9][0-9]*$'
    BASE_GLOB='v[0-9]*.[0-9]*'
    BASE_RE='^v[0-9]+\.[0-9]+(\.[0-9]+)?$' ;;
  *)
    echo "version.sh: FATAL -- VERSION_SH_SHAPE='${VERSION_SH_SHAPE}' is neither 'warpgate' nor 'ch'. Refusing to run." >&2
    exit 93 ;;
esac
is_valid_tag() { [[ "$1" =~ $RE ]]; }

USAGE="usage: version.sh --validate <tag> | --sort-key <tag> | --is-release <ref> | --next"

# Not `"${2:?...}"` anywhere below -- that form kills the script via bash's
# own parameter-expansion error, exit 1, indistinguishable from an ordinary
# failure and outside this codebase's exit-code contract (the same defect
# already fixed in cache-env.sh, run-check.sh, hardened-run.sh and
# configure-cache.sh). A missing required operand is a refusal like theirs,
# so it gets the same code: 93. $1 here is the subcommand name, only used to
# name the problem in the message.
require_operand() {
  if [ $# -lt 2 ] || [ -z "${2:-}" ]; then
    echo "version.sh: FATAL -- usage: version.sh $1 <tag> (required argument missing). Refusing to run." >&2
    exit 93
  fi
}

case "${1:-}" in
  --validate)
    require_operand --validate "${2:-}"
    is_valid_tag "$2" && exit 0 || exit 1
    ;;

  --is-release)
    require_operand --is-release "${2:-}"
    is_valid_tag "$2" && exit 0 || exit 1
    ;;

  --sort-key)
    require_operand --sort-key "${2:-}"
    tag="$2"
    # Validate before deriving a key. `printf %010d` on a non-numeric
    # counter (e.g. a hand-edited "v0.28.6-cove.abc") fails and silently
    # substitutes 0, which sorts below every real release and looks exactly
    # like a valid key -- the same "reading that can't tell two cases apart,
    # reported as one of them" failure this whole arc keeps finding. Refuse
    # instead of emitting a key that looks fine.
    if ! is_valid_tag "$tag"; then
      echo "version.sh: cannot sort '$tag' -- not a well-formed <upstream>-cove.<n> tag. Refusing to emit a key that would look valid." >&2
      exit 1
    fi
    base="${tag%-cove.*}"
    n="${tag##*-cove.}"
    # Zero-pad the counter so plain string sort matches numeric sort
    # (cove.10 must sort after cove.9).
    printf '%s-cove.%010d\n' "$base" "$n"
    ;;

  --next)
    # --exclude keeps our own release tags out of the candidate set. Without
    # it, once any -cove.* tag exists, `--match`'s glob (which cannot express
    # "digits only" -- `[0-9]*` is one digit then ANY characters, not
    # "one-or-more digits") also matches "v0.28.6-cove.9", and once a cove
    # tag is closer to HEAD than the real upstream tag, describe returns the
    # cove tag itself as "base" -- corrupting every version after the first
    # release (verified: v0.28.6, v0.28.6-cove.1 on a later commit, HEAD at
    # that commit -- describe with --match alone returns "v0.28.6-cove.1").
    base=$(git describe --tags --abbrev=0 \
             --match "$BASE_GLOB" --exclude '*-cove.*' 2>/dev/null)
    if [ -z "$base" ]; then
      echo "version.sh: FATAL -- no upstream vX.Y.Z tag reachable from HEAD; cannot compute a base version." >&2
      exit 95
    fi
    # CH shape only: the glob cannot say "digits only", so an upstream tag
    # like v53.0-rc1 could be the nearest match. It is not a base.
    if [ -n "$BASE_RE" ] && ! [[ "$base" =~ $BASE_RE ]]; then
      echo "version.sh: FATAL -- the nearest upstream tag, '$base', is not a plain upstream version; cannot compute a base version." >&2
      exit 95
    fi

    # Door 1 of 2: a shallow clone. It can still resolve $base above -- git
    # only needs the one nearest matching tag for that -- while missing every
    # other tag in the repository, including real cove releases.
    shallow=$(git rev-parse --is-shallow-repository 2>/dev/null)
    if [ "$shallow" != "false" ]; then
      echo "version.sh: FATAL -- refusing to trust an empty release search: this clone is shallow (or its depth could not be determined), which looks identical to \"no releases yet\" but can hide real ones. Fetch full history and tags (fetch-depth: 0, fetch-tags: true) and retry." >&2
      exit 96
    fi

    # Door 2 of 2: a full, non-shallow clone whose fetch simply never brought
    # tags (no --tags, or a checkout step that skipped them). is-shallow-
    # repository says "false" here too -- Round 1 review reproduced exactly
    # this and got back an already-released cove.1. Zero local cove tags for
    # $base is legitimately correct before the first release, so the ONLY
    # authoritative answer is the remote's own tag list: if the remote has a
    # release tag this clone lacks, the local view is incomplete, full stop.
    #
    # REMOTE defaults to the name every workflow's checkout gives its own
    # remote ("origin", from Forgejo Actions). Override with
    # VERSION_SH_REMOTE for a different name or a raw URL -- e.g. in *this*
    # dev clone, "origin" is upstream's GitHub, not the fork, so a real cut
    # here needs VERSION_SH_REMOTE=forge. A timeout is a refusal, not a hang:
    # this is exactly the discipline run-check.sh's lookup timeout applies.
    REMOTE="${VERSION_SH_REMOTE:-origin}"
    REMOTE_TIMEOUT="${VERSION_SH_REMOTE_TIMEOUT:-15}"
    remote_list=$(timeout "$REMOTE_TIMEOUT" git ls-remote --tags --refs "$REMOTE" "${base}-cove.*" 2>/dev/null)
    remote_rc=$?
    if [ "$remote_rc" -eq 124 ]; then
      echo "version.sh: FATAL -- timed out after ${REMOTE_TIMEOUT}s contacting remote '$REMOTE' for existing ${base}-cove.* tags. Refusing to guess blind." >&2
      exit 96
    elif [ "$remote_rc" -ne 0 ]; then
      echo "version.sh: FATAL -- could not query remote '$REMOTE' for existing ${base}-cove.* tags (exit $remote_rc). Refusing to trust a local search that might be incomplete." >&2
      exit 96
    fi

    missing=""
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      t="${line#*refs/tags/}"
      git rev-parse -q --verify "refs/tags/$t" >/dev/null 2>&1 || missing="$missing $t"
    done <<<"$remote_list"
    if [ -n "$missing" ]; then
      echo "version.sh: FATAL -- remote '$REMOTE' has release tag(s) this clone does not:$missing -- local view is incomplete, refusing to guess the next version." >&2
      exit 96
    fi

    last=0
    while IFS= read -r t; do
      [ -z "$t" ] && continue
      is_valid_tag "$t" || continue
      n="${t##*-cove.}"
      [ "$n" -gt "$last" ] && last="$n"
    done < <(git tag --list "${base}-cove.*")

    echo "${base}-cove.$((last + 1))"
    ;;

  *)
    echo "version.sh: FATAL -- $USAGE (subcommand missing or unrecognised). Refusing to run." >&2
    exit 93
    ;;
esac
