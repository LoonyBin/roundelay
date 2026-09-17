#!/usr/bin/env bash
#
# Materialise the specification this branch implements.
#
# The document lives on `main`; this branch holds the implementation. The files
# listed in spec.lock are written into the working tree at the same paths they
# have on `main`, and .gitignore keeps them untracked. Same paths, because
# `conformance/checklist.yaml` cites `docs/…` in every one of its 250 items and
# those citations have to resolve on both branches.
#
# Usage:
#   scripts/spec-sync.sh            sync to the ref in spec.lock
#   ROUNDELAY_SPEC_REF=<commit>     sync to something else, for reproducing a run
#   scripts/spec-sync.sh --check    report whether the tree is present, sync nothing
#
# The files it writes are ignored, so it never touches the index and can be run
# at any time, including on a dirty tree.

set -euo pipefail

cd "$(dirname "$0")/.."

lock=spec.lock
[[ -f $lock ]] || { echo "spec-sync: $lock not found" >&2; exit 1; }

# spec.lock is read with awk rather than sourced: it is data, and a config file
# that is also a shell script is a config file that can do anything.
lockref=$(awk '$1 == "ref" { print $2; exit }' "$lock")
ref=${ROUNDELAY_SPEC_REF:-$lockref}
[[ -n $ref ]] || { echo "spec-sync: no 'ref' in $lock" >&2; exit 1; }

# Everything indented under the `files` key, to the end of the file. Read with a
# loop rather than mapfile, which is bash 4 and macOS still ships 3.2.
files=()
while IFS= read -r f; do
  files+=("$f")
done < <(awk '
  $1 == "files" { inlist = 1; next }
  inlist && /^[[:space:]]+[^[:space:]#]/ { print $1 }
  inlist && /^[^[:space:]#]/ { inlist = 0 }
' "$lock")
(( ${#files[@]} > 0 )) || { echo "spec-sync: no 'files' in $lock" >&2; exit 1; }

if [[ ${1:-} == --check ]]; then
  missing=()
  for f in "${files[@]}"; do [[ -f $f ]] || missing+=("$f"); done
  if (( ${#missing[@]} )); then
    echo "spec-sync: the specification is not in this tree (${#missing[@]} of ${#files[@]} files missing)." >&2
    echo "spec-sync: it lives on '$ref' and is not committed here. Run: make spec" >&2
    exit 1
  fi
  echo "spec: ${#files[@]} files present"
  exit 0
fi

# Always try the remote first, even when a ref of that name already resolves
# locally. `ref` is normally a branch, and a stale local `main` quietly syncing
# yesterday's spec is precisely the failure this script exists to prevent.
#
# CI checks out one branch at a depth of one, so `main` is usually not in the
# object store at all and this fetch is the only way it gets there.
sha=
if git fetch --quiet --depth=1 origin "$ref" 2>/dev/null; then
  # A branch or tag name. The common case, and the only one CI takes.
  sha=$(git rev-parse --verify "FETCH_HEAD^{commit}")
elif git rev-parse --verify --quiet "$ref^{commit}" >/dev/null; then
  # Already here. Either origin is unreachable, or `ref` is a commit in a clone
  # that has it — a worktree of this repository, say.
  sha=$(git rev-parse --verify "$ref^{commit}")
  echo "spec-sync: could not fetch '$ref'; using the copy already in this repository" >&2
elif [[ -n $lockref ]]; then
  # `ref` is very likely a commit, and no server serves those by name. Fetch the
  # branch spec.lock names, deeply enough to contain it, and look it up there.
  # This is the ROUNDELAY_SPEC_REF path in a CI-shaped shallow clone.
  if [[ $(git rev-parse --is-shallow-repository) == true ]]; then
    git fetch --quiet --unshallow origin "$lockref" 2>/dev/null || true
  else
    git fetch --quiet origin "$lockref" 2>/dev/null || true
  fi
  if git rev-parse --verify --quiet "$ref^{commit}" >/dev/null; then
    sha=$(git rev-parse --verify "$ref^{commit}")
  fi
fi

if [[ -z $sha ]]; then
  sha=$(git rev-parse --verify --quiet "origin/$ref^{commit}" || true)
  if [[ -n $sha ]]; then
    echo "spec-sync: could not fetch '$ref'; using origin/$ref as last fetched" >&2
  fi
fi
[[ -n $sha ]] || { echo "spec-sync: cannot resolve '$ref'" >&2; exit 1; }

# Check the whole list before writing any of it. A partial sync surfaces as a
# file-not-found in a test, a long way from the thing that actually went wrong.
for f in "${files[@]}"; do
  git cat-file -e "$sha:$f" 2>/dev/null \
    || { echo "spec-sync: $f is not on $ref ($sha)" >&2; exit 1; }
done

for f in "${files[@]}"; do
  mkdir -p "$(dirname "$f")"
  git show "$sha:$f" > "$f"
done

echo "spec: ${#files[@]} files from $ref ($(git rev-parse --short "$sha"))"
