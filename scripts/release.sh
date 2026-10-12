#!/usr/bin/env bash
set -euo pipefail

CHANGELOG_FILE="CHANGELOG.md"
PYPROJECT_FILE="pyproject.toml"
SEMVER_RE='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

usage() {
  echo "Usage: scripts/release.sh X.Y.Z" >&2
}

is_valid_semver() {
  [[ "$1" =~ $SEMVER_RE ]]
}

pyproject_version() {
  grep -m1 -E '^version = "' "$PYPROJECT_FILE" | sed -E 's/^version = "(.*)"$/\1/'
}

# $1 > $2 ? both must already be valid X.Y.Z.
semver_gt() {
  local -a a b
  IFS=. read -r -a a <<<"$1"
  IFS=. read -r -a b <<<"$2"
  for i in 0 1 2; do
    if ((a[i] > b[i])); then
      return 0
    fi
    if ((a[i] < b[i])); then
      return 1
    fi
  done
  return 1
}

_trim_blank_lines() {
  awk '
    BEGIN { started = 0 }
    { if (!started && $0 == "") next; started = 1; lines[++n] = $0 }
    END { while (n > 0 && lines[n] == "") n--; for (i = 1; i <= n; i++) print lines[i] }
  '
}

changelog_unreleased_header_line() {
  grep -n '^## \[Unreleased\]' "$CHANGELOG_FILE" | head -1 | cut -d: -f1
}

# $1 = line number to search after; prints the next "## [" heading line, or
# nothing if Unreleased is the last section.
changelog_next_heading_line() {
  local after="$1" rel
  rel=$(tail -n "+$((after + 1))" "$CHANGELOG_FILE" | grep -n '^## \[' | head -1 | cut -d: -f1)
  if [[ -n "$rel" ]]; then
    echo "$((after + rel))"
  fi
}

# Prints the trimmed body of the [Unreleased] section (empty if none).
changelog_unreleased_content() {
  local start next end
  start=$(changelog_unreleased_header_line)
  if [[ -z "$start" ]]; then
    echo "ERROR: no '## [Unreleased]' heading found in $CHANGELOG_FILE." >&2
    return 1
  fi
  next=$(changelog_next_heading_line "$start")
  if [[ -n "$next" ]]; then
    end=$((next - 1))
  else
    end=$(wc -l <"$CHANGELOG_FILE")
  fi
  if ((end < start + 1)); then
    return 0
  fi
  sed -n "$((start + 1)),${end}p" "$CHANGELOG_FILE" | _trim_blank_lines
}

# Updates the Keep-a-Changelog compare-link block at the bottom of the file,
# if that convention is present. A no-op otherwise.
_update_compare_links() {
  local version="$1" link_line
  link_line=$(grep -n '^\[Unreleased\]: ' "$CHANGELOG_FILE" | head -1 | cut -d: -f1)
  if [[ -z "$link_line" ]]; then
    return 0
  fi
  local old_text repo_url old_version tmp
  old_text=$(sed -n "${link_line}p" "$CHANGELOG_FILE")
  repo_url=$(echo "$old_text" | sed -E 's#^\[Unreleased\]: (.*)/compare/v[0-9][0-9A-Za-z.+-]*\.\.\.HEAD$#\1#')
  old_version=$(echo "$old_text" | sed -E 's#^\[Unreleased\]: .*/compare/v([0-9][0-9A-Za-z.+-]*)\.\.\.HEAD$#\1#')
  tmp=$(mktemp)
  {
    sed -n "1,$((link_line - 1))p" "$CHANGELOG_FILE"
    echo "[Unreleased]: ${repo_url}/compare/v${version}...HEAD"
    echo "[${version}]: ${repo_url}/compare/v${old_version}...v${version}"
    sed -n "$((link_line + 1)),\$p" "$CHANGELOG_FILE"
  } >"$tmp"
  mv "$tmp" "$CHANGELOG_FILE"
}

# Moves the [Unreleased] body under a new dated [X.Y.Z] heading, leaving an
# empty [Unreleased] section above it, then updates the compare links.
rewrite_changelog() {
  local version="$1" date="$2" start next end content tmp
  start=$(changelog_unreleased_header_line)
  next=$(changelog_next_heading_line "$start")
  if [[ -n "$next" ]]; then
    end=$((next - 1))
  else
    end=$(wc -l <"$CHANGELOG_FILE")
  fi
  content=$(sed -n "$((start + 1)),${end}p" "$CHANGELOG_FILE" | _trim_blank_lines)

  tmp=$(mktemp)
  {
    sed -n "1,${start}p" "$CHANGELOG_FILE"
    echo ""
    echo "## [${version}] - ${date}"
    echo ""
    printf '%s\n' "$content"
    echo ""
    if [[ -n "$next" ]]; then
      sed -n "${next},\$p" "$CHANGELOG_FILE"
    fi
  } >"$tmp"
  mv "$tmp" "$CHANGELOG_FILE"

  _update_compare_links "$version"
}

bump_pyproject_version() {
  local version="$1" tmp
  tmp=$(mktemp)
  awk -v new="$version" '
    BEGIN { done = 0 }
    !done && /^version = "/ { print "version = \"" new "\""; done = 1; next }
    { print }
  ' "$PYPROJECT_FILE" >"$tmp"
  mv "$tmp" "$PYPROJECT_FILE"
}

main() {
  if [[ $# -ne 1 ]]; then
    usage
    exit 1
  fi
  local version="$1"

  if [[ ! -f "$CHANGELOG_FILE" || ! -f "$PYPROJECT_FILE" ]]; then
    echo "ERROR: run from the repo root ($CHANGELOG_FILE / $PYPROJECT_FILE not found here)." >&2
    exit 1
  fi

  if [[ -n "$(git status --porcelain)" ]]; then
    echo "ERROR: working tree is not clean. Commit or stash changes first." >&2
    exit 1
  fi

  local branch
  branch=$(git rev-parse --abbrev-ref HEAD)
  if [[ "$branch" != "main" ]]; then
    echo "ERROR: must run from 'main' (currently on '$branch')." >&2
    exit 1
  fi

  if ! is_valid_semver "$version"; then
    echo "ERROR: '$version' is not a valid semver (expected X.Y.Z)." >&2
    exit 1
  fi

  local current_version
  current_version=$(pyproject_version)
  if ! semver_gt "$version" "$current_version"; then
    echo "ERROR: $version is not greater than the current version $current_version in $PYPROJECT_FILE." >&2
    exit 1
  fi

  local unreleased_content
  unreleased_content=$(changelog_unreleased_content)
  if [[ -z "$unreleased_content" ]]; then
    echo "ERROR: the [Unreleased] section in $CHANGELOG_FILE is empty. Nothing to release." >&2
    exit 1
  fi

  local release_date
  release_date=$(date +%Y-%m-%d)

  rewrite_changelog "$version" "$release_date"
  bump_pyproject_version "$version"
  uv lock

  local release_branch="release/${version}"
  git checkout -b "$release_branch"
  git add "$CHANGELOG_FILE" "$PYPROJECT_FILE" uv.lock
  git commit -m "Released ${version}"

  cat <<EOF

Release branch '${release_branch}' created and committed locally. Next:
  1. Push it and open a PR against main: git push -u origin ${release_branch}
  2. Merge the PR.
  3. Tag the merge commit: git tag -a v${version} -m "Kimera v${version}" && git push origin v${version}
  4. Approve the 'pypi' environment job when publish.yml pauses.
  5. Watch the smoke-test job (installs from PyPI on 3.11 and 3.13).
EOF
}

if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  main "$@"
fi
