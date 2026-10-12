#!/usr/bin/env bash
# Self-test for release.sh: no framework, plain assertions. Run directly;
# non-zero exit means a check failed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELEASE_SH="${SCRIPT_DIR}/release.sh"
FAILURES=0

ok() { echo "ok - $1"; }
fail() {
  echo "FAIL - $1" >&2
  FAILURES=$((FAILURES + 1))
}

assert_eq() {
  local actual="$1" expected="$2" label="$3"
  if [[ "$actual" == "$expected" ]]; then
    ok "$label"
  else
    fail "$label (expected '$expected', got '$actual')"
  fi
}

# --- unit tests: source the script, which only runs main() when executed
# directly (see the BASH_SOURCE guard at the bottom of release.sh). ---
# shellcheck source=/dev/null
source "$RELEASE_SH"

for v in "1.2.3" "0.0.1" "10.20.30"; do
  if is_valid_semver "$v"; then
    ok "is_valid_semver accepts $v"
  else
    fail "is_valid_semver rejected valid version $v"
  fi
done

for v in "1.2" "1.2.3.4" "v1.2.3" "1.2.03" "1.2.x" ""; do
  if is_valid_semver "$v"; then
    fail "is_valid_semver accepted invalid version '$v'"
  else
    ok "is_valid_semver rejects '$v'"
  fi
done

if semver_gt "0.5.0" "0.4.0"; then ok "semver_gt: 0.5.0 > 0.4.0"; else fail "semver_gt: 0.5.0 > 0.4.0"; fi
if semver_gt "1.0.0" "0.4.9"; then ok "semver_gt: 1.0.0 > 0.4.9"; else fail "semver_gt: 1.0.0 > 0.4.9"; fi
if semver_gt "0.4.0" "0.4.0"; then fail "semver_gt: 0.4.0 not > itself"; else ok "semver_gt: 0.4.0 not > itself"; fi
if semver_gt "0.3.9" "0.4.0"; then fail "semver_gt: 0.3.9 not > 0.4.0"; else ok "semver_gt: 0.3.9 not > 0.4.0"; fi

# --- CHANGELOG rewrite, in a scratch directory ---
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

cat >"${WORKDIR}/CHANGELOG.md" <<'EOF'
# Changelog

## [Unreleased]

### Added

- Something new

## [0.4.0] - 2026-09-17

Body.

[Unreleased]: https://github.com/dynatrace-oss/kimera/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/dynatrace-oss/kimera/compare/v0.3.1...v0.4.0
EOF

(
  cd "$WORKDIR"
  content=$(changelog_unreleased_content)
  assert_eq "$content" "$(printf '### Added\n\n- Something new')" "changelog_unreleased_content reads the real body"

  rewrite_changelog "0.5.0" "2026-10-12"

  if grep -q '^## \[Unreleased\]$' CHANGELOG.md && ! grep -A2 '^## \[Unreleased\]$' CHANGELOG.md | grep -q 'Something new'; then
    ok "rewrite_changelog leaves [Unreleased] empty"
  else
    fail "rewrite_changelog did not empty [Unreleased]"
  fi

  if grep -q '^## \[0.5.0\] - 2026-10-12$' CHANGELOG.md; then
    ok "rewrite_changelog adds the dated heading"
  else
    fail "rewrite_changelog did not add the dated heading"
  fi

  if grep -A5 '^## \[0.5.0\]' CHANGELOG.md | grep -q 'Something new'; then
    ok "rewrite_changelog moves the Unreleased body under the new heading"
  else
    fail "rewrite_changelog did not move the body"
  fi

  if grep -q '^\[Unreleased\]: https://github.com/dynatrace-oss/kimera/compare/v0.5.0...HEAD$' CHANGELOG.md; then
    ok "rewrite_changelog updates the Unreleased compare link"
  else
    fail "rewrite_changelog did not update the Unreleased compare link"
  fi

  if grep -q '^\[0.5.0\]: https://github.com/dynatrace-oss/kimera/compare/v0.4.0...v0.5.0$' CHANGELOG.md; then
    ok "rewrite_changelog adds the new version's compare link"
  else
    fail "rewrite_changelog did not add the new compare link"
  fi
)

# Empty [Unreleased] is reported as empty content.
cat >"${WORKDIR}/CHANGELOG.md" <<'EOF'
# Changelog

## [Unreleased]

## [0.4.0] - 2026-09-17

Body.
EOF
(
  cd "$WORKDIR"
  content=$(changelog_unreleased_content)
  assert_eq "$content" "" "changelog_unreleased_content is empty when Unreleased has no bullets"
)

# --- pyproject version bump ---
cat >"${WORKDIR}/pyproject.toml" <<'EOF'
[project]
name = "kimera"
version = "0.4.0"

[dependency-groups]
dev = [
    "some-other-version = \"1.0.0\"",
]
EOF
(
  cd "$WORKDIR"
  assert_eq "$(pyproject_version)" "0.4.0" "pyproject_version reads the current version"
  bump_pyproject_version "0.5.0"
  assert_eq "$(pyproject_version)" "0.5.0" "bump_pyproject_version bumps it"
)

# --- end-to-end guard rejections, each in a disposable git repo ---
run_release_expect_failure() {
  local label="$1" version="$2" repo="$3"
  local out status
  set +e
  out=$(cd "$repo" && bash "$RELEASE_SH" "$version" 2>&1)
  status=$?
  set -e
  if [[ "$status" -ne 0 ]]; then
    ok "$label (exit $status: ${out##*$'\n'})"
  else
    fail "$label (expected non-zero exit, got 0)"
  fi
}

make_repo() {
  local repo="$1"
  mkdir -p "$repo"
  (
    cd "$repo"
    git init -q -b main
    git config user.email test@example.com
    git config user.name test
    cat >CHANGELOG.md <<'EOF'
## [Unreleased]

### Added

- A change

## [0.4.0] - 2026-09-17
EOF
    cat >pyproject.toml <<'EOF'
[project]
version = "0.4.0"
EOF
    : >uv.lock
    git add -A
    git commit -q -m init
  )
}

REPO_DIRTY="${WORKDIR}/dirty_repo"
make_repo "$REPO_DIRTY"
echo "uncommitted" >>"${REPO_DIRTY}/README.md"
run_release_expect_failure "dirty working tree rejected" "0.5.0" "$REPO_DIRTY"

REPO_BRANCH="${WORKDIR}/branch_repo"
make_repo "$REPO_BRANCH"
(cd "$REPO_BRANCH" && git checkout -q -b feature/x)
run_release_expect_failure "non-main branch rejected" "0.5.0" "$REPO_BRANCH"

REPO_VERSION="${WORKDIR}/version_repo"
make_repo "$REPO_VERSION"
run_release_expect_failure "invalid semver rejected" "not-a-version" "$REPO_VERSION"
run_release_expect_failure "non-increasing version rejected" "0.4.0" "$REPO_VERSION"
run_release_expect_failure "lower version rejected" "0.3.9" "$REPO_VERSION"

REPO_EMPTY_CL="${WORKDIR}/empty_changelog_repo"
make_repo "$REPO_EMPTY_CL"
(
  cd "$REPO_EMPTY_CL"
  cat >CHANGELOG.md <<'EOF'
## [Unreleased]

## [0.4.0] - 2026-09-17
EOF
  git commit -q -am "empty unreleased"
)
run_release_expect_failure "empty Unreleased section rejected" "0.5.0" "$REPO_EMPTY_CL"

echo
if [[ "$FAILURES" -eq 0 ]]; then
  echo "All checks passed."
  exit 0
else
  echo "${FAILURES} check(s) failed."
  exit 1
fi
