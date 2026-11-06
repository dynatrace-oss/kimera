# Releasing Kimera

## Prerequisites, one time

1. Trusted publishing registered on the PyPI project `kimera`:

   | Field | Value |
   |---|---|
   | Owner | `dynatrace-oss` |
   | Repository | `kimera` |
   | Workflow | `publish.yml` |
   | Environment | `pypi` |

2. Two GitHub Environments on `dynatrace-oss/kimera`, each with **required reviewers**.
   The `pypi` environment allows deployments from `main` and from `v*` tags.
   `publish.yml` rejects a tag whose commit is not on `main`.
   TestPyPI still reads `TEST_PYPI_API_TOKEN` from the `testpypi` environment.
   That token stays on the environment, not on the repository.

## Cut a release

1. Check out `main` with a clean working tree.
2. Run `scripts/release.sh X.Y.Z`. It verifies the tree is clean, you're on `main`, the
   `[Unreleased]` section is non-empty, and `X.Y.Z` is a valid semver greater than the current
   `pyproject.toml` version; then it moves `[Unreleased]` under a dated `[X.Y.Z]` heading, adds its
   compare link, bumps `version`, runs `uv lock`, creates `release/X.Y.Z`, and commits exactly
   `CHANGELOG.md`, `pyproject.toml` and `uv.lock`.
3. Push the branch, open a PR against `main`, and merge it.
4. Tag the merge commit, annotated: `git tag -a vX.Y.Z -m "Kimera vX.Y.Z" && git push origin vX.Y.Z`.
   Tags are annotated and point at the release merge commit on `main`. `v0.2.0` predates this rule
   and sits on an unrelated commit.
5. The tag push starts `publish.yml`. Approve the `pypi` environment job when the run pauses.
6. The `smoke-test` job installs from PyPI on 3.11 and 3.13 and exercises the console scripts.
   Watch it; it is the check that the packaged YAML and Jinja files shipped.

## Rehearse on TestPyPI first

Run `publish.yml` via **workflow_dispatch** with `target: testpypi` before tagging, then install
from TestPyPI into a clean venv and run `kimera --version`. TestPyPI consumes the version number
on its own index only.

## Version numbers are spent, not reserved

PyPI never permits re-uploading a version, successful or not. A broken `X.Y.Z` is fixed by
releasing `X.Y.Z+1`, never by retrying the tag.

## Token rotation

PyPI uploads use [Trusted Publishing](https://docs.pypi.org/trusted-publishers/).
There is no `PYPI_API_TOKEN`. Revoke any leftover project token once a release
published this way has succeeded.
TestPyPI still uses `TEST_PYPI_API_TOKEN`. Rotate that token yearly.
