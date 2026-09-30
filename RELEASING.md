# Releasing Kimera

## Prerequisites, one time

1. A PyPI API token scoped to the `kimera` project, and a TestPyPI token.
2. Two GitHub Environments on `dynatrace-oss/kimera`, each with **required reviewers**:

   | Environment | Secret |
   |---|---|
   | `pypi` | `PYPI_API_TOKEN` |
   | `testpypi` | `TEST_PYPI_API_TOKEN` |

   The tokens go on the environment, not on the repository. An environment secret is readable
   only by a job that declares that environment, and those jobs are reviewer-gated. A repository
   secret is readable by every workflow in the repo.

## Cut a release

1. Branch: `git switch -c release/X.Y.Z`.
2. One commit touching exactly `CHANGELOG.md`, `pyproject.toml` and `uv.lock`: move the
   `[Unreleased]` items under a dated `[X.Y.Z]` heading, add its compare link, bump `version`,
   then `uv lock`.
3. Open a PR against `main` and merge it.
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

The upload tokens are long-lived credentials. Rotate them yearly, and replace them with
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/) when convenient: the OIDC exchange
mints a short-lived credential at job runtime and stores no secret in the repository.
