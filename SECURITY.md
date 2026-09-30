# Security Policy

## Supported versions

Kimera is pre-1.0. Only the latest released version receives fixes.

| Version | Supported |
|---|---|
| 0.4.x | yes |
| < 0.4 | no |

## Reporting a vulnerability

Report a security issue in Kimera itself privately via
[GitHub Security Advisories](https://github.com/dynatrace-oss/kimera/security/advisories/new).
Do not open a public issue.

Include the affected version, the environment, and the steps to reproduce.
Expect an acknowledgement within five working days.

## Scope

Kimera executes real Kubernetes attack techniques against clusters you point it at.
A technique doing what it documents is not a vulnerability. In scope are defects that
let Kimera affect a cluster or namespace the operator did not target, leak credentials
it handles, or execute attacker-controlled input from cluster state or LLM output.
