# Security policy

Codex Privacy HUD is a local-first Codex plugin created during a hackathon
and maintained by one person, Yongkang Zou.

The plugin runtime processes data locally and makes no outbound network
requests. Explicit installation can download dependencies, model weights,
and patched Codex builds. Codex itself and connected services have their
own data flows.

Detection is heuristic, monitoring can have gaps, and hosted tools can
bypass local hooks. A denial issued by the plugin does not establish that
the host enforced it. See [Known limits](docs/known-limits.md).

## Supported versions

Only the latest released Privacy HUD plugin version is considered for
security updates. Older versions do not receive maintained security
backports. Patched Codex build tags are separate from plugin versions.

Maintenance is best effort. There is no guaranteed response time, fix
timeline, or support window, and no bounty or CVE issuance commitment.

## Reporting a concern

To reach the maintainer, open a
[public issue](https://github.com/inin-zou/codex-privacy-hud/issues/new)
containing only a request to arrange security reporting.

Issues are public. Do not include vulnerability details, exploit steps,
credentials, personal data, session transcripts, or ledger files in that
initial request.

If the maintainer responds, agree on a suitable reporting channel before
sharing sensitive details. This policy does not promise that a private
reporting channel is available.

For a report shared through an agreed channel, useful information includes
the plugin version, Codex version, operating system, expected and observed
behavior, and a minimal reproduction using synthetic data.
