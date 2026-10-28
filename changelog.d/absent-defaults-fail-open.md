## Leaving out a setting counts when the provider default is unsafe

Findings change: new findings where a setting is left out and the provider
default is the unsafe one. Terragoat gcp 112 → 113.

- **Cosmos DB** (`SEC-AZURE-COSMOS-001`): `public_network_access_enabled`
  defaults to `true` in the azurerm provider, so leaving it out now fires.
- **Cloud SQL** (`SEC-GCP-SQL-PUBLIC-001`): `ip_configuration.ipv4_enabled`
  defaults to `true` in the google provider, with or without a
  `private_network`, so leaving it (or `ip_configuration`) out now fires.
- **Project SSH keys** (`SEC-GCP-COMPUTE-PROJSSH-001`): `metadata` that
  doesn't set `block-project-ssh-keys` still allows project-wide keys, so
  it now fires like a missing `metadata` did.
- **ClusterRole escalation verbs** (`SEC-K8S-RBAC-001`): `bind`,
  `escalate` and `impersonate` were checked on Roles only; ClusterRoles
  are now checked too.
- **Helm `verify`** stays explicit-only: it defaults to `false`, but most
  public charts ship no provenance file, so the rule now says why it
  doesn't fire on an absent `verify`.
