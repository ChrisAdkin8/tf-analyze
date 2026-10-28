## ATT&CK tags name only the techniques a rule really bears on

- **T1195 is for mutable dependencies only**: Supply Chain Compromise was on
  27 active rules, including advice-only rules (`MOD-REUSE-*`), "module is
  behind latest" (`MOD-STALE-001`), Terraform CLI version floors
  (`ROB-VERSION-001/002`) and end-of-life / deprecation checks. It now stays
  only on rules that find an unpinned, mutable or unverified module,
  provider, chart, image or build (11 rules). End-of-life runtimes on
  internet-facing services (Function Apps, Cloud Functions, App Service, AKS)
  are tagged T1190 instead, like `STK-K8S-VERSION-001` already was.
- **Other broad techniques reviewed**: T1530, T1190, T1078.004, T1485 and
  T1562.008 were checked rule by rule against their ATT&CK definitions.
  Logging rules no longer claim T1530 or T1190 (they are T1562.008, like the
  other "logging is off" rules); availability rules (auto-healing, failover,
  maintenance windows, load-balancer deletion) no longer claim Data
  Destruction; Kubernetes RBAC rules use `T1078` / `T1078.001` rather than
  Cloud Accounts; Key Vault network exposure is T1555.006 (Cloud Secrets
  Management Stores) rather than T1530.
- **The MITRE coverage badge goes down** (80% → 74%) because 23 active rules
  that had only a loose tag now have none. That number now counts rules with
  a real mapping.
- **The tags can't creep back**: `scripts/apply_mitre.py`'s manifest is
  updated to match, and `tests/test_mitre_precision.py` pins the advice-only
  rules that must not carry T1195, checks the manifest matches the
  catalogue, and caps any one technique at 35 active rules.
