## `--attack-graph` and the GitHub Action gate no longer pass unchecked findings

- **`--attack-graph` demotion**: a finding on a resource the graph found
  unreachable from the internet drops one urgency tier. The graph only
  decides exposure for network-facing types (instances, databases, load
  balancers, security groups, ...), so every other type (an IAM grant, a
  logging setting) counted as unreachable and was always demoted: a
  `roles/owner` grant failed `--fail-on HIGH` without the flag and passed
  with it. Only a resource whose exposure the graph models is demoted
  now, including one behind a security group. Graph nodes carry a new
  `exposure_modelled` field.
- **Action gate**: the Action gates its own JSON report rather than
  passing `--fail-on`, so it missed two things `--fail-on` fails on: a
  rule check that ran out of time and a file that couldn't be read. Both
  now fail the job. The JSON summary carries `unreadable_files` when a
  file couldn't be read. The `integrations/github-action.yml` template
  gate also fails on these and on `nothing_scanned`.
