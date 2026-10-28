## The HCP run task follows the plan download redirect

- **Plan download**: HCP's `plan_json_api_url` answers a successful request
  with a `307` to a one-minute signed URL on `archivist.terraform.io`, and the
  server refused every redirect, so each real run reported "cannot fetch
  plan-json (307)". It now follows that one hop after checking the target
  like the request's own URLs (https, allow-listed host, public address).
  `archivist.terraform.io` is allowed by default, and
  `TFA_RUN_TASK_ALLOWED_REDIRECT_HOSTS` adds others. The bearer token goes
  along only when the host is unchanged (Terraform Enterprise redirects to
  itself); the signed URL carries its own authorisation. A second redirect
  is not followed.
