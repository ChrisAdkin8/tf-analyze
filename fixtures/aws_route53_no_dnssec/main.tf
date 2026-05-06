resource "aws_route53_zone" "no_dnssec" {
  name = "example.com"
  # No aws_route53_key_signing_key resource in this repo — DNSSEC not
  # configured. DNS responses can be spoofed.
}
