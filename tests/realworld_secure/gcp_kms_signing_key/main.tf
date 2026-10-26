resource "google_kms_key_ring" "release" {
  name     = "release"
  location = "global"
}

resource "google_kms_crypto_key" "signing" {
  name     = "artefact-signing"
  key_ring = google_kms_key_ring.release.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm = "EC_SIGN_P256_SHA256"
  }

  lifecycle {
    prevent_destroy = true
  }
}
