resource "google_sql_database_instance" "ledger" {
  name                = "ledger-pg"
  database_version    = "POSTGRES_16"
  region              = "europe-west1"
  deletion_protection = true
  settings {
    tier = "db-custom-2-7680"
  }
}

resource "google_storage_bucket" "exports" {
  name          = "acme-exports-prod"
  location      = "EU"
  force_destroy = true
}

resource "google_storage_bucket" "reports" {
  name                        = "acme-reports-prod"
  location                    = "EU"
  uniform_bucket_level_access = true
}

resource "google_compute_disk" "cache" {
  name = "settlement-cache"
  zone = "europe-west1-b"
  type = "pd-standard"
  size = 200
}

resource "google_kms_key_ring" "payments" {
  name     = "payments"
  location = "europe-west1"
}

resource "google_kms_crypto_key" "card_vault" {
  name     = "card-vault"
  key_ring = google_kms_key_ring.payments.id
}

resource "google_compute_firewall" "internal" {
  name          = "allow-internal"
  network       = "default"
  source_ranges = ["10.128.0.0/9"]
  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }
}

resource "google_pubsub_topic" "events" {
  for_each = toset(["settlements", "refunds", "chargebacks"])
  name     = each.key
  labels   = { team = "payments" }
}
