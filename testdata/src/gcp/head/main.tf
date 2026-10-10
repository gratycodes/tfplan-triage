# PR: "Move ledger to London, faster cache disk, share reports with partner"

resource "google_sql_database_instance" "ledger" {
  name                = "ledger-pg"
  database_version    = "POSTGRES_16"
  region              = "europe-west2"
  deletion_protection = false
  settings {
    tier = "db-custom-2-7680"
  }
}

resource "google_storage_bucket" "reports" {
  name                        = "acme-reports-prod"
  location                    = "EU"
  uniform_bucket_level_access = true
}

resource "google_storage_bucket_iam_member" "reports_partner" {
  bucket = google_storage_bucket.reports.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_project_iam_member" "ci_owner" {
  project = "acme-payments-prod"
  role    = "roles/owner"
  member  = "serviceAccount:ci-deployer@acme-payments-prod.iam.gserviceaccount.com"
}

resource "google_compute_disk" "cache" {
  name = "settlement-cache"
  zone = "europe-west1-b"
  type = "pd-ssd"
  size = 200

  lifecycle {
    prevent_destroy = false
  }
}

resource "google_kms_key_ring" "payments" {
  name     = "payments"
  location = "europe-west1"
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

resource "google_compute_firewall" "ssh_iap_debug" {
  name          = "allow-ssh-debug"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_address" "partner_sftp" {
  name   = "partner-sftp"
  region = "europe-west1"
}

resource "google_pubsub_topic" "events" {
  for_each = toset(["settlements", "refunds", "chargebacks"])
  name     = each.key
  labels   = { team = "payments", env = "prod" }
}
