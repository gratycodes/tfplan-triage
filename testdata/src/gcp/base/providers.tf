terraform {
  required_providers {
    google = { source = "hashicorp/google", version = "6.50.0" }
  }
}

# Synthetic token: plans are made with -refresh=false and never call GCP.
provider "google" {
  project      = "acme-payments-prod"
  region       = "europe-west1"
  access_token = "synthetic"
}
