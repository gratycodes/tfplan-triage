terraform {
  required_providers {
    local  = { source = "hashicorp/local", version = "2.5.3" }
    random = { source = "hashicorp/random", version = "3.7.2" }
  }
}

resource "random_password" "webhook_secret" {
  length  = 32
  special = false
  keepers = { rotation = "2026-q3" }
}

resource "local_file" "feature_flags" {
  filename = "${path.module}/out/feature-flags.json"
  content  = jsonencode({ instant_payouts = false })
}

resource "local_file" "routing" {
  filename = "${path.module}/out/routing.yaml"
  content  = "primary: eu-west-1\n"
}

resource "terraform_data" "release" {
  input = "v41"
}
