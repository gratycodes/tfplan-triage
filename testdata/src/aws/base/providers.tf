terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "6.15.0" }
  }
}

# Synthetic credentials: plans are made with -refresh=false and never call AWS.
provider "aws" {
  region                      = "eu-west-1"
  access_key                  = "synthetic"
  secret_key                  = "synthetic"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}
