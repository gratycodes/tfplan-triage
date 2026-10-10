variable "name" { type = string }
variable "encrypted" { type = bool }

resource "aws_kms_key" "legacy" {
  description             = "${var.name} legacy key"
  deletion_window_in_days = 30
}

resource "aws_db_instance" "this" {
  identifier                  = "${var.name}-pg"
  engine                      = "postgres"
  engine_version              = "16.4"
  instance_class              = "db.t4g.medium"
  allocated_storage           = 50
  username                    = "ledger_admin"
  manage_master_user_password = true
  storage_encrypted           = var.encrypted
  deletion_protection         = false
  skip_final_snapshot         = true
}
