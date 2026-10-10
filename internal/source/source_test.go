package source

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPreventDestroy(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "main.tf", `
resource "aws_db_instance" "guarded" {
  lifecycle { prevent_destroy = true }
}
resource "aws_db_instance" "explicit_off" {
  lifecycle {
    prevent_destroy = false
  }
}
resource "aws_s3_bucket" "plain" {}
resource "aws_s3_bucket" "from_var" {
  lifecycle { prevent_destroy = var.protect }
}
module "db" {
  source = "./modules/db"
}
module "remote" {
  source  = "terraform-aws-modules/rds/aws"
  version = "6.0.0"
}
`)
	write(t, dir, "modules/db/main.tf", `
resource "google_sql_database_instance" "this" {
  lifecycle { prevent_destroy = true }
}
module "inner" { source = "../inner" }
`)
	write(t, dir, "modules/inner/main.tf", `resource "google_compute_disk" "d" {}`)

	got, err := PreventDestroy(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"aws_db_instance.guarded":                      true,
		"aws_db_instance.explicit_off":                 false,
		"aws_s3_bucket.plain":                          false,
		"module.db.google_sql_database_instance.this":  true,
		"module.db.module.inner.google_compute_disk.d": false,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if g, ok := got[k]; !ok || g != v {
			t.Errorf("%s: got %v,%v want %v", k, g, ok, v)
		}
	}
	if _, ok := got["aws_s3_bucket.from_var"]; ok {
		t.Error("a variable is not a literal and must stay unknown")
	}
}

func TestPreventDestroyErrors(t *testing.T) {
	if _, err := PreventDestroy(t.TempDir()); err == nil {
		t.Error("empty dir should error")
	}
	dir := t.TempDir()
	write(t, dir, "bad.tf", `resource "x" "y" {`)
	if _, err := PreventDestroy(dir); err == nil {
		t.Error("parse error should surface")
	}
}

func TestFixtureSource(t *testing.T) {
	got, err := PreventDestroy("../../testdata/src/aws/head")
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"aws_s3_bucket.statements", "module.ledger_db.aws_db_instance.this", "aws_cloudwatch_log_group.service"} {
		if v, ok := got[addr]; !ok || v {
			t.Errorf("%s: got %v,%v", addr, v, ok)
		}
	}
}
