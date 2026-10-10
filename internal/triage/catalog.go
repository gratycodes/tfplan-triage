package triage

// This file is the rules table. Adding coverage for a new resource type is
// a one-line change here, or an entry in .tfplan-triage.yml (see Config)
// for types your organisation owns.

// Stateful describes a resource type whose destruction loses data or
// something that cannot be recreated identically (keys, addresses).
type Stateful struct {
	Kind string `yaml:"kind" json:"kind"`
	// Loss says what goes away, in reviewer terms.
	Loss string `yaml:"loss" json:"loss"`
	// GuardAttr is the provider-side deletion protection attribute, if any.
	GuardAttr string `yaml:"guard_attr" json:"guard_attr,omitempty"`
	// GuardOn is the value of GuardAttr that means "protected".
	// Defaults to true.
	GuardOn any `yaml:"guard_on" json:"guard_on,omitempty"`
	// Amplifiers are boolean attributes that make a destroy worse when
	// true, such as force_destroy on buckets.
	Amplifiers []string `yaml:"amplifiers" json:"amplifiers,omitempty"`
}

func st(kind, loss, guard string, amplifiers ...string) Stateful {
	return Stateful{Kind: kind, Loss: loss, GuardAttr: guard, Amplifiers: amplifiers}
}

func stOn(kind, loss, guard string, on any) Stateful {
	return Stateful{Kind: kind, Loss: loss, GuardAttr: guard, GuardOn: on}
}

const (
	lossRows    = "all data and automated backups"
	lossObjects = "all objects"
	lossKey     = "the key material; anything encrypted with it becomes unreadable"
	lossVolume  = "the volume contents"
	lossSecret  = "the stored secret values"
	lossMsgs    = "messages not yet consumed"
	lossIP      = "the address; allow-lists and DNS that point at it break"
)

// StatefulTypes is the built-in table, keyed by resource type.
var StatefulTypes = map[string]Stateful{
	// AWS
	"aws_db_instance":                   st("database", lossRows, "deletion_protection", "skip_final_snapshot", "delete_automated_backups"),
	"aws_rds_cluster":                   st("database", lossRows, "deletion_protection", "skip_final_snapshot"),
	"aws_rds_global_cluster":            st("database", lossRows, "deletion_protection"),
	"aws_docdb_cluster":                 st("database", lossRows, "deletion_protection", "skip_final_snapshot"),
	"aws_neptune_cluster":               st("database", lossRows, "deletion_protection", "skip_final_snapshot"),
	"aws_dynamodb_table":                st("database", "all items (point-in-time backups go with the table)", "deletion_protection_enabled"),
	"aws_redshift_cluster":              st("warehouse", lossRows, "", "skip_final_snapshot"),
	"aws_elasticache_replication_group": st("cache", "the cached data set", ""),
	"aws_elasticache_cluster":           st("cache", "the cached data set", ""),
	"aws_memorydb_cluster":              st("database", lossRows, ""),
	"aws_opensearch_domain":             st("search", "all indices", ""),
	"aws_s3_bucket":                     st("bucket", lossObjects, "", "force_destroy"),
	"aws_ebs_volume":                    st("disk", lossVolume, ""),
	"aws_efs_file_system":               st("filesystem", "all files", ""),
	"aws_fsx_lustre_file_system":        st("filesystem", "all files", ""),
	"aws_kms_key":                       st("key", lossKey, ""),
	"aws_secretsmanager_secret":         st("secret", lossSecret, ""),
	"aws_sqs_queue":                     st("queue", lossMsgs, ""),
	"aws_kinesis_stream":                st("stream", "records still in retention", ""),
	"aws_msk_cluster":                   st("stream", "all topics and records", ""),
	"aws_backup_vault":                  st("backup", "recovery points", "", "force_destroy"),
	"aws_ecr_repository":                st("registry", "all images", "", "force_delete"),
	"aws_cognito_user_pool":             stOn("identity", "all users and their credentials", "deletion_protection", "ACTIVE"),
	"aws_route53_zone":                  st("dns", "the zone and its name-server delegation", "", "force_destroy"),
	"aws_eip":                           st("address", lossIP, ""),

	// Google Cloud
	"google_sql_database_instance":  st("database", lossRows, "deletion_protection"),
	"google_sql_database":           st("database", lossRows, ""),
	"google_alloydb_cluster":        st("database", lossRows, ""),
	"google_spanner_instance":       st("database", lossRows, ""),
	"google_spanner_database":       st("database", lossRows, "deletion_protection"),
	"google_bigtable_instance":      st("database", lossRows, "deletion_protection"),
	"google_bigtable_table":         st("database", lossRows, ""),
	"google_firestore_database":     stOn("database", lossRows, "delete_protection_state", "DELETE_PROTECTION_ENABLED"),
	"google_bigquery_dataset":       st("warehouse", "all tables in the dataset", "", "delete_contents_on_destroy"),
	"google_bigquery_table":         st("warehouse", "the table data", "deletion_protection"),
	"google_redis_instance":         st("cache", "the cached data set", ""),
	"google_storage_bucket":         st("bucket", lossObjects, "", "force_destroy"),
	"google_compute_disk":           st("disk", lossVolume, ""),
	"google_compute_region_disk":    st("disk", lossVolume, ""),
	"google_filestore_instance":     st("filesystem", "all files", ""),
	"google_kms_crypto_key":         st("key", lossKey, ""),
	"google_kms_key_ring":           st("key", "the key ring (key rings cannot be deleted, only abandoned)", ""),
	"google_secret_manager_secret":  st("secret", lossSecret, ""),
	"google_pubsub_subscription":    st("queue", lossMsgs, ""),
	"google_compute_address":        st("address", lossIP, ""),
	"google_compute_global_address": st("address", lossIP, ""),
	"google_container_cluster":      st("cluster", "every workload and persistent volume in the cluster", "deletion_protection"),

	// Azure
	"azurerm_storage_account":            st("storage account", "all blobs, files, queues and tables in the account", ""),
	"azurerm_storage_container":          st("bucket", "all blobs in the container", ""),
	"azurerm_mssql_server":               st("database", "every database on the server", ""),
	"azurerm_mssql_database":             st("database", lossRows, ""),
	"azurerm_postgresql_flexible_server": st("database", lossRows, ""),
	"azurerm_mysql_flexible_server":      st("database", lossRows, ""),
	"azurerm_cosmosdb_account":           st("database", "every database and container in the account", ""),
	"azurerm_redis_cache":                st("cache", "the cached data set", ""),
	"azurerm_managed_disk":               st("disk", lossVolume, ""),
	"azurerm_key_vault":                  stOn("key", "all keys, secrets and certificates in the vault", "purge_protection_enabled", true),
	"azurerm_key_vault_key":              st("key", lossKey, ""),
	"azurerm_key_vault_secret":           st("secret", lossSecret, ""),
	"azurerm_servicebus_namespace":       st("queue", lossMsgs, ""),
	"azurerm_eventhub_namespace":         st("stream", "events still in retention", ""),
	"azurerm_recovery_services_vault":    st("backup", "recovery points", ""),
	"azurerm_public_ip":                  st("address", lossIP, ""),
}

// amplifierNotes explain why an amplifier attribute set to true makes a
// destroy worse.
var amplifierNotes = map[string]string{
	"force_destroy":              "the provider empties it first, so a non-empty %s is deleted without an error",
	"force_delete":               "the provider deletes it even when it still holds data",
	"delete_contents_on_destroy": "every table in the %s is deleted with it",
	"skip_final_snapshot":        "no final snapshot is taken before the %s is deleted",
	"delete_automated_backups":   "automated backups are deleted with the %s (the provider default)",
}

// PrivilegedAWSPolicies are managed policies that grant (near) admin.
var PrivilegedAWSPolicies = map[string]bool{
	"AdministratorAccess": true,
	"PowerUserAccess":     true,
	"IAMFullAccess":       true,
}

// PrivilegedGCPRoles are basic or IAM-admin roles that are broad enough to
// deserve a second reviewer wherever they are granted.
var PrivilegedGCPRoles = map[string]bool{
	"roles/owner":                             true,
	"roles/editor":                            true,
	"roles/iam.securityAdmin":                 true,
	"roles/iam.serviceAccountAdmin":           true,
	"roles/iam.serviceAccountTokenCreator":    true,
	"roles/iam.serviceAccountUser":            true,
	"roles/iam.workloadIdentityPoolAdmin":     true,
	"roles/resourcemanager.projectIamAdmin":   true,
	"roles/resourcemanager.organizationAdmin": true,
	"roles/storage.admin":                     true,
	"roles/cloudkms.admin":                    true,
}

// PrivilegedAzureRoles are built-in roles that can change resources or
// grant access to others.
var PrivilegedAzureRoles = map[string]bool{
	"Owner":                     true,
	"Contributor":               true,
	"User Access Administrator": true,
	"Role Based Access Control Administrator": true,
	"Key Vault Administrator":                 true,
	"Storage Account Contributor":             true,
}

// EscalationActions are AWS actions that let a principal grant itself more
// access, see https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
var EscalationActions = map[string]bool{
	"iam:passrole":                true,
	"iam:createpolicyversion":     true,
	"iam:setdefaultpolicyversion": true,
	"iam:attachrolepolicy":        true,
	"iam:attachuserpolicy":        true,
	"iam:putrolepolicy":           true,
	"iam:putuserpolicy":           true,
	"iam:createaccesskey":         true,
	"iam:updateassumerolepolicy":  true,
	"iam:createloginprofile":      true,
	"iam:updateloginprofile":      true,
	"sts:assumerole":              true,
	"lambda:updatefunctioncode":   true,
}

// SensitivePorts are ports that should essentially never be open to the
// internet: remote administration, databases, caches and brokers.
var SensitivePorts = map[int]string{
	22:    "SSH",
	23:    "Telnet",
	445:   "SMB",
	1433:  "SQL Server",
	1521:  "Oracle",
	2375:  "Docker API",
	2379:  "etcd",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5601:  "Kibana",
	5900:  "VNC",
	6379:  "Redis",
	9092:  "Kafka",
	9200:  "Elasticsearch",
	11211: "Memcached",
	27017: "MongoDB",
}

// noiseAttrs are attributes whose change alone rarely matters for review.
var noiseAttrs = map[string]bool{
	"tags":             true,
	"tags_all":         true,
	"labels":           true,
	"effective_labels": true,
	"terraform_labels": true,
	"description":      true,
}
