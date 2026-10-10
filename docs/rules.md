# Rules table

Generated from `internal/triage/catalog.go` by `go test ./internal/triage -update`. Do not edit by hand.

## Stateful resource types

Deleting or replacing these is `critical` (data stores, keys) or `high` (caches, queues, streams, addresses, DNS, registries).

| Cloud | Type | Kind | Lost on destroy | Deletion protection | Makes it worse when true |
|---|---|---|---|---|---|
| AWS | `aws_backup_vault` | backup | recovery points | none | `force_destroy` |
| AWS | `aws_cognito_user_pool` | identity | all users and their credentials | `deletion_protection = "ACTIVE"` |  |
| AWS | `aws_db_instance` | database | all data and automated backups | `deletion_protection = true` | `skip_final_snapshot`, `delete_automated_backups` |
| AWS | `aws_docdb_cluster` | database | all data and automated backups | `deletion_protection = true` | `skip_final_snapshot` |
| AWS | `aws_dynamodb_table` | database | all items (point-in-time backups go with the table) | `deletion_protection_enabled = true` |  |
| AWS | `aws_ebs_volume` | disk | the volume contents | none |  |
| AWS | `aws_ecr_repository` | registry | all images | none | `force_delete` |
| AWS | `aws_efs_file_system` | filesystem | all files | none |  |
| AWS | `aws_eip` | address | the address; allow-lists and DNS that point at it break | none |  |
| AWS | `aws_elasticache_cluster` | cache | the cached data set | none |  |
| AWS | `aws_elasticache_replication_group` | cache | the cached data set | none |  |
| AWS | `aws_fsx_lustre_file_system` | filesystem | all files | none |  |
| AWS | `aws_kinesis_stream` | stream | records still in retention | none |  |
| AWS | `aws_kms_key` | key | the key material; anything encrypted with it becomes unreadable | none |  |
| AWS | `aws_memorydb_cluster` | database | all data and automated backups | none |  |
| AWS | `aws_msk_cluster` | stream | all topics and records | none |  |
| AWS | `aws_neptune_cluster` | database | all data and automated backups | `deletion_protection = true` | `skip_final_snapshot` |
| AWS | `aws_opensearch_domain` | search | all indices | none |  |
| AWS | `aws_rds_cluster` | database | all data and automated backups | `deletion_protection = true` | `skip_final_snapshot` |
| AWS | `aws_rds_global_cluster` | database | all data and automated backups | `deletion_protection = true` |  |
| AWS | `aws_redshift_cluster` | warehouse | all data and automated backups | none | `skip_final_snapshot` |
| AWS | `aws_route53_zone` | dns | the zone and its name-server delegation | none | `force_destroy` |
| AWS | `aws_s3_bucket` | bucket | all objects | none | `force_destroy` |
| AWS | `aws_secretsmanager_secret` | secret | the stored secret values | none |  |
| AWS | `aws_sqs_queue` | queue | messages not yet consumed | none |  |
| Azure | `azurerm_cosmosdb_account` | database | every database and container in the account | none |  |
| Azure | `azurerm_eventhub_namespace` | stream | events still in retention | none |  |
| Azure | `azurerm_key_vault` | key | all keys, secrets and certificates in the vault | `purge_protection_enabled = %!q(bool=true)` |  |
| Azure | `azurerm_key_vault_key` | key | the key material; anything encrypted with it becomes unreadable | none |  |
| Azure | `azurerm_key_vault_secret` | secret | the stored secret values | none |  |
| Azure | `azurerm_managed_disk` | disk | the volume contents | none |  |
| Azure | `azurerm_mssql_database` | database | all data and automated backups | none |  |
| Azure | `azurerm_mssql_server` | database | every database on the server | none |  |
| Azure | `azurerm_mysql_flexible_server` | database | all data and automated backups | none |  |
| Azure | `azurerm_postgresql_flexible_server` | database | all data and automated backups | none |  |
| Azure | `azurerm_public_ip` | address | the address; allow-lists and DNS that point at it break | none |  |
| Azure | `azurerm_recovery_services_vault` | backup | recovery points | none |  |
| Azure | `azurerm_redis_cache` | cache | the cached data set | none |  |
| Azure | `azurerm_servicebus_namespace` | queue | messages not yet consumed | none |  |
| Azure | `azurerm_storage_account` | storage account | all blobs, files, queues and tables in the account | none |  |
| Azure | `azurerm_storage_container` | bucket | all blobs in the container | none |  |
| Google Cloud | `google_alloydb_cluster` | database | all data and automated backups | none |  |
| Google Cloud | `google_bigquery_dataset` | warehouse | all tables in the dataset | none | `delete_contents_on_destroy` |
| Google Cloud | `google_bigquery_table` | warehouse | the table data | `deletion_protection = true` |  |
| Google Cloud | `google_bigtable_instance` | database | all data and automated backups | `deletion_protection = true` |  |
| Google Cloud | `google_bigtable_table` | database | all data and automated backups | none |  |
| Google Cloud | `google_compute_address` | address | the address; allow-lists and DNS that point at it break | none |  |
| Google Cloud | `google_compute_disk` | disk | the volume contents | none |  |
| Google Cloud | `google_compute_global_address` | address | the address; allow-lists and DNS that point at it break | none |  |
| Google Cloud | `google_compute_region_disk` | disk | the volume contents | none |  |
| Google Cloud | `google_container_cluster` | cluster | every workload and persistent volume in the cluster | `deletion_protection = true` |  |
| Google Cloud | `google_filestore_instance` | filesystem | all files | none |  |
| Google Cloud | `google_firestore_database` | database | all data and automated backups | `delete_protection_state = "DELETE_PROTECTION_ENABLED"` |  |
| Google Cloud | `google_kms_crypto_key` | key | the key material; anything encrypted with it becomes unreadable | none |  |
| Google Cloud | `google_kms_key_ring` | key | the key ring (key rings cannot be deleted, only abandoned) | none |  |
| Google Cloud | `google_pubsub_subscription` | queue | messages not yet consumed | none |  |
| Google Cloud | `google_redis_instance` | cache | the cached data set | none |  |
| Google Cloud | `google_secret_manager_secret` | secret | the stored secret values | none |  |
| Google Cloud | `google_spanner_database` | database | all data and automated backups | `deletion_protection = true` |  |
| Google Cloud | `google_spanner_instance` | database | all data and automated backups | none |  |
| Google Cloud | `google_sql_database` | database | all data and automated backups | none |  |
| Google Cloud | `google_sql_database_instance` | database | all data and automated backups | `deletion_protection = true` |  |
| Google Cloud | `google_storage_bucket` | bucket | all objects | none | `force_destroy` |

## Privileged roles and policies

- AWS managed policies: `AdministratorAccess`, `IAMFullAccess`, `PowerUserAccess` (`AdministratorAccess` is critical, `*FullAccess` is medium)
- AWS privilege-escalation actions: `iam:attachrolepolicy`, `iam:attachuserpolicy`, `iam:createaccesskey`, `iam:createloginprofile`, `iam:createpolicyversion`, `iam:passrole`, `iam:putrolepolicy`, `iam:putuserpolicy`, `iam:setdefaultpolicyversion`, `iam:updateassumerolepolicy`, `iam:updateloginprofile`, `lambda:updatefunctioncode`, `sts:assumerole`
- Google Cloud roles: `roles/cloudkms.admin`, `roles/editor`, `roles/iam.securityAdmin`, `roles/iam.serviceAccountAdmin`, `roles/iam.serviceAccountTokenCreator`, `roles/iam.serviceAccountUser`, `roles/iam.workloadIdentityPoolAdmin`, `roles/owner`, `roles/resourcemanager.organizationAdmin`, `roles/resourcemanager.projectIamAdmin`, `roles/storage.admin`
- Azure roles: `Contributor`, `Key Vault Administrator`, `Owner`, `Role Based Access Control Administrator`, `Storage Account Contributor`, `User Access Administrator`

## Sensitive ports

World-open ingress on these, or on all ports, is critical; other world-open ports are medium.

- 22 SSH
- 23 Telnet
- 445 SMB
- 1433 SQL Server
- 1521 Oracle
- 2375 Docker API
- 2379 etcd
- 3306 MySQL
- 3389 RDP
- 5432 PostgreSQL
- 5601 Kibana
- 5900 VNC
- 6379 Redis
- 9092 Kafka
- 9200 Elasticsearch
- 11211 Memcached
- 27017 MongoDB
