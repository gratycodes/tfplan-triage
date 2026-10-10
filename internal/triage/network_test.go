package triage

import "testing"

func TestNetworkExposure(t *testing.T) {
	cases := []struct {
		name, typ, after string
		sev              Severity
		want             string
	}{
		{"aws sg inline ssh", "aws_security_group", `{"ingress":[{"cidr_blocks":["0.0.0.0/0"],"from_port":22,"to_port":22,"protocol":"tcp"}]}`, Critical, "port 22 (SSH)"},
		{"aws sg all traffic", "aws_security_group", `{"ingress":[{"cidr_blocks":["0.0.0.0/0"],"from_port":0,"to_port":0,"protocol":"-1"}]}`, Critical, "all ports"},
		{"aws sg rule ipv6 range", "aws_security_group_rule", `{"type":"ingress","ipv6_cidr_blocks":["::/0"],"from_port":7000,"to_port":7100,"protocol":"tcp"}`, Medium, "ports 7000-7100"},
		{"aws sg range covering db", "aws_security_group_rule", `{"type":"ingress","cidr_blocks":["0.0.0.0/0"],"from_port":3000,"to_port":3400,"protocol":"tcp"}`, Critical, "3306 MySQL"},
		{"aws ingress rule https", "aws_vpc_security_group_ingress_rule", `{"cidr_ipv4":"0.0.0.0/0","from_port":443,"to_port":443,"ip_protocol":"tcp"}`, Medium, "port 443"},
		{"aws ingress rule all", "aws_vpc_security_group_ingress_rule", `{"cidr_ipv4":"0.0.0.0/0","from_port":null,"to_port":null,"ip_protocol":"-1"}`, Critical, "all ports"},
		{"s3 public access block", "aws_s3_bucket_public_access_block", `{"block_public_acls":true,"block_public_policy":false,"ignore_public_acls":true,"restrict_public_buckets":true}`, High, "block_public_policy = false"},
		{"s3 acl", "aws_s3_bucket_acl", `{"acl":"public-read"}`, Critical, "public-read"},
		{"rds public", "aws_db_instance", `{"publicly_accessible":true}`, High, "publicly_accessible"},
		{"lambda url", "aws_lambda_function_url", `{"authorization_type":"NONE"}`, High, "NONE"},
		{"eks endpoint", "aws_eks_cluster", `{"vpc_config":[{"endpoint_public_access":true,"public_access_cidrs":["0.0.0.0/0"]}]}`, High, "EKS API"},
		{"lb", "aws_lb", `{"internal":false}`, Medium, "internet-facing"},
		{"gcp firewall all", "google_compute_firewall", `{"direction":"INGRESS","source_ranges":["0.0.0.0/0"],"allow":[{"protocol":"tcp","ports":[]}]}`, Critical, "all ports"},
		{"gcp firewall rdp", "google_compute_firewall", `{"source_ranges":["0.0.0.0/0"],"allow":[{"protocol":"tcp","ports":["3389"]}]}`, Critical, "RDP"},
		{"gcp instance", "google_compute_instance", `{"network_interface":[{"access_config":[{"nat_ip":""}]}]}`, Medium, "external IP"},
		{"cloud sql", "google_sql_database_instance", `{"settings":[{"ip_configuration":[{"authorized_networks":[{"value":"0.0.0.0/0"}]}]}]}`, Critical, "authorized network"},
		{"azure nsr", "azurerm_network_security_rule", `{"direction":"Inbound","access":"Allow","protocol":"Tcp","source_address_prefix":"Internet","destination_port_range":"22"}`, Critical, "SSH"},
		{"azure nsr prefixes", "azurerm_network_security_rule", `{"direction":"Inbound","access":"Allow","protocol":"*","source_address_prefixes":["0.0.0.0/0"],"destination_port_ranges":["8080-8090"]}`, Critical, "all ports"},
		{"azure nsg inline", "azurerm_network_security_group", `{"security_rule":[{"direction":"Inbound","access":"Allow","protocol":"Tcp","source_address_prefix":"*","destination_port_range":"5432"}]}`, Critical, "PostgreSQL"},
		{"azure container", "azurerm_storage_container", `{"container_access_type":"container"}`, Critical, "anonymous list"},
		{"azure nested public", "azurerm_storage_account", `{"allow_nested_items_to_be_public":true}`, High, "public blob"},
		{"azure sql firewall", "azurerm_mssql_firewall_rule", `{"start_ip_address":"0.0.0.0","end_ip_address":"255.255.255.255"}`, Critical, "every IPv4"},
		{"azure services", "azurerm_postgresql_flexible_server_firewall_rule", `{"start_ip_address":"0.0.0.0","end_ip_address":"0.0.0.0"}`, Medium, "all Azure services"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := change(t, tc.typ, `["create"]`, `null`, tc.after)
			f := one(t, Analyze(p, Options{}), RuleNetworkExposure)
			if f.Severity != tc.sev || !hasDetail(f, tc.want) {
				t.Fatalf("got %s %q %v", f.Severity, f.Title, f.Details)
			}
		})
	}
}

func TestNotExposed(t *testing.T) {
	cases := []struct{ name, typ, after string }{
		{"aws egress", "aws_security_group_rule", `{"type":"egress","cidr_blocks":["0.0.0.0/0"],"from_port":0,"to_port":0,"protocol":"-1"}`},
		{"aws private cidr", "aws_security_group", `{"ingress":[{"cidr_blocks":["10.0.0.0/8"],"from_port":22,"to_port":22,"protocol":"tcp"}]}`},
		{"gcp egress", "google_compute_firewall", `{"direction":"EGRESS","source_ranges":["0.0.0.0/0"],"allow":[{"protocol":"all"}]}`},
		{"gcp disabled", "google_compute_firewall", `{"disabled":true,"source_ranges":["0.0.0.0/0"],"allow":[{"protocol":"tcp","ports":["22"]}]}`},
		{"azure deny", "azurerm_network_security_rule", `{"direction":"Inbound","access":"Deny","source_address_prefix":"*","destination_port_range":"*"}`},
		{"azure outbound", "azurerm_network_security_rule", `{"direction":"Outbound","access":"Allow","source_address_prefix":"*","destination_port_range":"*"}`},
		{"internal address", "google_compute_address", `{"address_type":"INTERNAL"}`},
		{"private container", "azurerm_storage_container", `{"container_access_type":"private"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			none(t, Analyze(change(t, tc.typ, `["create"]`, `null`, tc.after), Options{}), RuleNetworkExposure)
		})
	}
}

func TestExistingExposureIsNotReflagged(t *testing.T) {
	sg := `{"ingress":[{"cidr_blocks":["0.0.0.0/0"],"from_port":443,"to_port":443,"protocol":"tcp"}],"tags":{}}`
	sgTagged := `{"ingress":[{"cidr_blocks":["0.0.0.0/0"],"from_port":443,"to_port":443,"protocol":"tcp"}],"tags":{"a":"b"}}`
	none(t, Analyze(change(t, "aws_security_group", `["update"]`, sg, sgTagged), Options{}), RuleNetworkExposure)

	// Widening an existing world-open rule to SSH is new exposure.
	sgSSH := `{"ingress":[{"cidr_blocks":["0.0.0.0/0"],"from_port":443,"to_port":443,"protocol":"tcp"},{"cidr_blocks":["0.0.0.0/0"],"from_port":22,"to_port":22,"protocol":"tcp"}]}`
	f := one(t, Analyze(change(t, "aws_security_group", `["update"]`, sg, sgSSH), Options{}), RuleNetworkExposure)
	if hasDetail(f, "443") {
		t.Fatalf("existing 443 should not be reported: %+v", f)
	}
}

func TestPublicIPOnlyOnCreate(t *testing.T) {
	one(t, Analyze(change(t, "azurerm_public_ip", `["create"]`, `null`, `{"allocation_method":"Static"}`), Options{}), RuleNetworkExposure)
	none(t, Analyze(change(t, "azurerm_public_ip", `["update"]`, `{"tags":{}}`, `{"tags":{"a":"b"}}`), Options{}), RuleNetworkExposure)
}

func TestExtraSensitivePorts(t *testing.T) {
	p := change(t, "aws_vpc_security_group_ingress_rule", `["create"]`, `null`, `{"cidr_ipv4":"0.0.0.0/0","from_port":8443,"to_port":8443,"ip_protocol":"tcp"}`)
	if f := one(t, Analyze(p, Options{}), RuleNetworkExposure); f.Severity != Medium {
		t.Fatalf("default severity %s", f.Severity)
	}
	f := one(t, Analyze(p, Options{ExtraSensitivePorts: map[int]string{8443: "admin UI"}}), RuleNetworkExposure)
	if f.Severity != Critical || !hasDetail(f, "admin UI") {
		t.Fatalf("%+v", f)
	}
}

func TestParsePorts(t *testing.T) {
	for in, want := range map[string]portRange{"22": {22, 22}, "1000-2000": {1000, 2000}, "*": allPorts, "": allPorts} {
		got, ok := parsePorts(in)
		if !ok || got != want {
			t.Errorf("%q: got %v %v", in, got, ok)
		}
	}
	if _, ok := parsePorts("http"); ok {
		t.Error("named ports are not parsed")
	}
}
