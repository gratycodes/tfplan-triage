package triage

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/gratycodes/tfplan-triage/internal/plan"
)

var worldCIDRs = map[string]bool{
	"0.0.0.0/0": true, "::/0": true, "*": true, "Internet": true, "Any": true, "0.0.0.0": true,
}

// portRange is an inclusive range; all ports is 0-65535.
type portRange struct{ from, to int }

var allPorts = portRange{0, 65535}

func (p portRange) String() string {
	switch {
	case p == allPorts:
		return "all ports"
	case p.from == p.to:
		return "port " + strconv.Itoa(p.from)
	}
	return fmt.Sprintf("ports %d-%d", p.from, p.to)
}

// parsePorts reads "22", "1000-2000", "*" or "" (all).
func parsePorts(s string) (portRange, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return allPorts, true
	}
	lo, hi, isRange := strings.Cut(s, "-")
	a, err := strconv.Atoi(lo)
	if err != nil {
		return portRange{}, false
	}
	if !isRange {
		return portRange{a, a}, true
	}
	b, err := strconv.Atoi(hi)
	if err != nil {
		return portRange{}, false
	}
	return portRange{a, b}, true
}

func num(v any) (int, bool) {
	switch x := v.(type) {
	case fmt.Stringer:
		n, err := strconv.Atoi(x.String())
		return n, err == nil
	case float64:
		return int(x), true
	case string:
		n, err := strconv.Atoi(x)
		return n, err == nil
	}
	return 0, false
}

// exposures maps a stable description of each exposure to its severity.
type exposures map[string]Severity

func (e exposures) add(sev Severity, format string, args ...any) {
	f := fmt.Sprintf(format, args...)
	if cur, ok := e[f]; !ok || sev > cur {
		e[f] = sev
	}
}

// ingress records world-reachable ports. Sensitive ports and all-port
// rules are critical; other ports (typically 80/443) are medium because
// they are often intended, but still worth a look.
func (a *analyzer) ingress(e exposures, source string, ports portRange, protocol string) {
	if p := strings.ToLower(protocol); p == "-1" || p == "all" || p == "*" {
		ports = allPorts
	}
	if ports == allPorts {
		e.add(Critical, "all ports open to the internet (from `%s`)", source)
		return
	}
	var hit []string
	for port, name := range a.sensitivePorts {
		if port >= ports.from && port <= ports.to {
			if ports.from == ports.to {
				hit = append(hit, name)
			} else {
				hit = append(hit, fmt.Sprintf("%d %s", port, name))
			}
		}
	}
	sort.Strings(hit)
	if len(hit) > 0 {
		e.add(Critical, "%s (%s) open to the internet (from `%s`)", ports, strings.Join(hit, ", "), source)
		return
	}
	e.add(Medium, "%s open to the internet (from `%s`)", ports, source)
}

func (a *analyzer) network(rc *plan.ResourceChange) []Finding {
	act := rc.Action()
	if act != plan.Create && act != plan.Update && act != plan.Replace {
		return nil
	}
	before := a.exposures(rc, rc.BeforeMap(), plan.Update)
	after := a.exposures(rc, rc.AfterMap(), act)
	type item struct {
		fact string
		sev  Severity
	}
	var added []item
	for f, sev := range after {
		if old, ok := before[f]; !ok || sev > old {
			added = append(added, item{f, sev})
		}
	}
	if len(added) == 0 {
		return nil
	}
	sort.Slice(added, func(i, j int) bool {
		if added[i].sev != added[j].sev {
			return added[i].sev > added[j].sev
		}
		return added[i].fact < added[j].fact
	})
	title := "Exposes: " + added[0].fact
	if len(added) > 1 {
		title += fmt.Sprintf(" (+%d more)", len(added)-1)
	}
	var d []string
	for _, it := range added[1:] {
		d = append(d, it.fact)
	}
	return []Finding{newFinding(rc, RuleNetworkExposure, added[0].sev, title, d...)}
}

// exposures lists what one side of a change exposes. act tells whether the
// object is being created, which matters for "allocates a public IP".
func (a *analyzer) exposures(rc *plan.ResourceChange, m map[string]any, act plan.Action) exposures {
	e := exposures{}
	if m == nil {
		return e
	}
	switch rc.Type {
	// AWS
	case "aws_security_group":
		for _, r := range plan.Blocks(m, "ingress") {
			a.awsRule(e, r)
		}
	case "aws_security_group_rule":
		if plan.Str(m, "type") == "ingress" {
			a.awsRule(e, m)
		}
	case "aws_vpc_security_group_ingress_rule":
		for _, k := range []string{"cidr_ipv4", "cidr_ipv6"} {
			if src := plan.Str(m, k); worldCIDRs[src] {
				a.ingress(e, src, awsPorts(m), plan.Str(m, "ip_protocol"))
			}
		}
	case "aws_s3_bucket_public_access_block", "aws_s3_account_public_access_block":
		for _, k := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
			if on, ok := plan.Bool(m, k); ok && !on {
				e.add(High, "S3 Block Public Access `%s = false`", k)
			}
		}
	case "aws_s3_bucket_acl":
		switch acl := plan.Str(m, "acl"); acl {
		case "public-read", "public-read-write":
			e.add(Critical, "bucket ACL `%s`", acl)
		case "authenticated-read":
			e.add(High, "bucket ACL `%s` (any AWS account)", acl)
		}
	case "aws_db_instance", "aws_rds_cluster_instance", "aws_redshift_cluster", "aws_dms_replication_instance":
		if on, _ := plan.Bool(m, "publicly_accessible"); on {
			e.add(High, "database is `publicly_accessible`")
		}
	case "aws_instance":
		if on, _ := plan.Bool(m, "associate_public_ip_address"); on {
			e.add(Medium, "instance gets a public IP")
		}
	case "aws_eip":
		if act == plan.Create {
			e.add(Medium, "allocates a public Elastic IP")
		}
	case "aws_lb":
		if internal, ok := plan.Bool(m, "internal"); ok && !internal {
			e.add(Medium, "internet-facing load balancer")
		}
	case "aws_lambda_function_url":
		if plan.Str(m, "authorization_type") == "NONE" {
			e.add(High, "Lambda function URL with `authorization_type = \"NONE\"`")
		}
	case "aws_eks_cluster":
		for _, vc := range plan.Blocks(m, "vpc_config") {
			if on, _ := plan.Bool(vc, "endpoint_public_access"); on {
				for _, c := range plan.Strings(vc, "public_access_cidrs") {
					if worldCIDRs[c] {
						e.add(High, "EKS API endpoint reachable from `%s`", c)
					}
				}
			}
		}

	// Google Cloud
	case "google_compute_firewall":
		dir := plan.Str(m, "direction")
		disabled, _ := plan.Bool(m, "disabled")
		if (dir == "" || dir == "INGRESS") && !disabled {
			for _, src := range plan.Strings(m, "source_ranges") {
				if !worldCIDRs[src] {
					continue
				}
				for _, al := range plan.Blocks(m, "allow") {
					ports := plan.Strings(al, "ports")
					if len(ports) == 0 {
						a.ingress(e, src, allPorts, plan.Str(al, "protocol"))
					}
					for _, p := range ports {
						if pr, ok := parsePorts(p); ok {
							a.ingress(e, src, pr, plan.Str(al, "protocol"))
						}
					}
				}
			}
		}
	case "google_compute_instance":
		for _, ni := range plan.Blocks(m, "network_interface") {
			if len(plan.List(ni, "access_config")) > 0 {
				e.add(Medium, "instance gets an external IP (`access_config`)")
			}
		}
	case "google_compute_address", "google_compute_global_address":
		if t := plan.Str(m, "address_type"); (t == "" || t == "EXTERNAL") && act == plan.Create {
			e.add(Medium, "reserves an external IP address")
		}
	case "google_sql_database_instance":
		for _, s := range plan.Blocks(m, "settings") {
			for _, ip := range plan.Blocks(s, "ip_configuration") {
				for _, n := range plan.Blocks(ip, "authorized_networks") {
					if v := plan.Str(n, "value"); worldCIDRs[v] {
						e.add(Critical, "Cloud SQL authorized network `%s`", v)
					}
				}
			}
		}

	// Azure
	case "azurerm_network_security_rule":
		a.azureRule(e, m)
	case "azurerm_network_security_group":
		for _, r := range plan.Blocks(m, "security_rule") {
			a.azureRule(e, r)
		}
	case "azurerm_public_ip":
		if act == plan.Create {
			e.add(Medium, "allocates a public IP")
		}
	case "azurerm_storage_account":
		if on, _ := plan.Bool(m, "allow_nested_items_to_be_public"); on {
			e.add(High, "storage account allows public blob containers (`allow_nested_items_to_be_public`)")
		}
	case "azurerm_storage_container":
		switch t := plan.Str(m, "container_access_type"); t {
		case "blob":
			e.add(High, "anonymous read of blobs (`container_access_type = \"blob\"`)")
		case "container":
			e.add(Critical, "anonymous list and read (`container_access_type = \"container\"`)")
		}
	case "azurerm_mssql_firewall_rule", "azurerm_postgresql_flexible_server_firewall_rule", "azurerm_mysql_flexible_server_firewall_rule":
		start, end := plan.Str(m, "start_ip_address"), plan.Str(m, "end_ip_address")
		switch {
		case start == "0.0.0.0" && end == "255.255.255.255":
			e.add(Critical, "database firewall open to every IPv4 address")
		case start == "0.0.0.0" && end == "0.0.0.0":
			e.add(Medium, "database firewall allows all Azure services (any tenant)")
		}
	}
	return e
}

func awsPorts(m map[string]any) portRange {
	from, ok1 := num(m["from_port"])
	to, ok2 := num(m["to_port"])
	if !ok1 || !ok2 || (from == 0 && to == 0) || from < 0 {
		return allPorts
	}
	return portRange{from, to}
}

func (a *analyzer) awsRule(e exposures, r map[string]any) {
	for _, k := range []string{"cidr_blocks", "ipv6_cidr_blocks"} {
		for _, c := range plan.Strings(r, k) {
			if worldCIDRs[c] {
				a.ingress(e, c, awsPorts(r), plan.Str(r, "protocol"))
			}
		}
	}
}

func (a *analyzer) azureRule(e exposures, r map[string]any) {
	if !strings.EqualFold(plan.Str(r, "direction"), "Inbound") || !strings.EqualFold(plan.Str(r, "access"), "Allow") {
		return
	}
	sources := plan.Strings(r, "source_address_prefixes")
	if s := plan.Str(r, "source_address_prefix"); s != "" {
		sources = append(sources, s)
	}
	ports := plan.Strings(r, "destination_port_ranges")
	if p := plan.Str(r, "destination_port_range"); p != "" {
		ports = append(ports, p)
	}
	for _, src := range sources {
		if !worldCIDRs[src] {
			continue
		}
		for _, p := range ports {
			if pr, ok := parsePorts(p); ok {
				a.ingress(e, src, pr, plan.Str(r, "protocol"))
			}
		}
	}
}
