#!/usr/bin/env python3
"""Turn `terraform show -json` of a plan into a v4 state file.

Used by gen.sh to fabricate the "before" state for the cloud scenarios
without credentials. Computed attributes that are unknown at plan time are
filled with a type-appropriate synthetic value from the provider schema
(empty collections, false, 0, or a "synthetic-..." string), so that
re-planning the same config is a no-op and only the PR's edits show up.

usage: build_state.py plan.json schema.json > terraform.tfstate
"""
import json
import re
import sys


def walk(mod):
    yield mod
    for child in mod.get("child_modules", []):
        yield from walk(child)


def zero(ty, label):
    if ty == "string":
        return "synthetic-" + label
    if ty == "number":
        return 0
    if ty == "bool":
        return False
    if isinstance(ty, list) and ty[0] in ("list", "set"):
        return []
    if isinstance(ty, list) and ty[0] == "map":
        return {}
    return None


def fill(values, unknown, block, label):
    """Fill unknown top-level attributes using the schema block."""
    out = dict(values)
    attrs = block.get("attributes", {})
    nested = block.get("block_types", {})
    for name, flag in (unknown or {}).items():
        if flag is True:
            if name in attrs and "type" in attrs[name]:
                out[name] = zero(attrs[name]["type"], label)
            elif name in nested:
                out[name] = []
        elif name == "id" or name == "arn":
            pass
    if "arn" in attrs and str(out.get("arn") or "synthetic-").startswith("synthetic-"):
        out["arn"] = "arn:aws:synthetic:eu-west-1:111122223333:" + label
    if not out.get("id"):
        out["id"] = "synthetic-" + label
    return out


def main():
    plan = json.load(open(sys.argv[1]))
    schema = json.load(open(sys.argv[2]))
    unknown_by_addr = {
        rc["address"]: rc["change"].get("after_unknown") or {}
        for rc in plan.get("resource_changes", [])
    }
    groups = {}
    for mod in walk(plan["planned_values"]["root_module"]):
        for r in mod.get("resources", []):
            if r["mode"] != "managed":
                continue
            key = re.sub(r"\[[^\]]*\]$", "", r["address"])
            groups.setdefault(key, []).append(r)
    resources = []
    for key, rs in groups.items():
        r0 = rs[0]
        block = schema["provider_schemas"][r0["provider_name"]]["resource_schemas"][r0["type"]]["block"]
        entry = {
            "mode": "managed",
            "type": r0["type"],
            "name": r0["name"],
            "provider": 'provider["%s"]' % r0["provider_name"],
            "instances": [],
        }
        m = re.match(r"^((?:module\.[^.\[]+(?:\[[^\]]*\])?\.)+)", r0["address"])
        if m:
            entry["module"] = m.group(1).rstrip(".")
        for r in rs:
            label = re.sub(r"[^a-z0-9]+", "-", r["address"].lower()).strip("-")
            inst = {
                "schema_version": r.get("schema_version", 0),
                "attributes": fill(r["values"], unknown_by_addr.get(r["address"]), block, label),
                "sensitive_attributes": [],
            }
            if "index" in r:
                inst["index_key"] = r["index"]
            entry["instances"].append(inst)
        resources.append(entry)
    json.dump({
        "version": 4,
        "terraform_version": plan["terraform_version"],
        "serial": 1,
        "lineage": "00000000-1111-2222-3333-444444444444",
        "outputs": {},
        "resources": resources,
        "check_results": None,
    }, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
