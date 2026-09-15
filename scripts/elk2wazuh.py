#!/usr/bin/env python3
"""
elk2wazuh.py — Convert Kibana Detection Rules (XLSX) to Wazuh 4.14 XML rules.

Usage:
    python3 elk2wazuh.py input.xlsx -o output.xml
    python3 elk2wazuh.py input.xlsx --start-id 200000 -o output.xml

XLSX columns expected:
    Rule Name, Rule Description, Severity, Log Type, Rule Type,
    Index, Query, Filter, Threshold, Schedule, Rule Exception, status
"""

import argparse
import re
import sys
from pathlib import Path

try:
    import openpyxl
except ImportError:
    print("ERROR: openpyxl not installed. Run: pip install openpyxl", file=sys.stderr)
    sys.exit(1)


# ── Severity → Wazuh Level ──────────────────────────────────────

SEVERITY_MAP = {
    "critical": 12,
    "high": 10,
    "medium": 7,
    "low": 4,
    "info": 2,
}

def severity_to_level(severity: str) -> int:
    return SEVERITY_MAP.get(severity.strip().lower(), 7)


# ── ES Query Parser ─────────────────────────────────────────────

def parse_es_query(query: str) -> list:
    """
    Parse a simplified ES query string into a list of conditions.
    Returns: list of dicts with keys: field, value, negate
    
    Handles:
        field:value
        not field:value
        field:(v1 or v2)
        field:value1 and field2:value2
    """
    if not query or not query.strip():
        return []

    conditions = []
    query = query.strip()

    # Split by ' and ' (case-insensitive), but respect parentheses
    parts = re.split(r'\s+and\s+', query, flags=re.IGNORECASE)

    for part in parts:
        part = part.strip()
        if not part:
            continue

        # Check for negation
        negate = False
        if part.lower().startswith("not "):
            negate = True
            part = part[4:].strip()

        # Match field:value or field:(value1 or value2)
        m = re.match(r'^([\w.]+)\s*:\s*(.+)$', part)
        if not m:
            continue

        field = m.group(1)
        value = m.group(2).strip().strip('"').strip("'")

        # Handle OR values: field:(v1 or v2)
        or_match = re.match(r'^\((.+)\)$', value)
        if or_match:
            inner = or_match.group(1)
            or_values = re.split(r'\s+or\s+', inner, flags=re.IGNORECASE)
            or_values = [v.strip().strip('"').strip("'") for v in or_values]
            value = "|".join(or_values)

        conditions.append({
            "field": field,
            "value": value,
            "negate": negate,
        })

    return conditions


# ── XML Generator ───────────────────────────────────────────────

def generate_wazuh_rule(
    rule_id: int,
    name: str,
    description: str,
    severity: str,
    log_type: str,
    rule_type: str,
    query: str,
    filter_str: str,
    threshold: str,
    schedule: str,
    exception: str,
    status: str,
    group_prefix: str = "elk_converted",
) -> str:
    """Generate a single Wazuh XML rule block."""

    level = severity_to_level(severity)
    conditions = parse_es_query(query)

    # Also parse filter if present
    if filter_str and filter_str.strip():
        filter_conds = parse_es_query(filter_str)
        conditions.extend(filter_conds)

    lines = []
    lines.append(f'  <!-- ELK Rule: {name} -->')
    if description and description.strip():
        lines.append(f'  <!-- Description: {description.strip()[:120]} -->')
    lines.append(f'  <!-- Original Severity: {severity} | Log Type: {log_type} | Type: {rule_type} -->')

    # Status
    status_attr = ' status="disabled"' if status and status.strip().lower() == "disabled" else ""

    lines.append(f'  <rule id="{rule_id}" level="{level}"{status_attr}>')

    # Conditions
    if conditions:
        for cond in conditions:
            field = cond["field"]
            value = cond["value"]
            if cond["negate"]:
                lines.append(f'    <field name="{field}" negate="yes">{value}</field>')
            else:
                lines.append(f'    <field name="{field}">{value}</field>')
    else:
        # No parsed conditions — use comment for manual review
        lines.append(f'    <!-- TODO: Could not auto-parse query. Original query below: -->')
        lines.append(f'    <!-- {query} -->')
        lines.append(f'    <if_sid>0</if_sid>')

    # Description
    lines.append(f'    <description>{name}</description>')

    # Groups
    groups = [group_prefix]
    if log_type and log_type.strip():
        groups.append(log_type.strip().lower().replace(" ", "_").replace("-", "_"))
    lines.append(f'    <group>{",".join(groups)}</group>')

    # Threshold handling
    if threshold and threshold.strip() and rule_type and "threshold" in rule_type.lower():
        # Parse threshold: e.g., "count > 5" or just "5"
        t_match = re.search(r'(\d+)', threshold)
        if t_match:
            freq = t_match.group(1)
            lines.append(f'    <!-- Threshold: {threshold.strip()} — convert to frequency rule -->')
            lines.append(f'    <!-- frequency="{freq}" timeframe="300" (adjust as needed) -->')

    lines.append(f'  </rule>')
    return "\n".join(lines)


def generate_wazuh_file(rules_data: list, start_id: int = 100000, group_prefix: str = "elk_converted") -> str:
    """Generate a complete Wazuh rules XML file."""

    header = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<!DOCTYPE rules_config>',
        '',
        '<!--',
        '  Wazuh Custom Rules — Converted from Kibana Detection Rules',
        f'  Total rules: {len(rules_data)}',
        '  Deploy to: /var/ossec/etc/rules/',
        '  Restart: wazuh-control restart',
        '-->',
        '',
        f'<group name="{group_prefix},">',
    ]

    footer = [
        '</group>',
    ]

    body = []
    for i, rule in enumerate(rules_data):
        rule_id = start_id + i
        rule_xml = generate_wazuh_rule(
            rule_id=rule_id,
            name=rule.get("Rule Name", f"Rule_{rule_id}"),
            description=rule.get("Rule Description", ""),
            severity=rule.get("Severity", "medium"),
            log_type=rule.get("Log Type", ""),
            rule_type=rule.get("Rule Type", ""),
            query=rule.get("Query", ""),
            filter_str=rule.get("Filter", ""),
            threshold=rule.get("Threshold", ""),
            schedule=rule.get("Schedule", ""),
            exception=rule.get("Rule Exception", ""),
            status=rule.get("status", ""),
            group_prefix=group_prefix,
        )
        body.append(rule_xml)
        body.append("")

    return "\n".join(header + body + footer)


# ── XLSX Reader ─────────────────────────────────────────────────

def read_xlsx(filepath: str) -> list:
    """Read XLSX file and return list of rule dicts."""
    wb = openpyxl.load_workbook(filepath, read_only=True, data_only=True)
    ws = wb.active

    rows = list(ws.iter_rows(values_only=True))
    if len(rows) < 2:
        print("ERROR: XLSX has less than 2 rows (need header + data)", file=sys.stderr)
        sys.exit(1)

    headers = [str(h).strip() if h else "" for h in rows[0]]
    rules = []
    for row in rows[1:]:
        rule = {}
        for j, val in enumerate(row):
            if j < len(headers) and headers[j]:
                rule[headers[j]] = str(val).strip() if val else ""
        # Only include rows that have at least a Rule Name
        if rule.get("Rule Name"):
            rules.append(rule)

    return rules


# ── Main ────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Convert Kibana Detection Rules (XLSX) to Wazuh XML rules"
    )
    parser.add_argument("input", help="Input XLSX file path")
    parser.add_argument("-o", "--output", default="custom_rules.xml", help="Output XML file path")
    parser.add_argument("--start-id", type=int, default=100000, help="Starting rule ID (default: 100000)")
    parser.add_argument("--group", default="elk_converted", help="Wazuh group name prefix")

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: File not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Reading: {input_path}")
    rules = read_xlsx(str(input_path))
    print(f"[*] Found {len(rules)} rules")

    if not rules:
        print("[!] No rules found in file. Check column headers.", file=sys.stderr)
        sys.exit(1)

    xml_content = generate_wazuh_file(rules, start_id=args.start_id, group_prefix=args.group)

    output_path = Path(args.output)
    output_path.write_text(xml_content, encoding="utf-8")
    print(f"[+] Written to: {output_path}")
    print(f"[+] Rule IDs: {args.start_id} — {args.start_id + len(rules) - 1}")
    print(f"[+] Deploy to: /var/ossec/etc/rules/{output_path.name}")
    print(f"[+] Then run:  wazuh-control restart")

    # Summary
    print("\n[*] Summary:")
    for i, rule in enumerate(rules):
        rid = args.start_id + i
        sev = rule.get("Severity", "?")
        name = rule.get("Rule Name", "?")[:60]
        print(f"    {rid} | {sev:8s} | {name}")


if __name__ == "__main__":
    main()
