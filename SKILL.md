---
name: elk-to-wazuh
description: >
  Convert Kibana Detection Rules (exported as XLSX/NDJSON) to Wazuh 4.14.x custom XML rules.
  Also generates Wazuh rules from natural language conditions or raw Elasticsearch query syntax.
  Use when the user wants to: (1) migrate Kibana/SIEM rules to Wazuh, (2) convert ES query to Wazuh rule XML,
  (3) generate Wazuh detection rules from conditions like "tags:fortinet and Firewall.action:crash".
---

# ELK to Wazuh Rule Converter

## Overview

Two modes:
1. **Batch convert** — Parse Kibana-exported XLSX → generate Wazuh XML rule file
2. **Single generate** — Given a condition string (ES query syntax or natural language) → generate one Wazuh rule XML

## Quick Start

### Mode 1: Batch Convert from XLSX

```bash
python3 scripts/elk2wazuh.py input_rules.xlsx -o output_rules.xml
```

### Mode 2: Single Rule from Condition

Use the reference guide in `references/wazuh_rules.md` to manually construct XML, or ask the user for: rule name, condition, severity level.

## Field Mapping (Kibana → Wazuh)

| Kibana Field | Wazuh XML Element | Notes |
|---|---|---|
| Rule Name | `<description>` | |
| Rule Description | `<info>` (in comment or extra) | |
| Severity (critical/high/medium/low) | `level` attribute (12/10/7/4) | |
| Rule Type (threshold/query/eql) | `<compiled_rule>` or `<list>` | See threshold handling |
| Query (ES syntax) | `<field>` + `<not_field>` | Parsed from ES query string |
| Index | Comment only | Wazuh doesn't use index concept |
| Filter | Additional `<field>` conditions | |
| Schedule | Comment only | Wazuh uses frequency rules differently |
| Rule Exception | `<list>` with negation | Inverted as exclude conditions |
| Status (enabled/disabled) | `<rule status="...">` | |

## Severity Mapping

```
critical → level="12"
high     → level="10"
medium   → level="7"
low      → level="4"
```

## ES Query → Wazuh XML Conversion

Reference: `references/es_to_wazuh.md`

### Basic Patterns

| ES Query | Wazuh XML |
|---|---|
| `field:value` | `<field name="field">value</field>` |
| `not field:value` | `<field name="field" negate="yes">value</field>` |
| `field:value1 and field2:value2` | Two `<field>` elements (implicit AND) |
| `field:(value1 or value2)` | `<field name="field">value1\|value2</field>` (regex OR) |
| `field:*` | Skip (wildcard match all) |
| `exists:field` | `<field name="field">.+</field>` (regex) |

### Threshold Rules

For Kibana threshold rules (count > N within time window):
```xml
<rule id="XXXXX" level="Y" frequency="N" timeframe="T">
  <if_matched_sid>PARENT_RULE_ID</if_matched_sid>
  ...
</rule>
```

## Wazuh Rule XML Template

```xml
<!-- ELK Rule: {rule_name} -->
<!-- Original Severity: {severity} -->
<!-- Converted from Kibana Detection Rule -->
<group name="elk_converted,">
  <rule id="{id}" level="{level}">
    <field name="{field1}">{value1}</field>
    <field name="{field2}">{value2}</field>
    <description>{rule_name}</description>
    <group>{log_type}</group>
  </rule>
</group>
```

## Rule ID Range

Use IDs in range **100000–199999** for converted rules (avoids conflict with Wazuh built-in rules starting at 500–99999).

## Workflow

1. Read input (XLSX file or condition string)
2. Parse ES query fields into structured conditions
3. Map severity to Wazuh level
4. Generate XML with proper structure
5. Output complete rule file ready to place in `/var/ossec/etc/rules/`
6. Remind user: `wazuh-control restart` after deploying rules

## Testing

After deploying rules, test with:
```bash
/var/ossec/bin/wazuh-logtest
```
Paste a sample log line to verify rule matching.
