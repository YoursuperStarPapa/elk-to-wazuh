# Elasticsearch Query Syntax → Wazuh XML Conversion Reference

## Parsing Rules

### 1. Simple field match
**ES:** `tags:"fortinet"`
**Wazuh:**
```xml
<field name="tags">fortinet</field>
```

### 2. Negation
**ES:** `not tags:"Satellite-Server"`
**Wazuh:**
```xml
<field name="tags" negate="yes">Satellite-Server</field>
```

### 3. AND logic (implicit)
**ES:** `Firewall.type:"SYSTEM" and Firewall.action:"crash"`
**Wazuh:**
```xml
<field name="Firewall.type">SYSTEM</field>
<field name="Firewall.action">crash</field>
```
Multiple `<field>` elements in one rule = implicit AND.

### 4. OR logic
**ES:** `Firewall.type:("SYSTEM" or "daemon")`
**Wazuh:**
```xml
<field name="Firewall.type">SYSTEM|daemon</field>
```
Use `|` (pipe) as regex OR separator.

### 5. Wildcard / exists
**ES:** `exists:Firewall.type`
**Wazuh:**
```xml
<field name="Firewall.type">.+</field>
```

### 6. Nested field (dotted)
**ES:** `Fortinet.log.level:"error"`
**Wazuh:**
```xml
<field name="Fortinet.log.level">error</field>
```
Wazuh supports dotted field names directly.

### 7. Phrase vs keyword
**ES:** `tags:"some phrase"` → exact match
**Wazuh:** Use regex if needed: `<field name="tags">some phrase</field>`

### 8. NOT group
**ES:** `not (tags:"a" or tags:"b")`
**Wazuh:**
```xml
<field name="tags" negate="yes">a|b</field>
```

## Wazuh XML Rule Structure Reference

### Basic rule
```xml
<rule id="100001" level="10">
  <if_sid>0</if_sid>
  <field name="tags">fortinet</field>
  <field name="Firewall.type">SYSTEM</field>
  <description>Fortinet Firewall System Event</description>
  <group>firewall,fortinet</group>
</rule>
```

### Rule with parent
```xml
<rule id="100002" level="12">
  <if_sid>100001</if_sid>
  <field name="Firewall.action">crash</field>
  <description>Fortinet Firewall Crash Detected</description>
  <group>firewall,fortinet,crash</group>
</rule>
```

### Frequency rule (threshold equivalent)
```xml
<rule id="100003" level="10" frequency="5" timeframe="300">
  <if_matched_sid>100001</if_matched_sid>
  <description>Fortinet crash events exceeded threshold (5 in 5 min)</description>
  <group>firewall,fortinet</group>
</rule>
```

### Rule with list (CDB) negation
```xml
<rule id="100004" level="5">
  <list field="tags" lookup="not_match_key">etc/lists/exclude_tags</list>
  <field name="tags">fortinet</field>
  <description>Fortinet event excluding certain tags</description>
</rule>
```

## Common Pitfalls

1. **Wazuh `<field>` is regex** — values like `SYSTEM` are safe, but special chars (`[`, `.`, `*`) need escaping or use `\.`
2. **No OR between different fields** — Wazuh ANDs same-level `<field>` elements. For OR across fields, use separate rules or `<compiled_rule>`
3. **Level range** — 0 (ignore) to 15 (critical). Use 4/7/10/12 for low/med/high/critical
4. **Rule IDs** — Must be unique. Built-in: 1–99999. Custom: 100000+
5. **Group names** — Comma-separated, no spaces after commas
