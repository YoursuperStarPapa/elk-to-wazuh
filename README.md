# elk-to-wazuh

Convert Kibana Detection Rules (exported as XLSX) to Wazuh 4.14.x custom XML rules.

## Features

- Batch convert Kibana XLSX exports to Wazuh XML rule file
- Parse Elasticsearch query syntax (AND, OR, NOT, nested fields)
- Severity mapping: critical/high/medium/low to Wazuh levels 12/10/7/4
- Threshold rule detection with frequency/timeframe hints
- Rule ID range: 100000-199999

## Quick Start

    pip install openpyxl
    python3 scripts/elk2wazuh.py your_rules.xlsx -o custom_rules.xml
    sudo cp custom_rules.xml /var/ossec/etc/rules/
    sudo wazuh-control restart

## License

MIT
