import json
import jsonschema
from jsonschema import validate

def validate_json_data(data, filepath="schema.json"):
    
    with open(filepath, 'r', encoding='utf-8') as schema_file:
        schema_dict = json.load(schema_file)
    
    
    validate(instance=data, schema=schema_dict)

    if data is Valid:
        return "Validation successful. The JSON data is valid according to the schema."
    else:
        raise ValueError("The JSON data is not valid according to the schema.")

if  __name__ == "__main__":
    sample_data = {
  "event": {
    "event_id": "EVT-987654321",
    "timestamp": "2026-09-24T19:20:40Z",
    "source": "firewall-edge-01",
    "event_type": "multiple_failed_logins",
    "severity": "high"
  },
  "enrichment": {
    "threat_intel_matches": [
      "known_botnet_ip",
      "tor_exit_node"
    ],
    "asset_context": {
      "hostname": "auth-server-primary",
      "ip_address": "10.0.1.55"
    },
    "related_events": [
      "EVT-987654310",
      "EVT-987654315"
    ]
  },
  
  "approval": {
    "approval_status": "auto-approved",
    "approver_id": "soar-automation-bot",
    "approval_timestamp": "2026-09-24T19:20:45Z"
  },
  "audit_trail": [
    {
      "actor": "system_ingestor",
      "action": "event_created",
      "timestamp": "2026-09-24T19:20:40Z"
    },
    {
      "actor": "soar-automation-bot",
      "action": "enrichment_and_approval_completed",
      "timestamp": "2026-09-24T19:20:45Z"
    }
  ]
}

    try:
        result = validate_json_data(sample_data)
        print(result)
    except ValueError as ve:
        print(f"Validation error: {ve}")
    except jsonschema.exceptions.ValidationError as ve:
        print(f"Schema validation error: {ve}")
    