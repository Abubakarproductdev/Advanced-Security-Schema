import json
import jsonschema
from jsonschema import validate

def load_schema(filepath="ArzensIntern_MuhamamdAbubakar_schema.json"):
    try:
        with open(filepath, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Could not find fle path")
        exit(1)

valid_record = {
    "event": {
        "event_id": "SEC-EVT-9901",
        "timestamp": "2026-07-11T10:15:30Z",
        "source": "AWS_WAF_US_EAST",
        "event_type": "sql_injection_attempt",
        "severity": "critical"
    },
    "enrichment": {
        "threat_intel_matches": 4,
        "asset_context": "customer_data_cluster_01",
        "related_events": ["SEC-EVT-9888", "SEC-EVT-9889"]
    },
    "confidence": {
        "level": 92,
        "applied_to": ["enrichment.threat_intel_matches", "event.event_type"]
    },
    "approval": {
        "approval_status": "pending",
        "approver_id": "analyst_m_abubakar",
        "approval_timestamp": "2026-07-11T10:16:00Z"
    },
    "audit_trail": [
        {
            "actor": "system",
            "action": "event_ingested_and_enriched",
            "timestamp": "2026-07-11T10:15:35Z"
        }
    ]
}

missing_confidence_record = {
    "event": {
        "event_id": "SEC-EVT-9902",
        "timestamp": "2026-07-11T10:20:00Z",
        "source": "VPN_Gateway",
        "event_type": "impossible_travel_login",
        "severity": "high"
    },
    "enrichment": {
        "threat_intel_matches": 0,
        "asset_context": "remote_employee_vpn",
        "related_events": []
    },
    "approval": {
        "approval_status": "pending"
    },
    "audit_trail": [
        {
            "actor": "system",
            "action": "flagged_for_review",
            "timestamp": "2026-07-11T10:20:05Z"
        }
    ]
}

missing_approval_record = {
    "event": {
        "event_id": "SEC-EVT-9903",
        "timestamp": "2026-07-11T10:25:00Z",
        "source": "Endpoint_AV",
        "event_type": "ransomware_signature_detected",
        "severity": "critical"
    },
    "enrichment": {
        "threat_intel_matches": 12,
        "asset_context": "executive_laptop",
        "related_events": []
    },
    "confidence": {
        "level": 99,
        "applied_to": ["event.event_type"]
    },
    "audit_trail": [
        {
            "actor": "system",
            "action": "quarantine_initiated",
            "timestamp": "2026-07-11T10:25:10Z"
        }
    ]
}

def validate_event_record(record_name, record_data, schema):
    print(f"\n--- Testing: {record_name} ---")
    try:
        validate(instance=record_data, schema=schema)
        print("✅ PASS: Record is fully valid and conforms to the schema.")
    except jsonschema.exceptions.ValidationError as err:
        print("❌ FAIL: Validation Error Detected.")
        if "is a required property" in err.message:
            print(f"   Reason: Missing required field -> {err.message}")
        else:
            print(f"   Reason: Data structure issue -> {err.message}")

if __name__ == "__main__":
    print("Loading schema.json...")
    secops_schema = load_schema()
    
    validate_event_record("Valid Record", valid_record, secops_schema)
    validate_event_record("Missing Confidence Record", missing_confidence_record, secops_schema)
    validate_event_record("Missing Approval Record", missing_approval_record, secops_schema)

    print("\n--- Validation Suite Complete ---\n")

# AI Tool Used: Gemini
# How it was used: Utilized as a brainstorming and debugging partner to structure the JSON Schema Draft-07 syntax, ensure the Python validator correctly utilized the 'jsonschema' library, and format readable error outputs for missing required fields.