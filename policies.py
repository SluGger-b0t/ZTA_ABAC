policy_templates = {
    "doctor_policy": {
        "role": ["doctor"],
        "attributes": {
            "team": "emergency",
            "action": ["read", "update", "write", "delete", "request_approval"],
        },
    },
    "nurse_policy": {
        "role": ["nurse"],
        "attributes": {
            "team": "emergency",
            "action": ["read", "update", "delete", "request_approval"],
        },
    },
    "admin_policy": {
        "role": ["admin"],
        "attributes": {
            "action": [
                "read",
                "update",
                "manage",
                "delete",
                "create",
                "approve",
                "revoke_access",
            ],
        },
    },
    "ambulance_policy": {
        "role": ["ambulance"],
        "attributes": {
            "team": "emergency",
            "action": ["read", "update"],
        },
    },
    "pharmacist_policy": {
        "role": ["pharmacist"],
        "attributes": {
            "team": "pharmacy",
            "action": ["read", "update", "write", "modify_inventory"],
        },
    },
    "receptionist_policy": {
        "role": ["receptionist"],
        "attributes": {
            "action": ["read", "create", "schedule_appointments"],
        },
    },
    "lab_technician_policy": {
        "role": ["lab_technician"],
        "attributes": {
            "team": "lab",
            "action": ["read", "update", "generate_reports"],
        },
    },
    "billing_clerk_policy": {
        "role": ["billing_clerk"],
        "attributes": {
            "team": "billing",
            "action": ["read", "update", "manage_billing"],
        },
    },
    "surgeon_policy": {
        "role": ["surgeon"],
        "attributes": {
            "team": "surgery",
            "action": ["read", "update", "write", "delete", "perform_surgery"],
        },
    },
    "anesthesiologist_policy": {
        "role": ["anesthesiologist"],
        "attributes": {
            "team": "surgery",
            "action": ["read", "update", "write", "administer_anesthesia"],
        },
    },
    "physician_policy": {
        "role": ["physician"],
        "attributes": {
            "team": "emergency",
            "action": ["read", "update", "prescribe_treatment"],
        },
    },
    "xray_technician_policy": {
        "role": ["xray_technician"],
        "attributes": {
            "team": "radiology",
            "action": ["read", "update", "manage_images"],
        },
    },
}
