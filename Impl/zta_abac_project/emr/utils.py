import json
from cryptography.fernet import Fernet
from django.core.cache import cache
from .models import AccessLog, User

# Encryption setup
key = Fernet.generate_key()
cipher_suite = Fernet(key)


def encrypt_data(data):
    return cipher_suite.encrypt(data.encode())


def decrypt_data(encrypted_data):
    return cipher_suite.decrypt(encrypted_data).decode()


def load_policies():
    with open("policies.json", "r") as file:
        return json.load(file)


POLICIES = load_policies()


def evaluate_policy(action, attributes):
    """
    Evaluate policies for a specific action using user attributes.
    """
    for policy_name, policy in POLICIES.items():
        if action in policy["actions"]:
            conditions_met = all(
                (
                    attributes.get(cond["attribute"]) in cond["value"]
                    if isinstance(cond["value"], list)
                    else attributes.get(cond["attribute"]) == cond["value"]
                )
                for cond in policy["conditions"]
            )
            if conditions_met:
                return {"decision": "PERMIT"}
    return {"decision": "DENY"}


def log_access(user, action, resource, decision):
    AccessLog.objects.create(
        user=user,
        action=action,
        resource=resource,
        decision=decision,
        location=user.last_known_location or "Unknown",
    )


def continuous_verification(user, device_id, location):
    """
    Verify user attributes dynamically (Zero Trust checks).
    """
    if not user.active_shift:
        return {"decision": "DENY", "reason": "User not on active shift"}
    if user.last_device_id != device_id:
        return {"decision": "DENY", "reason": "Unrecognized device"}
    if user.last_known_location != location:
        return {"decision": "DENY", "reason": "Unusual location"}
    return {"decision": "PERMIT"}


def evaluate_policy_with_zta(user, action, resource, device_id, location):
    """
    Combine ZTA and ABAC evaluations.
    """
    # Step 1: ZTA continuous verification
    zta_result = continuous_verification(user, device_id, location)
    if zta_result["decision"] == "DENY":
        log_access(user, action, resource, zta_result["decision"])
        return zta_result

    # Step 2: ABAC policy evaluation
    attributes = {
        "role": user.role,
        "active_shift": user.active_shift,
        "team": user.team.name if user.team else None,
    }
    policy_result = evaluate_policy(action, attributes)

    # Log and return result
    log_access(user, action, resource, policy_result["decision"])
    return policy_result
