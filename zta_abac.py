from datetime import datetime
from roles import roles
from policies import policy_templates
from users import users

resources = [
    {"id": 101, "type": "EMR", "team": "emergency"},
    {"id": 102, "type": "EMR", "team": "surgery"},
    {"id": 103, "type": "Pharmacy Data", "team": "pharmacy"},
    {"id": 104, "type": "Lab Results", "team": "lab"},
    {"id": 105, "type": "Billing Data", "team": "billing"},
    {"id": 106, "type": "Patient Record", "team": "emergency"},
    {"id": 107, "type": "Surgery Data", "team": "surgery"},
    {"id": 108, "type": "X-Ray Images", "team": "radiology"},
    {"id": 109, "type": "Insurance Claims", "team": "billing"},
    {"id": 110, "type": "Pharmacy Inventory", "team": "pharmacy"},
]

LOG_FILE_PATH = "access_logs.txt"


def log_access(user, resource, action, decision, reason=None):
    log_entry = {
        "user": user["name"],
        "resource_id": resource["id"] if resource else "N/A",
        "action": action,
        "decision": decision,
        "reason": reason,
        "timestamp": datetime.now().isoformat(),
    }

    with open(LOG_FILE_PATH, "a") as log_file:
        log_file.write(f"{log_entry}\n")
    print("LOG:", log_entry)


class PDP:
    def __init__(self, policy_templates):
        self.policy_templates = policy_templates

    def evaluate_policy(self, user, action, resource):
        for policy_name, policy in self.policy_templates.items():
            if user["role"] in policy["role"]:
                attributes = policy["attributes"]
                if all(user.get(attr) == value for attr, value in attributes.items()):
                    if action not in attributes.get("action", []):
                        return False, "Action not allowed for role"
                    return True, "Policy evaluation passed"
        return False, "Policy evaluation failed"


class PEP:
    def __init__(self, pdp):
        self.pdp = pdp

    def enforce(self, user, action, resource, device_id, location):
        zt_passed, zt_reason = zero_trust_verification(user, device_id, location)
        if not zt_passed:
            log_access(user, resource, action, "DENY", reason=zt_reason)
            return False

        decision, reason = self.pdp.evaluate_policy(user, action, resource)

        log_access(
            user, resource, action, "PERMIT" if decision else "DENY", reason=reason
        )
        return decision


def zero_trust_verification(user, device_id, location):
    if not user["active_shift"]:
        return False, "User is not on active shift"
    if device_id != "device123":
        return False, "Unrecognized device"
    if location != "hospital_1":
        return False, "Unrecognized location"
    return True, None


def get_user_attributes(user_id):
    user = next((user for user in users if user["id"] == user_id), None)
    if user is None:
        raise ValueError(f"User with ID {user_id} not found.")
    return user


def break_glass_mechanism(user, resource, action):
    break_glass = input(
        f"{user['name']} is invoking Break Glass for {resource['type']}. Do you want to invoke the Break Glass Mechanism? (yes/no): "
    ).lower()
    if break_glass == "yes":
        print(f"{user['name']} is invoking Break Glass for {resource['type']}")
        log_access(
            user, resource, action, "PERMIT", reason="Break Glass invoked by admin"
        )
    else:
        print(f"{user['name']} did not invoke Break Glass. Access is denied.")


def example_workflow():
    pdp = PDP(policy_templates)
    pep = PEP(pdp)

    print("\nScenario: Doctor Accessing Emergency EMR")
    user = get_user_attributes(1)
    resource = resources[0]
    action = "update"
    pep.enforce(user, action, resource, device_id="device123", location="hospital_1")

    print("\nScenario: Nurse Accessing Emergency EMR")
    user = get_user_attributes(2)
    resource = resources[0]
    action = "update"
    pep.enforce(user, action, resource, device_id="device123", location="hospital_1")

    print("\nScenario: Pharmacist Accessing Pharmacy Data")
    user = get_user_attributes(5)
    resource = resources[2]
    action = "update"
    pep.enforce(user, action, resource, device_id="device123", location="hospital_1")

    print("\nScenario: Admin Accessing Billing Data")
    user = get_user_attributes(3)
    resource = resources[4]
    action = "manage"
    pep.enforce(user, action, resource, device_id="device123", location="hospital_1")

    print("\nScenario: Break Glass Mechanism for Nurse")
    user = get_user_attributes(2)
    resource = resources[0]
    action = "update"
    break_glass_mechanism(user, resource, action)

    print("\nScenario: Surgeon Accessing Surgery Data")
    user = get_user_attributes(9)
    resource = resources[6]
    action = "write"
    pep.enforce(user, action, resource, device_id="device123", location="hospital_1")

    print("\nScenario: X-ray Technician Accessing X-Ray Images")
    user = get_user_attributes(11)
    resource = resources[7]
    action = "read"
    pep.enforce(user, action, resource, device_id="device123", location="hospital_1")

    print("\nScenario: Admin Accessing All Data (Audit Logs)")
    user = get_user_attributes(3)
    resource = None
    action = "audit_logs"
    pep.enforce(user, action, resource, device_id="device123", location="hospital_1")

    print("\nScenario: Nurse Accessing Billing Data (Denied)")
    user = get_user_attributes(2)
    resource = resources[4]  # Billing Data
    action = "update"
    pep.enforce(
        user, action, resource, device_id="device123", location="hospital_1"
    )  # Denied due to lack of permission

    print("\nScenario: Admin Accessing Patient Record")
    user = get_user_attributes(3)
    resource = resources[5]  # Patient Record
    action = "read"
    pep.enforce(
        user, action, resource, device_id="device123", location="hospital_1"
    )  # Admin allowed to read patient records

    print("\nScenario: X-ray Technician Accessing Lab Results (Denied)")
    user = get_user_attributes(11)
    resource = resources[3]  # Lab Results
    action = "update"
    pep.enforce(
        user, action, resource, device_id="device123", location="hospital_1"
    )  # Denied due to role limitation

    print("\nScenario: Doctor Accessing Pharmacy Inventory (Denied)")
    user = get_user_attributes(1)
    resource = resources[9]  # Pharmacy Inventory
    action = "update"
    pep.enforce(
        user, action, resource, device_id="device123", location="hospital_1"
    )  # Denied due to role limitation

    print("\nScenario: Admin Accessing Lab Results (Audit Logs)")
    user = get_user_attributes(3)
    resource = resources[3]  # Lab Results
    action = "read"
    pep.enforce(
        user, action, resource, device_id="device123", location="hospital_1"
    )  # Admin allowed access

    print("\nScenario: Admin Trying to Access Restricted Resource (Break Glass)")
    user = get_user_attributes(3)
    resource = {
        "id": 999,
        "type": "Restricted Data",
        "team": "restricted",
    }  # Hypothetical restricted resource
    action = "update"
    break_glass_mechanism(user, resource, action)

    print("\nScenario: Pharmacist Accessing Patient Record (Denied)")
    user = get_user_attributes(5)
    resource = resources[5]  # Patient Record
    action = "update"
    pep.enforce(
        user, action, resource, device_id="device123", location="hospital_1"
    )  # Denied due to lack of permission

    print("\nScenario: Surgeon Accessing Surgery Data (Allowed)")
    user = get_user_attributes(9)
    resource = resources[6]  # Surgery Data
    action = "update"
    pep.enforce(
        user, action, resource, device_id="device123", location="hospital_1"
    )  # Surgeon allowed to access surgery data

    print("\nScenario: Anesthesiologist Accessing Surgery Data (Allowed)")
    user = get_user_attributes(10)
    resource = resources[6]  # Surgery Data
    action = "read"
    pep.enforce(
        user, action, resource, device_id="device123", location="hospital_1"
    )  # Anesthesiologist can read surgery data

    print("\nScenario: Admin Performing Emergency Access")
    user = get_user_attributes(3)
    resource = resources[0]  # Emergency EMR
    action = "update"
    break_glass_mechanism(user, resource, action)

    print("\nScenario: Lab Technician Accessing Lab Results")
    user = get_user_attributes(8)
    resource = resources[3]  # Lab Results
    action = "read"
    pep.enforce(
        user, action, resource, device_id="device123", location="hospital_1"
    )  # Lab Technician allowed to read lab results

    print("\nScenario: Unauthorized User Trying to Access Lab Results")
    user = get_user_attributes(6)  # A user without permission
    resource = resources[3]  # Lab Results
    action = "update"
    pep.enforce(
        user, action, resource, device_id="device123", location="hospital_1"
    )  # Denied due to lack of permissions

    print("\nScenario: Nurse Accessing Surgery Data (Break Glass)")
    user = get_user_attributes(2)
    resource = resources[6]  # Surgery Data
    action = "read"
    break_glass_mechanism(user, resource, action)


example_workflow()
