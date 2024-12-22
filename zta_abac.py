from datetime import datetime, timedelta
from cachetools import TTLCache


users = [
    {
        "id": 1,
        "name": "Dr. John",
        "role": "doctor",
        "active_shift": True,
        "team": "emergency",
    },
    {
        "id": 2,
        "name": "Nurse Jane",
        "role": "nurse",
        "active_shift": True,
        "team": "emergency",
    },
    {
        "id": 3,
        "name": "Admin Mike",
        "role": "admin",
        "active_shift": False,
        "team": "admin",
    },
    {
        "id": 4,
        "name": "Ambulance Alex",
        "role": "ambulance",
        "active_shift": True,
        "team": "emergency",
    },  
]

resources = [
    {"id": 101, "type": "EMR", "team": "emergency"},
    {"id": 102, "type": "EMR", "team": "surgery"},
]

roles = {
    "doctor": ["read", "update"],
    "nurse": ["read"],
    "admin": ["read", "update", "manage"],
    "ambulance": ["read"],  
}


attribute_cache = TTLCache(maxsize=100, ttl=300)


policy_templates = {
    "emergency_access": {
        "role": [
            "doctor",
            "nurse",
            "ambulance",
        ],  
        "attributes": {"active_shift": True, "team": "emergency"},
    },
    "admin_access": {
        "role": ["admin"],
        "attributes": {"active_shift": False, "team": "admin"},
    },
    "ambulance_access": {
        "role": ["ambulance"],
        "attributes": {"active_shift": True, "team": "emergency", "action": "read"},
    },
}

LOG_FILE_PATH = "access_logs.txt"



def log_access(user, resource, action, decision, reason=None):
    if user["name"] == "System" and action in ["add_policy", "remove_policy", "audit"]:
        return  

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



class PAP:
    def __init__(self):
        self.policies = policy_templates

    def add_policy(self, policy_name, policy_details):
        self.policies[policy_name] = policy_details
        print(f"Policy '{policy_name}' added successfully.")
        log_access(
            {"name": "System"},
            {"id": "N/A"},
            "add_policy",
            "PERMIT",
            f"Policy '{policy_name}' added.",
        )

    def remove_policy(self, policy_name):
        if policy_name in self.policies:
            del self.policies[policy_name]
            print(f"Policy '{policy_name}' removed successfully.")
            log_access(
                {"name": "System"},
                {"id": "N/A"},
                "remove_policy",
                "PERMIT",
                f"Policy '{policy_name}' removed.",
            )
        else:
            print(f"Policy '{policy_name}' does not exist.")
            log_access(
                {"name": "System"},
                {"id": "N/A"},
                "remove_policy",
                "DENY",
                f"Policy '{policy_name}' does not exist.",
            )



def zero_trust_verification(user, device_id, location):
    if not user["active_shift"]:
        return False, "User is not on active shift"
    if device_id != "device123":
        return False, "Unrecognized device"
    if location != "hospital_1":
        return False, "Unrecognized location"
    return True, None



class BreakGlass:
    def __init__(self):
        self.sessions = {}

    def request_break_glass(self, user, resource, approver=None):
        if approver:
            approval = input(
                f"Approval required from {approver['name']}. Type 'yes' to approve: "
            )
            if approval.lower() != "yes":
                log_access(
                    user, resource, "break-glass", "DENY", reason="Authorization denied"
                )
                return False

        session_id = f"{user['id']}_{resource['id']}"
        expiry_time = datetime.now() + timedelta(minutes=10)
        self.sessions[session_id] = {"user": user, "expiry": expiry_time}
        print(
            f"Break-glass access granted for {user['name']} to resource {resource['id']} until {expiry_time}."
        )
        log_access(
            user,
            resource,
            "break-glass",
            "PERMIT",
            reason="Time-bound emergency override",
        )
        return True

    def audit_sessions(self):
        print("Auditing break-glass sessions...")
        with open(LOG_FILE_PATH, "r") as log_file:
            logs = log_file.readlines()
            for log in logs:
                print(log.strip())



def get_user_attributes(user_id):
    if user_id in attribute_cache:
        return attribute_cache[user_id]
    user = next((u for u in users if u["id"] == user_id), None)
    attribute_cache[user_id] = user
    return user



def post_incident_audit():
    print("Performing post-incident audit...")
    with open(LOG_FILE_PATH, "r") as log_file:
        logs = log_file.readlines()
        for log in logs:
            print(f"AUDIT LOG: {log.strip()}")
            log_access(
                {"name": "System"},
                {"id": "N/A"},
                "audit",
                "PERMIT",
                f"Audit log: {log.strip()}",
            )



def example_workflow():
    
    pap = PAP()
    pdp = PDP(policy_templates)
    pep = PEP(pdp)
    break_glass = BreakGlass()

    # Scenario 1: Normal Access without Break-Glass
    print("\nScenario 1: Normal Access without Break-Glass")
    user = get_user_attributes(4)  # Ambulance Alex
    resource = resources[0]  # Emergency EMR
    action = "update"
    device_id = "device123"
    location = "hospital_1"
    access_granted = pep.enforce(user, action, resource, device_id, location)
    # approver = get_user_attributes(3)
    # print(f"Access Granted: {access_granted}")
    # break_glass.request_break_glass(user, resource, approver=approver)

    # Scenario 2: Denied Access (Without Break-Glass) due to Policy
    print("\nScenario 2: Denied Access (Without Break-Glass)")
    user = get_user_attributes(3)  # Admin Mike (not on active shift)
    resource = resources[0]  # Emergency EMR
    action = "read"
    device_id = "device123"
    location = "hospital_1"
    access_granted = pep.enforce(user, action, resource, device_id, location)
    print(f"Access Granted: {access_granted}")

    # Scenario 3: Break-Glass Access Requested (with Approval)
    print("\nScenario 3: Break-Glass Access Requested (with Approval)")
    user = get_user_attributes(1)  # Dr. John
    resource = resources[0]  # Emergency EMR
    action = "update"
    approver = get_user_attributes(3)  # Admin Mike
    break_glass.request_break_glass(user, resource, approver=approver)

    # Scenario 4: Break-Glass Access Denied (without Approval)
    print("\nScenario 4: Break-Glass Access Denied (without Approval)")
    user = get_user_attributes(2)  # Nurse Jane
    resource = resources[1]  # Surgery EMR
    action = "update"
    break_glass.request_break_glass(
        user, resource
    )  # No approver here, so it should be denied

    # Add and Remove Policies via PAP
    pap.add_policy(
        "ambulance_access", {"role": ["ambulance"], "attributes": {"team": "emergency"}}
    )
    pap.remove_policy("admin_access")

    # Audit Break-Glass Sessions
    break_glass.audit_sessions()

    # Post-Incident Audit
    post_incident_audit()

# Main Function
if __name__ == "__main__":
    example_workflow()


# def example_workflow():
#     # Initialize Components
#     pap = PAP()
#     pdp = PDP(policy_templates)
#     pep = PEP(pdp)
#     break_glass = BreakGlass()

#     # Simulated Inputs for Various Scenarios
#     # Scenario 1: Doctor Accesses Emergency EMR (Without Break-Glass)
#     # user = get_user_attributes(1)  # Dr. John
#     # resource = resources[0]  # Emergency EMR
#     action = "read"
#     device_id = "device123"
#     location = "hospital_1"
#     # pep.enforce(user, action, resource, device_id, location)

#     # Scenario 2: Nurse Tries to Access Surgery EMR (Without Break-Glass)
#     # user = get_user_attributes(2)  # Nurse Jane
#     # resource = resources[1]  # Surgery EMR
#     # pep.enforce(user, action, resource, device_id, location)

#     # # Scenario 3: Admin Tries to Access Emergency EMR but is Off Shift (Without Break-Glass)
#     # user = get_user_attributes(3)  # Admin Mike
#     # resource = resources[0]  # Emergency EMR
#     # pep.enforce(user, action, resource, device_id, location)

#     # # Scenario 4: Admin Approves Break-Glass for Doctor (With Break-Glass)
#     # approver = get_user_attributes(3)  # Admin Mike
#     # break_glass.request_break_glass(user, resource, approver=approver)

#     # # Scenario 5: Doctor Break-Glass Attempt Without Approval (Without Break-Glass)
#     # user = get_user_attributes(1)  # Dr. John
#     # resource = resources[1]  # Surgery EMR
#     # break_glass.request_break_glass(user, resource)  # No approver

#     # # Scenario 6: User with Unrecognized Device Attempts Access (Without Break-Glass)
#     # device_id = "device999"  # Unrecognized Device
#     # pep.enforce(user, action, resource, device_id, location)

#     # # Scenario 7: Access to Resource by User Not in Active Shift (Without Break-Glass)
#     # user = get_user_attributes(3)  # Admin Mike
#     # pep.enforce(user, action, resource, device_id, location)

#     # Scenario 8: Audit of Break-Glass Sessions
#     break_glass.audit_sessions()

#     # Post-Incident Audit
#     post_incident_audit()
