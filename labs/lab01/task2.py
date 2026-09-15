users = {
    "incident_commander": {
        "role": "incident_response",
        "clearance": 4,
        "department": "CSIRT",
        "active": True
    },
    "malware_analyst": {
        "role": "malware_researcher",
        "clearance": 3,
        "department": "Research",
        "active": True
    },
    "monitoring_tech": {
        "role": "monitoring",
        "clearance": 2,
        "department": "NOC",
        "active": True
    },
    "customer_rep": {
        "role": "customer_service",
        "clearance": 1,
        "department": "Customer",
        "active": True
    },
    "backup_service": {
        "role": "service_account",
        "clearance": 2,
        "department": "System",
        "active": False
    }
}

resources = [
    ("incident_playbook", 4),
    ("malware_lab", 3),
    ("monitoring_dashboards", 2),
    ("customer_portal", 1),
    ("emergency_procedures", 4),
    ("service_desk", 1),
    ("reverse_engineering", 3),
    ("alert_systems", 2),
    ("escalation_matrix", 3),
    ("knowledge_base", 1)
]

security_levels = (
    "Public Access",
    "Authorized",
    "Privileged",
    "Critical"
)

blocked_users = {
    "backup_service",
    "deactivated_svc",
    "policy_violation"
}



print("Resource")

for resource_name, security_level in resources:
    level_name = security_levels[security_level - 1]
    print(
        f"Resource: {resource_name} | "
        f"Security level: {level_name}"
    )



def check_access(username, resource_name, resource_level):

    
    if username not in users:
        return "DENY (User not found)"

    user = users[username]

   
    if username in blocked_users:
        return "DENY (User is blocked)"

    
    if user["active"] is False:
        return "DENY (Account inactive)"

    
    if user["clearance"] >= resource_level:
        return "ALLOW"

    return "DENY (Insufficient clearance)"



print("\n ACCESS CHECK ")

for username in users:

    for resource_name, resource_level in resources:

        result = check_access(
            username,
            resource_name,
            resource_level
        )

        print(
            f"user={username} "
            f"resource={resource_name} -> {result}"
        )