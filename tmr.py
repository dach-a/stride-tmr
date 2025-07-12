!pip install pytm
!apt-get install -y graphviz

import sys
import json
from pytm import TM, Server, Datastore, Dataflow, Boundary, Actor, Controls
from IPython.display import Image

# Backup and clear arguments to prevent conflicts
original_argv = sys.argv.copy()
sys.argv = [sys.argv[0]]

# Initialize threat model
tm = TM("Small Enterprise Threat Model")
tm.description = "Threat model for 70-employee enterprise with 3 offices"
tm.isOrdered = True

# ===== Define Boundaries =====
internet = Boundary("Internet")
corporate_net = Boundary("Corporate Network")
dmz = Boundary("DMZ")
cloud = Boundary("Cloud Services")

# ===== Define Components with Security Properties =====
# Set properties using EXACT names expected by threat conditions
# Internet entities
attacker = Actor("Attacker")
internet_users = Actor("Internet Users")

# Corporate assets
user_office1 = Actor("Branch Office 1 Users")
user_office2 = Actor("Branch Office 2 Users")
user_head = Actor("Head Office Users")

firewall = Server("Firewall")
firewall.controls = Controls()
firewall.controls.protectsAgainstDoS = False  # For DoS threats

switch = Server("Core Switch")

# DMZ assets
web_server = Server("Web Server")
web_server.inBoundary = dmz
web_server.controls = Controls()
web_server.controls.sanitizesInput = False  # For injection threats
web_server.controls.checksInputBounds = False  # For overflow threats
web_server.implementsAuthenticationScheme = False  # For auth threats

# Internal assets
db_server = Datastore("Database Server")
db_server.inBoundary = corporate_net
db_server.controls = Controls()
db_server.encryptionAtRest = False  # For data exposure
db_server.isSql = True  # For SQL injection

app_server = Server("Application Server")
app_server.inBoundary = corporate_net

file_server = Datastore("File Server")
file_server.inBoundary = corporate_net
file_server.controls = Controls()
file_server.encryptionAtRest = False  # For data exposure

# Cloud assets
saas_crm = Server("CRM SaaS")
saas_crm.inBoundary = cloud
saas_crm.controls = Controls()

saas_email = Server("Email SaaS")
saas_email.inBoundary = cloud

iaas = Server("Cloud IaaS")
iaas.inBoundary = cloud

# ===== Define Data Flows =====
# Create dataflows and set security properties
public_requests = Dataflow(internet_users, firewall, "Public requests")
attack_traffic = Dataflow(attacker, firewall, "Attack traffic")
filtered_traffic = Dataflow(firewall, web_server, "Filtered traffic")
db_queries = Dataflow(web_server, db_server, "DB queries")
internal_access = Dataflow(user_head, app_server, "Internal app access")
crm_sync = Dataflow(app_server, saas_crm, "CRM data sync")
cloud_backups = Dataflow(file_server, iaas, "Cloud backups")

# Set data classification for information disclosure threats
db_queries.data = type('', (), {'classification': 'SECRET'})()
db_queries.encrypted = False

# ===== Generate DFD Diagram =====
dot_code = tm.dfd()
with open("threat_model.dot", "w") as f:
    f.write(dot_code)
    
!dot -Tpng threat_model.dot -o threat_model.png

print("\n✅ DFD diagram generated: threat_model.png")
Image('threat_model.png')

# ===== Threat Definitions =====
threats = [
    # Authentication Bypass
    {
        "SID": "AA01",
        "target": ["Server"],
        "description": "Authentication Abuse/Bypass",
        "severity": "High",
        "condition": "not target.implementsAuthenticationScheme",
        "mitigation": "Implement strong authentication mechanisms"
    },
    
    # SQL Injection
    {
        "SID": "INP01",
        "target": ["Server", "Datastore"],
        "description": "SQL Injection",
        "severity": "High",
        "condition": "target.isSql and not target.controls.sanitizesInput",
        "mitigation": "Use parameterized queries and input validation"
    },
    
    # Data Exposure
    {
        "SID": "DS01",
        "target": ["Datastore"],
        "description": "Sensitive Data Exposure",
        "severity": "High",
        "condition": "not target.encryptionAtRest",
        "mitigation": "Enable encryption for data at rest"
    },
    
    # DoS
    {
        "SID": "DO01",
        "target": ["Server"],
        "description": "Denial of Service",
        "severity": "Medium",
        "condition": "not target.controls.protectsAgainstDoS",
        "mitigation": "Implement DoS protection mechanisms"
    },
    
    # Info Disclosure
    {
        "SID": "I01",
        "target": ["Dataflow"],
        "description": "Information Disclosure in Transit",
        "severity": "High",
        "condition": "hasattr(target, 'data') and not target.encrypted",
        "mitigation": "Encrypt sensitive data in transit"
    }
]

with open("threats.json", "w") as f:
    json.dump(threats, f)

tm.threatsFile = "threats.json"

# ===== Run Threat Analysis =====
tm.process()

# ===== Print Threat Report =====
print("\n=== STRIDE Threat Report ===")
if hasattr(tm, 'threats') and tm.threats:
    for threat in tm.threats:
        print(f"\n🔒 Threat: {threat.description}")
        print(f"   Component: {threat.target.name}")
        print(f"   Severity: {threat.severity}")
        print(f"   Mitigation: {threat.mitigation}")
else:
    print("No threats identified. Check component properties and threat conditions.")

# Restore original arguments
sys.argv = original_argv
