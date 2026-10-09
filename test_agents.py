
from pprint import pprint
from agent_engine import generate_investigation

test_alert = {
    "Alert ID": "SOC-2001",
    "Alert Type": "Suspicious Login",
    "Asset": "Production Server",
    "Severity": "High",
    "Details": (
        "Multiple failed login attempts followed by an unusual login "
        "from a known malicious IP"
    ),
    "Source": "SIEM"
}

result = generate_investigation(test_alert)
pprint(result)
