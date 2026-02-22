import json
from datetime import datetime


def log_alert(src_ip, attack_type, threat_score, severity):
    alert = {
        "timestamp": datetime.utcnow().isoformat(),
        "src_ip": src_ip,
        "attack_type": attack_type,
        "threat_score": threat_score,
        "severity": severity
    }

    with open("alerts.log", "a") as f:
        f.write(json.dumps(alert) + "\n")

    print(f"[ALERT LOGGED] {attack_type} from {src_ip}")
