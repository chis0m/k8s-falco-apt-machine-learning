from datetime import datetime

# Same keyword list as notebook 02, section on suspicious_cmd_flag
SUSPICIOUS_KEYWORDS = ["curl", "wget", "nc ", "chmod 777", "base64", "/etc/shadow", "history"]


def extract_mitre_tactic(tags):
    # same rule as notebook 02: first tag starting with "mitre_", else "none"
    if not isinstance(tags, list):
        return "none"
    for tag in tags:
        if isinstance(tag, str) and tag.startswith("mitre_"):
            return tag
    return "none"


def has_suspicious_keyword(cmdline):
    cmdline = str(cmdline).lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in cmdline:
            return 1
    return 0


def parse_raw_alert(raw_alert: dict) -> dict:
    output_fields = raw_alert.get("output_fields", {})

    cmdline = output_fields.get("proc.cmdline", "")
    tags = raw_alert.get("tags", [])
    time_str = raw_alert.get("time")

    # pull just the hour out of the timestamp, same as notebook 02
    if time_str:
        hour = datetime.fromisoformat(time_str.replace("Z", "+00:00")).hour
    else:
        hour = 0

    return {
        "priority": raw_alert.get("priority", "Notice"),
        "rule": raw_alert.get("rule", "unknown"),
        "mitre_tactic": extract_mitre_tactic(tags),
        "user_name": output_fields.get("user.name") or "unknown",
        "image_repo": output_fields.get("container.image.repository") or "unknown",
        "hour": hour,
        "cmdline_length": len(str(cmdline)),
        "suspicious_cmd_flag": has_suspicious_keyword(cmdline),
        "has_process_detail": 1 if output_fields.get("proc.name") is not None else 0,
        "has_file_event": 1 if output_fields.get("fd.name") is not None else 0,
    }