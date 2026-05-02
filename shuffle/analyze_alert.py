import json
import re

raw_data = """$exec"""

# --- SAFE INPUT HANDLING ---
if not raw_data or raw_data.strip() == "":
    print(json.dumps({
        "route": "skip",
        "reason": "empty input received"
    }))
    exit()

try:
    alert = json.loads(raw_data)
except Exception as e:
    print(json.dumps({
        "route": "skip",
        "reason": f"invalid json: {str(e)}"
    }))
    exit()

# --- EXTRACTION ---
data       = alert.get("data", {})
srcip      = data.get("srcip", "unknown")
url        = data.get("url", "")
full_log   = alert.get("full_log", "")
http_code  = str(data.get("id", "0"))
user_agent = data.get("user_agent", "")
time_taken = float(data.get("time_taken", 0) or 0)
bytes_resp = int(data.get("bytes", 0) or 0)
timestamp  = alert.get("timestamp", "")

# --- VALIDATION ---
if srcip in ["unknown", "0.0.0.0"] and not url and not full_log:
    print(json.dumps({
        "route": "skip",
        "reason": "empty alert"
    }))
    exit()

combined = (url + full_log).upper()

# --- SQLi DETECTION ---
sleep_match = re.search(
    r'SLEEP\((\d+)\)|PG_SLEEP\((\d+)\)|WAITFOR\s+DELAY|DBMS_LOCK\.SLEEP',
    combined
)

injection_type = "Unknown"

if sleep_match or "WAITFOR DELAY" in combined or "DBMS_LOCK" in combined:
    injection_type = "Time-Based"

elif any(k in combined for k in [
    "EXTRACTVALUE", "UPDATEXML",
    "CONVERT(INT", "CAST(",
    "CTXSYS.DRITHSX", "UTL_INADDR",
    "INFORMATION_SCHEMA",
    "@@VERSION", "VERSION()"
]):
    injection_type = "Error-Based"

elif any(k in combined for k in [
    "AND 1=1", "AND 1=2",
    "OR 1=1", "OR 1=2",
    "SUBSTRING(", "SUBSTR(",
    "ASCII(", "CHAR(",
    "MID(", "LENGTH("
]):
    injection_type = "Boolean-Blind"

elif any(k in combined for k in [
    "UNION SELECT",
    "UNION ALL SELECT",
    "UNION DISTINCT SELECT"
]):
    injection_type = "Union-Based"

elif any(k in combined for k in [
    "'; ", '"; ',
    "1; DROP", "1; INSERT",
    "1; UPDATE", "1; DELETE",
    "1; EXEC", "1; EXECUTE"
]):
    injection_type = "Stacked-Queries"

elif any(k in combined for k in [
    "UTL_HTTP", "UTL_FILE",
    "LOAD_FILE", "INTO OUTFILE",
    "INTO DUMPFILE",
    "OPENROWSET", "OPENDATASOURCE"
]):
    injection_type = "Out-of-Band"

elif any(k in combined for k in [
    "INSERT INTO", "UPDATE SET",
    "STORED", "SECOND ORDER"
]):
    injection_type = "Second-Order"

elif any(k in combined for k in [
    "/*!", "/**/",
    "0X", "%27", "%20OR%20"
]):
    injection_type = "Evasion-Based"

elif any(k in combined for k in [
    "' OR '1'='1",
    "' OR 1=1--",
    "ADMIN'--",
    "' OR 'X'='X",
    "') OR ('1'='1"
]):
    injection_type = "Auth-Bypass"

elif any(k in combined for k in [
    "LOAD_FILE(", "SELECT INTO OUTFILE",
    "UTL_HTTP.REQUEST",
    "XP_DIRTREE", "XP_CMDSHELL"
]):
    injection_type = "DNS-Exfiltration"

# --- INJECTION SUCCESS CHECK ---
sleep_seconds = 0
injection_succeeded = False

if sleep_match:
    sleep_seconds = int(
        sleep_match.group(1) or sleep_match.group(2) or 0
    )
    if sleep_seconds > 0 and abs(time_taken - sleep_seconds) <= 2:
        injection_succeeded = True

if http_code in ["200", "500"]:
    injection_succeeded = True

if bytes_resp > 800:
    injection_succeeded = True

# --- PRIORITY ---
if injection_succeeded:
    priority = "P1"
    status   = "SUCCESSFUL INJECTION"
elif http_code in ["403", "404"]:
    priority = "P3"
    status   = "BLOCKED"
else:
    priority = "P2"
    status   = "FAILED - multiple attempts"

# --- USER AGENT CHECK ---
suspicious_ua = any(t in user_agent.lower() for t in [
    "sqlmap", "curl", "python",
    "nikto", "havij", "pangolin",
    "netsparker", "acunetix", "nmap"
])

# --- TAGS ---
if priority == "P1":
    tags = ["sqli", "wazuh", injection_type, "P1", "REQUIRES-ACTION"]
elif priority == "P2":
    tags = ["sqli", "wazuh", injection_type, "P2", "MONITOR"]
else:
    tags = ["sqli", "wazuh", injection_type, "P3", "SILENT-LOG"]

# --- OUTPUT ---
result = {
    "srcip": srcip,
    "status": status,
    "priority": priority,
    "injection_type": injection_type,
    "http_code": http_code,
    "bytes_response": bytes_resp,
    "possible_exfil": bytes_resp > 800,
    "suspicious_ua": suspicious_ua,
    "user_agent": user_agent,
    "timestamp": timestamp,
    "sleep_seconds": sleep_seconds,
    "tags": tags
}

# --- FINAL ROUTING ---
if srcip in ["unknown", "0.0.0.0"] or not srcip:
    route = "skip"
elif priority == "P3":
    route = "silent"
else:
    route = "full"

result["route"] = route

# --- PRINT RESULT ---
print(json.dumps(result))
