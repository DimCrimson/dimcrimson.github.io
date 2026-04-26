import os
import requests
import sys
from wcwidth import wcswidth
from datetime import datetime, timezone, timedelta

# =========================
# CONFIG
# =========================

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"

MICROSOFT_TENANT_IDS = {"f8cdef31-a31e-4b4a-93e4-5f571e91255a",
                        "cdc5aeea-15c5-4db6-b079-fcadd2505dc2"}

CARD_WIDTH = 120

# =========================
# DATA MODELS
# =========================
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
BASE_SCORE_MAP = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
PRIORITY_MAP = {0: "P0", 1: "P1", 2: "P2", 3: "P3"}

FORCE_CRITICAL_SCOPES = {
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All"
}

LOW_SCOPES = {
    "User.Read",
    "openid",
    "profile",
    "email"
}

MEDIUM_SCOPES = {
    "Mail.Read",
    "Files.Read",
    "offline_access",
    "User.Read.All"
}

# =========================
# AUTH
# =========================
def get_token():
    try:
        data = {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials"
        }

        r = requests.post(TOKEN_URL, data=data)

        if not r.ok:
            try:
                error_body = r.json()
            except Exception:
                error_body = r.text

            print("[AUTH ERROR] Failed to authenticate with SPN credentials.")
            print(f"[DETAIL] HTTP {r.status_code}")
            print(f"[BODY] {error_body}")
            sys.exit(1)

        return r.json()["access_token"]

    except requests.exceptions.RequestException as e:
        print("[AUTH ERROR] Network or HTTP request failure during authentication.")
        print(f"[DETAIL] {repr(e)}")
        sys.exit(1)

    except Exception as e:
        print("[AUTH ERROR] Unexpected authentication failure.")
        print(f"[DETAIL] {repr(e)}")
        sys.exit(1)

# =========================
# GRAPH UTILS
# =========================
def graph_get(url, token):
    headers = {"Authorization": f"Bearer {token}"}
    results = []

    while url:
        r = requests.get(url, headers=headers)
        r.raise_for_status()
        data = r.json()

        results.extend(data.get("value", []))
        url = data.get("@odata.nextLink")

    return results

# =========================
# HELPERS
# =========================
def validate_config():
    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
        print("[CONFIG ERROR] Missing required environment variables.")
        sys.exit(1)

def log_step(msg):
    print(f"[+] {msg}")

def parse_time(ts):
    try:
        if ts.endswith("Z"):
            ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except Exception:
        return None

def is_external(sp):
    owner = sp.get("appOwnerOrganizationId")
    return owner and owner != TENANT_ID and owner not in MICROSOFT_TENANT_IDS

def is_verified_publisher(pub):
    if not pub:
        return False
    vid = pub.get("verifiedPublisherId")
    return vid is not None and vid != "None" and vid != ""

# =========================
# INDEX BUILDERS
# =========================
def build_external_spn_index(sps):
    index = {}

    for sp in sps:
        if is_external(sp):
            index[sp["id"]] = {
                "identity": sp,
                "oauth_grants": [],
                "app_roles": []
            }

    return index

# =========================
# ATTACHERS
# =========================
def attach_oauth_grants(grants, index, user_cache):
    for g in grants:
        cid = g.get("clientId")

        if cid in index:
            principal = g.get("principalId")

            user = (
                "ADMIN CONSENT (ALL USERS)"
                if g.get("consentType") == "AllPrincipals"
                else user_cache.get(principal, principal)
            )

            index[cid]["oauth_grants"].append({
                "scopes": g.get("scope", "").split(),
                "user": user,
                "consentType": g.get("consentType")
            })

def attach_app_roles(token, index, sp_cache):
    headers = {"Authorization": f"Bearer {token}"}

    for sp_id, sp_data in index.items():
        url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_id}/appRoleAssignments"

        r = requests.get(url, headers=headers)
        if r.status_code != 200:
            continue

        for role in r.json().get("value", []):
            res = role.get("resourceId")
            rid = role.get("appRoleId")

            resource = sp_cache.get(res)

            if resource:
                role_name = None

                for rdef in resource.get("appRoles", []):
                    if rdef.get("id") == rid:
                        role_name = rdef.get("value")

                sp_data["app_roles"].append({
                    "resource": resource.get("displayName"),
                    "role": role_name or rid
                })

# =========================
# SEVERITY ENGINE
# =========================
def classify_scope(scope: str) -> str:
    if scope in LOW_SCOPES:
        return "LOW"
    if scope in MEDIUM_SCOPES:
        return "MEDIUM"
    return "HIGH"


def compute_base_severity(oauth_grants):
    levels = []

    for g in oauth_grants:
        for s in g.get("scopes", []):
            levels.append(classify_scope(s))

    if "HIGH" in levels:
        return "HIGH"
    if "MEDIUM" in levels:
        return "MEDIUM"
    return "LOW"


def escalate(level: str, step: int) -> str:
    idx = SEVERITY_ORDER.index(level)
    return SEVERITY_ORDER[min(idx + step, len(SEVERITY_ORDER) - 1)]


def compute_severity(oauth_grants, app_roles):
    # 1. FORCE CRITICAL OVERRIDE
    for g in oauth_grants:
        for s in g.get("scopes", []):
            if s in FORCE_CRITICAL_SCOPES:
                return "CRITICAL"

    # 2. BASELINE FROM SCOPES
    severity = compute_base_severity(oauth_grants)

    # 3. ADMIN CONSENT ESCALATION (+1)
    if any(g.get("consentType") == "AllPrincipals" for g in oauth_grants):
        severity = escalate(severity, 1)

    # 4. APPLICATION PERMISSIONS ESCALATION (+2)
    if app_roles:
        severity = escalate(severity, 2)

    return severity


# =========================
# PRIORITY ENGINE
# =========================
def compute_priority(severity, activity):
    score = BASE_SCORE_MAP.get(severity, 2)

    if activity == "ACTIVE":
        score = max(0, score - 2)
    elif activity == "RECENT":
        score = max(0, score - 1)

    return PRIORITY_MAP[score]

# =========================
# LOGS ENGINE
# =========================
def get_signins_batch(token):
    url = "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=1000"
    return graph_get(url, token)


def get_audits_batch(token):
    url = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$top=1000"
    return graph_get(url, token)

def safe_fetch_logs(func, *args, name="logs"):
    try:
        return func(*args)
    except Exception as e:
        print(f"[WARN] Failed to fetch {name}: {repr(e)}")
        return []

def build_activity_index(signins):
    index = {}

    for s in signins:

        app_id = s.get("appId") or s.get("appDisplayName")

        ts = s.get("createdDateTime")

        if not app_id or not ts:
            continue

        index.setdefault(app_id, []).append(ts)

    return index


def extract_audit_flags(audits):
    flags = {}

    for a in audits:

        app_id = None

        for tr in a.get("targetResources", []):
            app_id = tr.get("id")

        if not app_id:
            continue

        flags.setdefault(app_id, []).append(a.get("activityDisplayName"))

    return flags

def compute_activity_signal(signins, audit_events=None):
    if not signins:
        signins = []

    if audit_events is None:
        audit_events = []

    now = datetime.now(timezone.utc)

    has_active = False
    has_recent = False

    # 1. SIGN-IN SIGNAL
    for ts in signins:
        t = parse_time(ts)
        if not t:
            continue

        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)

        if t > now - timedelta(days=7):
            has_active = True
        elif t > now - timedelta(days=90):
            has_recent = True

    # 2. AUDIT BOOST
    audit_boost = False

    for e in audit_events:
        if e in [
            "Consent to application",
            "Add service principal",
            "Add app role assignment",
            "Add delegated permission grant"
        ]:
            audit_boost = True
            break

    # 3. FINAL DECISION
    if has_active or audit_boost:
        return "ACTIVE"

    if has_recent:
        return "RECENT"

    return "INACTIVE"

# =========================
# OUTPUT CARD
# =========================
def severity_badge(severity):
    return {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢"
    }.get(severity, "⚪")

def activity_badge(activity):
    return {
        "ACTIVE": "⚡",
        "RECENT": "🕒",
        "INACTIVE": "⚫"
    }.get(activity, "⚪")

def priority_badge(priority):
    return {
        "P0": "🚨",
        "P1": "⚠️",
        "P2": "📌",
        "P3": "💤"
    }.get(priority, "❓")

def format_line(content=""):
    content = str(content)
    max_len = CARD_WIDTH - 4
    width = wcswidth(content)

    if width > max_len:
        content = content[:max_len]
        width = wcswidth(content)

    padding = max_len - width
    return f"│ {content}{' ' * padding} │"

def print_spn_card(spn, severity, priority, activity):
    identity = spn["identity"]
    oauth = spn["oauth_grants"]
    roles = spn["app_roles"]

    pub = identity.get("verifiedPublisher")
    pub_str = pub.get("displayName") if is_verified_publisher(pub) else "UNVERIFIED"

    sev_icon = severity_badge(severity)
    prio_icon = priority_badge(priority)
    act_icon = activity_badge(activity)

    line = "─" * (CARD_WIDTH - 2)

    print(f"\n┌{line}┐")
    print(format_line(f"{identity.get('displayName')} — {sev_icon} {severity}"))
    print(f"├{line}┤")

    print(format_line(f"AppId: {identity.get('appId')}"))
    print(format_line(f"External Tenant: {identity.get('appOwnerOrganizationId')}"))
    print(format_line(f"Publisher: {pub_str}"))
    print(format_line(f"Score: {severity}"))
    print(format_line(f"Priority: {prio_icon} {priority}"))
    print(format_line(f"Activity: {act_icon} {activity}"))

    print(f"├{line}┤")
    print(format_line("Delegated Permissions"))

    if oauth:
        for g in oauth:
            print(format_line(f"• {g['user']}"))
            print(format_line(f"  Scopes: {', '.join(g['scopes'])}"))
    else:
        print(format_line("(none)"))

    print(f"├{line}┤")
    print(format_line("Application Permissions"))

    if roles:
        for r in roles:
            print(format_line(f"• {r['resource']}"))
            print(format_line(f"  Role: {r['role']}"))
    else:
        print(format_line("(none)"))

    print(f"└{line}┘")

# =========================
# MAIN
# =========================
def main():
    validate_config()
    token = get_token()

    log_step("Fetching service principals...")
    sps = graph_get(
        "https://graph.microsoft.com/v1.0/servicePrincipals?"
        "$select=id,appId,displayName,appOwnerOrganizationId,verifiedPublisher",
        token
    )

    log_step("Building SPN index...")
    index = build_external_spn_index(sps)

    user_cache = {
        u["id"]: u["userPrincipalName"]
        for u in graph_get(
            "https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName",
            token
        )
    }

    log_step("Fetching app roles...")
    sp_cache = {
        sp["id"]: sp
        for sp in graph_get(
            "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,displayName,appRoles",
            token
        )
    }

    log_step("Fetching OAuth grants...")
    grants = graph_get(
        "https://graph.microsoft.com/v1.0/oauth2PermissionGrants",
        token
    )

    attach_oauth_grants(grants, index, user_cache)
    attach_app_roles(token, index, sp_cache)

    log_step("Fetching sign-in logs...")
    signins = safe_fetch_logs(get_signins_batch, token, name="signins_90d")

    log_step("Fetching audit logs...")
    audits = safe_fetch_logs(get_audits_batch, token, name="audits_90d")

    activity_index = build_activity_index(signins)
    audit_flags = extract_audit_flags(audits)

    activity = compute_activity_signal(signins, audits)

    log_step("Evaluating SPNs...")
    for sp in index.values():
        oauth = sp.get("oauth_grants", [])
        roles = sp.get("app_roles", [])

        severity = compute_severity(oauth, roles)

        app_id = sp["identity"].get("appId")
        signins = activity_index.get(app_id, [])
        audits = audit_flags.get(app_id, [])
        activity = compute_activity_signal(signins, audits)
        priority = compute_priority(severity, activity)

        print_spn_card(sp, severity, priority, activity)

if __name__ == "__main__":
    main()
