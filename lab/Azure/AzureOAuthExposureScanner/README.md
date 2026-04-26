# AzureOAuthExposureScanner

A lightweight Azure AD / Entra ID security scanner focused on identifying **external service principals exposed via OAuth consent grants and application role assignments**, with activity-based prioritization.

The tool correlates:
- External Service Principals (foreign tenants)
- OAuth2 delegated consent grants
- Application role assignments
- Sign-in activity (service principal + user sign-ins)
- Directory audit signals

It produces a risk-based prioritization model to highlight potential OAuth consent abuse and phishing-enabled applications.

## Risk Model (Severity & Priority)
### 🔴 Severity 

Severity represents what an application/service principal can do if compromised or misused.
It is derived strictly from OAuth permission exposure:

`LOW`: Basic delegated permissions (e.g. User.Read). No tenant-wide or sensitive access.

`MEDIUM`: Tenant-wide read access to common data. Examples: User.Read.All, Mail.Read, Files.Read.All.

`HIGH`: Broad or sensitive data access across users/services. Multiple or combined sensitive permissions.

`CRITICAL`: Privilege-sensitive or directory-impacting permissions. Includes role assignment, directory write, or consent abuse paths.

### 🚦 Priority 

Priority represents how urgently a service principal should be investigated.
It is derived in two steps:

1. Base mapping (severity → priority)

| Severity | Base Priority |
| -------- | ------------- |
| CRITICAL | P0            |
| HIGH     | P1            |
| MEDIUM   | P2            |
| LOW      | P3            |

2. Activity adjustment 

Priority is then adjusted using observed activity signals:

| Activity State | Time Window             | Priority Effect                 |
| -------------- | ----------------------- | ------------------------------- |
| ACTIVE         | ≤ 7 days                | Increases urgency significantly |
| RECENT         | ≤ 90 days               | Slight increase in urgency      |
| INACTIVE       | > 90 days / no activity | No change applied               |

---

## 🔐 Requirements

This tool requires an Azure Service Principal with Microsoft Graph access.

Credentials must be provided via environment variables:

`Bash`
```bash
export TENANT_ID=xxx
export CLIENT_ID=xxx
export CLIENT_SECRET=xxx
```
`Powershell`

```powershell
$env:TENANT_ID="xxx"
$env:CLIENT_ID="xxx"
$env:CLIENT_SECRET="xxx"
```

### Required API permissions for the SPN
- `AuditLog.Read.All`
- `Directory.Read.All`
- `User.Read.All`
- `Application.Read.All`
- `DelegatedPermissionGrant.Read.All`
> Admin consent is required for all permissions.

---

## ⚙️ Execution

```bash
pip install -r requirements.txt
python oauth_scanner.py
```

---

## 🔗 Links

- GitHub Repository: [https://github.com/DimCrimson/AzureOAuthExposureScanner](https://github.com/DimCrimson/AzureOAuthExposureScanner)
