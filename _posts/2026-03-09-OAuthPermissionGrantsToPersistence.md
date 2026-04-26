---
title: Abusing OAuth Permission Grants for Tenant Persistence
date: 2026-03-09 23:00:00 +0000
description: OAuth Permission Grants Abuse in Microsoft Entra ID - Attack Path Analysis and MITRE ATT&CK Mapping.
comments: false
toc: true
categories: [Azure, Azure Entra ID]
tags: [aad,entra id,tokens,azure,identity,security,consent-phishing] # TAG names should always be lowercase
---

**⚠️ Attention**: *This article focuses on cross-tenant OAuth consent grant abuse involving external applications accessing resources in the target tenant. Intra-tenant consent abuse scenarios are out of scope.*

# OAuth Consent Abuse in Microsoft Entra ID: Attack Paths, MITRE ATT&CK Mapping, and Detection Gaps

## 1. Introduction

*Identity is the new perimeter* in cloud security: This is mainly because attackers traditionally focused on network and infrastructure perimeters, whereas the cloud has shifted security boundaries towards identity and access control.

In cloud environments, identity is the key element enabling control over data, APIs, and network boundaries, which makes identity misconfiguration a primary target.
More specifically, attackers increasingly target *applications* and OAuth consent mechanisms to gain a persistent foothold in cloud environments, leveraging consent grants that can persist beyond password resets and MFA enforcement.

These applications are represented in Entra ID by application objects and their associated service principals (Enterprise Applications) and can be granted OAuth permissions, including access to APIs such as Microsoft Graph.

## 2. OAuth Grants as a Security Boundary

Before examining how Entra ID applications can be abused, let's first look at how permissions are granted to applications.
Entra ID supports two types of permissions that can be granted to applications:

- **Delegated**: application acts on behalf of a signed-in user with privileges constrained by the user's permissions and the granted scopes. These are a common target for consent phishing, as users can be tricked into approving the permissions.
- **Application**: application acts as itself with no user context. Admin consent is always required for these permissions as they're scoped to the whole tenant.

A permission grant defines what an application is authorized to access within the tenant and across its resource APIs. Permissions are approved through the consent process, either by a user or an administrator.

These grants are subject to consent policies, which by default rely on Microsoft-managed settings.

![DefaultMSConsentPolicies](/assets/Images/2026-03-09-OAuthPermissionsGrant/PermissionGrantPolicies.png)

Once consent is granted, the application can then request OAuth tokens to access the approved APIs, either through user-based OAuth flows (with refresh tokens for delegated permissions) or through client credentials authentication for application permissions.

Because these permission grants allow applications to obtain tokens and access APIs programmatically, abusing them can provide attackers with durable access to tenant resources. This makes permission grants a critical security boundary in Entra ID.

## 3. Consent-Driven Attack Flows

This section describes how OAuth consent mechanisms can be abused to establish persistent access to Microsoft Entra ID resources, without relying on credential theft.

Rather than targeting passwords or secrets, this model exploits permission grants to transition from identity-level trust into sustained access to protected APIs such as Microsoft Graph.

Two primary attack paths implement this model: `delegated permissions` (user consent) and `application permissions` (admin consent).
Both ultimately result in the issuance of OAuth tokens that can be used to interact with tenant resources, either in a user context or application context.

OAuth consent abuse operates at the identity control plane, where permissions are defined, while the resulting tokens are used at the data plane to access resources such as Microsoft Graph.

### Delegated Permissions - User Consent Abuse

Delegated permissions require the presence of an authenticated user and are granted through an interactive OAuth 2.0 authorization flow. In this process, the client application requests access to specific scopes, which the user must explicitly consent to before the application can act on their behalf.

Permissions that only require the user's consent are listed with the `AdminConsentRequired` set to 'No' with, on the default Entra ID configuration, the exclusion of some permissions through a [consent policy managed by Microsoft](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-app-consent-policies?pivots=ms-graph#microsoft-recommended-user-consent-policy).
Microsoft documentation does not always enumerate all permissions included or excluded under these policies. Full visibility therefore requires exploring the PermissionGrantPolicies object via CLI.

The [linked PowerShell script](https://raw.githubusercontent.com/DimCrimson/dimcrimson.github.io/refs/heads/main/lab/Azure/consentPoliciesCrawler.ps1) retrieves the policies applied in the tenant and the permissions they govern.

Keep in mind that this list is subject to updates on Microsoft's side, so the script must be periodically executed to get the latest exclusion list.

A list of GraphAPI delegated permissions can be [extrapolated from the official Microsoft documentation](https://learn.microsoft.com/en-us/graph/permissions-reference#all-permissions).

**⚠️ Attention:**  *In this article, “interactive” refers to the OAuth authorization flow where user interaction is required to obtain an authorization code, and should not be confused with [MSAL token acquisition methods](https://learn.microsoft.com/en-us/entra/msal/msal-authentication-flows#interactive-and-non-interactive-authentication).*

The scenario demonstrated in this article relies on the OAuth 2.0 authorization code grant. The interaction can be summarized as follows:

1. The user is directed to an authorization URL controlled by the application.
2. The user authenticates with Microsoft Entra ID.
3. The user is prompted to grant delegated permissions to the application.
4. Upon consent, Microsoft Entra ID redirects the browser to the configured redirect URI with an authorization code.
5. The application redeems this authorization code at the token endpoint.
6. The application obtains tokens representing the user, including an access token and potentially a refresh token.

To see how this plays out in practice, I’ll run through a demonstration leveraging a two-tenant setup:
- **Source Tenant**: The tenant hosting the application registration, representing an attacker-controlled environment.
- **Target Tenant**: The tenant where the targeted user identities reside, along with the resources and data accessible to those users.

<small><span style="color:red; display:block; text-align:center;"> All resources and configurations demonstrated in this article were created in a controlled testing environment for research purposes only. They are intentionally non-realistic, as clearly indicated by their naming conventions and redirect URIs, and are not designed to replicate or be used in real-world phishing scenarios. </span></small>

It all starts with an App Registration in the source tenant that is enabled for multi-tenant use cases:

![ImageOfAppRegistrationToAdd](/assets/Images/2026-03-09-OAuthPermissionsGrant/EntraIDAppRegistration.png)

**⚠️ Attention:** *A warning indicates that end users cannot grant consent to newly registered multi-tenant applications unless the publisher is first verified, a restriction enforced by default since 2020.*

![UnverifiedPublisherWarning](/assets/Images/2026-03-09-OAuthPermissionsGrant/VerifiedPublishersForUserConsent.png)

Verifying an application requires having a custom domain as default onmicrosoft.com are not supported for verification. As well as creating a Microsoft Partner Center (MPN) account and associating with the application.

The `redirectUriSettings` parameter must point to a compute resource that will host the OAuth flow logic to inspect and retrieve the user's tokens.

````json
 "signInAudience": "AzureADMultipleOrgs"
 "web": {
      "homePageUrl": null,
      "implicitGrantSettings": {
        "enableAccessTokenIssuance": false,
        "enableIdTokenIssuance": false
      },
      "logoutUrl": null,
      "redirectUriSettings": [
        {
          "index": null,
          "uri": "https://oauthgrantdemo-gqh0e7c7feh7evdt.northeurope-01.azurewebsites.net/callback"
        }
      ],
      "redirectUris": [
        "https://oauthgrantdemo-gqh0e7c7feh7evdt.northeurope-01.azurewebsites.net/callback"
      ]
    }
````

 I opted for a simple Azure Web App with two simple endpoints:

- **/** : The landing page for my demo web app, this endpoint will build the URL to initiate the user consent grant workflow for our App Registration delegated permissions.
- **/callback** : The endpoint that is configured as the redirectUri for my App Registration. This endpoint will receive the object returned after the user grants the consent for our App Registration, then will call the Microsoft /token endpoint to complete the OAuth flow and retrieve the user's tokens.

#### Authorization Request Construction: Breaking Down the Delegated Permissions URL

So the first step is to redirect the targeted user to the OAuth authorization endpoint and initiate the Authorization Code flow. Let's break down how this URL is built with a focus on the main parameters:

```text
    https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?
    client_id=f6d1cd86-...
    &response_type=code
    &redirect_uri=...
    &response_mode=query
    &scope=openid%20profile%20email%20offline_access%20User.Read
    &state=...
    &prompt=consent
```

- **`client_id`** - *Mandatory*: Identifies the application (App Registration) requesting access. This value matches the `Application (client) ID` of the application initiating the authorization flow.
- **`response_type`**: Specifies the type of response expected from the authorization server, `code` indicates the authorization code flow is being used.
- **`redirect_uri`** - *Mandatory*: The URL where Microsoft Entra ID sends the user after authentication and consent. This must match the redirect URI configured in the application, otherwise the request fails.
- **`response_mode`**: Defines how the authorization response is returned. For example, `query` means the authorization code is appended to the redirect URI as a query parameter.
- **`scope`** - *Mandatory*: The permissions requested by the application which includes:
  - OpenID scopes (`openid`, `profile`, `email`) for authentication-related claims  
  - `offline_access` allows the application to obtain a refresh token, enabling it to request new access tokens without further user interaction, effectively extending access beyond the user's presence.
  - API scopes (e.g., `User.Read`) for delegated access to resources. These scopes are exposed by resource applications (such as Microsoft Graph or Azure services) and, by default (unless restricted by consent policies), can be granted through user consent. `.default` is a special scope value that instructs the authorization server to issue a token containing all permissions for the targeted resource that have already been consented to. If no prior consent exists, it triggers a consent prompt for all configured delegated permissions for that resource.

![GraphAPIReadFilesPermission](/assets/Images/2026-03-09-OAuthPermissionsGrant/DelegatedPermissionsFiles.png)

- **`state`**: A value generated by the client to maintain request integrity. It is returned unchanged by the authorization server and is used to prevent CSRF attacks.
- **`prompt`**: Controls user interaction behavior. For example:
  - `consent` forces the consent prompt to appear. Other values can influence whether the user is re-authenticated or forced to re-consent

  **⚠️ Attention** *If consent has not been previously granted, using prompt=none will cause the request to fail.*

The above list of parameters if not exhaustive, the complete list of parameters with Authorization code is available on [Microsoft's documentation](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow?#request-an-authorization-code).

#### User Authentication and Consent Grant in Microsoft Entra ID

The user completes authentication and is prompted to grant consent for the application:
![DelegatedPermissionsPrompt](/assets/Images/2026-03-09-OAuthPermissionsGrant/DelegatedPermissionsUserConsent.png)
Behind the scenes, this sends the authorization code back to the endpoint specified in the redirect URI.

#### Authorization Code Redemption and Token Acquisition

The callback endpoint receives the authorization code and calls the **/token** endpoint. The response includes a refresh token (*offline_access* was requested), enabling the application to maintain access by requesting new access tokens without further user interaction.

![DelegatedPermissionTokens](/assets/Images/2026-03-09-OAuthPermissionsGrant/DelegatedPermissionTokensReturned.png)

The user consent grant is materialized in Entra ID as an `OAuth2PermissionGrant` object associated with the principalId representing the user for whom the delegated permissions are granted:

![OAuth2PermissionGrantObject](/assets/Images/2026-03-09-OAuthPermissionsGrant/DelegatedPermissionArtifactCreated.png)

In this multi-tenant scenario, this models trust externalization: a resource tenant accepts delegated access for an application originating from another tenant, creating a powerful cross-boundary attack vector.

In a malicious attempt, the flow is:
![DelegatedPermissionsWorkflow](/assets/Images/2026-03-09-OAuthPermissionsGrant/delegatedPermissionsWorkflow.png)

While delegated permissions rely on user interaction and context, application permissions remove the user entirely from the equation, shifting the attack surface from user deception to administrative trust.

### Application Permissions - Admin Consent Abuse

The second type of access for applications is the app-only permissions. These permissions must be consented by an administrator, which reduces the set of identities that can approve the consent. In contrast, the impact of such consent is higher as the permissions are more important and can be scoped to the whole tenant.

Administrator consent can be confirmed in the azure portal, via CLI (e.g. Graph Powershell) or as preferred by the phishing attacks, through the **/adminconsent** endpoint:

```text
https://login.microsoftonline.com/common/adminconsent?
client_id=f6d1cd86-...
&redirect_uri=...
&state=...
```

Contrary to the user consent grant, the `scope` parameter is not required as the request is evaluated against the application’s pre-configured application permissions.

Moreover, the admin grant does not return an authorization code or tokens linked to the administrator account that proceeded to grant the permission. It creates an `AppRoleAssignment` artifact linked to the Service Principal object:

![ApplicationPermissionArtifactCreated](/assets/Images/2026-03-09-OAuthPermissionsGrant/ApplicationPermissionArtifactCreated.png)

In a malicious attempt, the flow is:

![applicationPermissionsWorkflow](/assets/Images/2026-03-09-OAuthPermissionsGrant/applicationPermissionsWorkflow.png)

At this stage, we have seen how permissions can be granted. The next step is to distinguish how these grants differ from another major class of identity attacks: service principal compromise.

## 4. OAuth / Consent Abuse vs Service Principal Abuse

So far, we have demonstrated the two permission grant flows and how user or admin trust can be abused.
OAuth Grant abuse does not require prior credential compromise and this attack could generate two artifacts : `oAuth2PermissionGrant` and/or `appRoleAssignment`.

These attack paths must not be confused with Service Principal abuse where the credentials of an application (client secret or certificate) with legitimate permissions are compromised and reused by an attacker.

These attack paths should be understood as two distinct patterns of identity abuse: establishing permissions through consent (delegated or application), and exploiting identities through credential or token abuse.

| Dimension          | OAuth / Consent Abuse                                         | Service Principal Abuse                   |
| ------------------ | ------------------------------------------------------------- | ----------------------------------------- |
| Trigger            | Consent flow (user or admin)                                  | Credential compromise                     |
| Persistence anchor | Permission grant (OAuth2PermissionGrant or AppRoleAssignment) | Secret or certificate                     |
| Visibility         | AuditLogs (consent events)                                    | Sign-in logs (service principal sign-ins) |
| Revocation         | Remove grant / revoke sessions                                | Rotate credentials / disable SPN          |
| Stealth            | High (user-driven, low anomaly signal)                        | Medium (requires credential exposure)     |

With OAuth consent abuse, the attacker's objective shifts fundamentally from compromising identities to establishing trusted access paths that persist independently of credentials.

To understand how these attack patterns maintain access, understanding the different ways tokens can be abused is therefore critical.

## 5. Token Replay vs Token Renewal vs Token Minting

A common source of confusion in OAuth abuse analysis lies in the distinction between token replay and token generation capabilities.
Below listed are the different capabilities with increasing level of persistence and autonomy over token acquisition.

**Token replay** refers to the reuse of an existing access token to access protected resources.
The token is used as-is with no interaction with the identity provider.
However, this technique provides limited persistence due to the short token lifetime (~2h). Moreover, tokens may be invalidated earlier than their lifetimes via Continuous Access Evaluation (CAE) in supported resource providers
> The attacker is borrowing access

**Token renewal** refers to the abuse of a compromised refresh token granting the attacker to gain the ability to request new access tokens from the identity provider.
This is not replay of an access token, but a legitimate refresh token exchange that results in new access tokens being issued.
This introduces a conditional persistence model subject to Conditional Access policies, session revocation, and token lifetime controls.
> The attacker is maintaining access

**Token minting** where an attacker controls a client secret or certificate and can directly request access tokens using the client credentials flow.
This represents true autonomous persistence as no user context is required, and tokens can be generated on demand once the application is authorized at the tenant level.
> The attacker is owning the access pipeline

| Capability        | Token Replay                  | Token Renewal (Delegated)                           | Token Minting (Application)                                |
| ----------------- | ----------------------------- | --------------------------------------------------- | ---------------------------------------------------------- |
| Mechanism         | Reuse of existing token       | Refresh token exchange                              | Credential-based token issuance                            |
| Persistence model | Stateless / token-bound       | Session-bound / conditional                         | Identity-bound / autonomous                                |
| Dependency        | Access token                  | Refresh token (revocable)                           | Client secret / certificate                                |
| IdP Interaction   | None                          | Required (/token endpoint)                          | Required (/token endpoint)                                 |
| Revocation impact | High (token expiry or CAE)    | Medium (session revocation / CA policies)           | Variable (depends on credential rotation / SP disablement) |
| Detection         | Easier (token reuse patterns) | Moderate (requires correlation of refresh activity) | Harder (workload identity, no user context)                |

The two consent grant paths are different but share the same goal: *persistence*.
More specifically, application permissions enable an autonomous token minting relying on the service principal credentials, whereas delegated permissions enable a conditional token minting capability.
In conclusion, OAuth abuse is dangerous not because it grants access, but because it enables partially or wholly, token minting without re-authentication.

*→ The true security boundary is not the protection of tokens themselves, but the control over the mechanisms that allow tokens to be continuously issued.*

## 6. MITRE ATT&CK Mapping

MITRE ATT&CK does not model OAuth consent abuse as a standalone technique, but its components are represented across multiple techniques spanning social engineering, account manipulation, and the use of valid identities.

As explained so far, unlike traditional identity attacks, OAuth consent abuse does not inherently rely on credential theft or token exfiltration, and therefore does not depend on techniques such as `T1555` (Credentials from Password Stores) or `T1528` (Steal Application Access Token), although these may appear as follow-on actions.
Instead, it leverages legitimate identity constructs to establish persistent and renewable access, by embedding permissions directly into the identity control plane.

In many scenarios, the attack starts with the creation of a malicious application in the attacker’s tenant. This can be mapped to `Create Cloud Account (T1136.003)`, as it introduces a new application identity (service principal) used in the attack.

This step is not strictly required (e.g. reuse of an existing application) but often serves as the foundation for initiating the attack.

Both `delegated` and `application` permission abuse share common ATT&CK techniques:
![ConsentAbuseMITREMapping](/assets/Images/2026-03-09-OAuthPermissionsGrant/oauthConsentAbuseMITREAttck.png)

- `Phishing (T1566)`: A user or administrator is tricked into initiating a consent flow. No credentials are harvested; the attacker targets user decision, not secrets : It is consent phishing.
- `Account Manipulation (T1098)`: While no credentials are modified, the authorization model of the identity is altered through the creation of persistent permission grant artifacts:
  - OAuth2PermissionGrant (delegated permissions)
  - AppRoleAssignment (application permissions)
- `Valid Cloud Accounts (T1078.004)`: No credential theft is required. Access relies on EntraID identities with granted trust and is performed using:
  - A legitimate user identity (delegated flow)
  - A legitimate service principal (application flow)
- `Application Layer Protocol: Web Protocols (T1071.001)`: The attacker queries an API (e.g. Microsoft Graph) over HTTPS using valid tokens. The activity follows normal API consumption patterns.

OAuth consent abuse blurs the boundary between Initial Access (Phishing – T1566) and Persistence (Account Manipulation – T1098): **A single user action simultaneously grants access and establishes long-term persistence.**

By analyzing this attack chain, we also notice that the **OAuth Consent Abuse** does not rely on breaking security controls, but on leveraging them as designed: By combining consent-based authorization with legitimate API access, attackers achieve persistence and data access while remaining fully aligned with expected identity behaviors :
> There's no brute force, no anomalous authentication is required, no token needs to be stolen. Authentication, token issuance and API usage are **all legitimate**.

This highlights a fundamental detection challenge: traditional controls focus on credential misuse and anomalous authentication, while this attack operates through legitimate identity transformations and standard API usage. As a result, effective detection depends on visibility into consent events, permission grants, and workload identity activity rather than authentication anomalies alone.

This explains why consent abuse frequently bypasses traditional monitoring approaches and remains under-detected in many environments.

## 7. Detection Gaps and Defensive Blind Spots

As mentioned during the attack path analysis, detection challenges do not stem from a lack of telemetry, but from a mismatch between traditional detection models and identity-based attack paths.
OAuth consent abuse does not generate suspicious authentication patterns, but instead introduces subtle authorization changes and new workload identities.

Some hints on consent abuse patterns are distributed in the victim's tenant, across identity logs, directory objects, and service principal activity, but these fragmented signals are rarely consolidated into a single detection model:

### Directory Objects

After a successful consent abuse attack, an Enterprise Application object and the subsequent Service Principal, is created in the target's tenant.

A first indication is therefore the presence of suspicious multi-organization Service Principals backed by applications registered in external tenants, especially when they are not associated with known or trusted partners.

```powershell
Get-MgServicePrincipal -Filter "DisplayName eq 'OAuthGrantAbuse'" | select AppDisplayName, AppId, AppOwnerOrganizationId, DisplayName, Id, ReplyUrls, ServicePrincipalType, SignInAudience, @{Name = "CreatedDateTime";Expression = { $_.AdditionalProperties["createdDateTime"]}}, @{Name = "PublisherName";Expression = { $_.VerifiedPublisher["DisplayName"]}},AccountEnabled, Homepage,Tags 
```

![DirectoryObjectsAnalysis](/assets/Images/2026-03-09-OAuthPermissionsGrant/DirectoryObjectAnalysis.png)

- `DisplayName`, `AppDisplayName`, `AppId`, `Id`: Object identifiers; generic, inconsistent, or suspicious naming can be a first indicator of potentially malicious applications.
- `AppOwnerOrganizationId`: The ID of the tenant where the App Registration object resides; values pointing to external tenants should be reviewed carefully.
- `SignInAudience`: Accounts supported by the application; external or multi-tenant apps often have values not limited to the current organization (e.g. AzureADMultipleOrgs).
- `VerifiedPublisher`: A missing or unverified publisher represents a lower level of trust.
- `CreatedDateTime`: A recent creation, especially when aligned with consent or sign-in events, can be suspicious.
- `ReplyUrls`, `Homepage`: External URLs that could potentially be used for phishing or data exfiltration.
- `AccountEnabled`: Indicates active objects and potentially ongoing access.
- `Tags`: Metadata associated with the application. Missing or inconsistent tags compared to known publishers may indicate anomalous or unmanaged applications.

 External application ownership (AppOwnerOrganizationId) combined with an unverified or unknown publishers could signal potential multi-tenant consent phishing.

### Sign-in Logs

The Enterprise Application object will also be associated with logs on each sign-in activity with information on the user accounts concerned, geolocation (IP address, location), if Conditional Access was applied and the resource application for which the access tokens were requested :

The Enterprise Application object is also associated with sign-in events that capture authentication activity when users interact with the application. These logs provide visibility on:

- User context (user identity, tenant, user type);
- Source information (IP address, geolocation, device, user agent);
- Authentication details (MFA, authentication method, protocol);
- Conditional Access evaluation (applied, not applied, or failed);
- Target resource for which access tokens are issued;

**Normalized Sign-in Logs:**

```json
[
  {
    "createdDateTime": "2026-03-28T20:31:23Z",
    "userPrincipalName": "sse@...",
    "userType": "Member",
    "appDisplayName": "OAuthGrantSecurityDemo",
    "resourceDisplayName": "Microsoft Entra ID",
    "status": {
      "errorCode": 65001,
      "failureReason": "Consent required"
    },
    "clientAppUsed": "Browser",
    "deviceDetail": {
      "browser": "Firefox 149.0",
      "operatingSystem": "Windows 10"
    },
    "location": {
      "ipAddress": "2001:861:3201:ebc0:9513:2664:3c3e:8d50",
      "countryOrRegion": "France"
    },
    "authenticationDetails": {
      "authenticationRequirement": "Multifactor authentication",
      "authenticationMethod": "Prompted"
    },
    "conditionalAccessStatus": "notApplied",
    "correlationId": "4b5812d8-bbb1-4d51-9197-d6d1315833ce",
    "resultType": "Interrupted"
  },
  {
    "createdDateTime": "2026-03-28T20:32:08Z",
    "userPrincipalName": "sse@...",
    "userType": "Member",
    "appDisplayName": "OAuthGrantSecurityDemo",
    "resourceDisplayName": "Microsoft Entra ID",
    "status": {
      "errorCode": 0,
      "failureReason": null
    },
    "clientAppUsed": "Browser",
    "deviceDetail": {
      "browser": "Firefox 149.0",
      "operatingSystem": "Windows 10"
    },
    "location": {
      "ipAddress": "2001:861:3201:ebc0:9513:2664:3c3e:8d50",
      "countryOrRegion": "France"
    },
    "authenticationDetails": {
      "authenticationRequirement": "Multifactor authentication",
      "authenticationMethod": "Satisfied"
    },
    "conditionalAccessStatus": "notApplied",
    "correlationId": "4b5812d8-bbb1-4d51-9197-d6d1315833ce",
    "resultType": "Success"
  }
]
```

A suspicious external enterprise application associated with user sign-in activity indicates that a legitimate user has authenticated and interacted with the application.

In the extracted logs, the presence of a status `Interrupted` with error code `65001` indicates that authentication succeeded but token issuance was blocked because the application required user or administrator consent.

Successful sign-ins may indicate that a consent grant already existed, or that the user has granted delegated permissions during the interaction.

This effectively grants the external application a foothold in the tenant, allowing it to access resources independently of the user’s interactive session through the access and potentially refresh tokens.

### Audit Logs

The audit logs provide insights on the consent events and scopes and indicates the scope (API permissions) requested and subsequently granted:

**Normalized Audit Logs:**

```json
[
  {
    "activityDateTime": "2026-03-28T20:32:08Z",
    "activityDisplayName": "Consent to application",
    "result": "success",
    "correlationId": "1253aa1c-fd46-4e15-8a75-397d23cde2ce",
    "initiatedBy": {
      "user": {
        "userPrincipalName": "sse@...",
        "ipAddress": "20.240.136.183"
      }
    },
    "targetResources": [
      {
        "displayName": "OAuthGrantAbuse",
        "type": "ServicePrincipal"
      }
    ],
    "modifiedProperties": {
      "ConsentContext.IsAdminConsent": "True",
      "ConsentContext.OnBehalfOfAll": "True",
      "ConsentAction.Permissions": ["Chat.Read", "Notes.Read", "User.Read"]
    }
  },
  {
    "activityDateTime": "2026-03-28T20:32:08Z",
    "activityDisplayName": "Add app role assignment to service principal",
    "result": "success",
    "initiatedBy": {
      "user": {
        "userPrincipalName": "sse@..."
      }
    },
    "targetResources": [
      {
        "displayName": "Microsoft Graph",
        "type": "ServicePrincipal"
      }
    ],
    "modifiedProperties": {
      "AppRole.Value": "User.Read.All"
    }
  }
]
```

We observe consent grant events in the log entries (e.g. "activityDisplayName": "Consent to application") including information about the grant type: *"ConsentContext.OnBehalfOfAll": "True"* indicates an admin consent granting tenant-wide access.

None of these indicators is inherently malicious when viewed in isolation. A service principal creation, a consent event, or a successful sign-in can all occur as part of legitimate application usage.

This is the main detection challenge of OAuth consent abuse: there is no single high-signal alert, but rather a sequence of low-signal events that must be correlated and interpreted in context.

As a result, detection must shift from event-based monitoring to the analysis of identities, permissions, and trust relationships within the tenant.

## 8. Detection and Mitigation Opportunities

**⚠️ Attention:** *This article focuses specifically on OAuth consent abuse and does not cover insider-driven data leakage scenarios related to multi-tenant application exposure.*

### 8.1 Detection

OAuth consent abuse detection combines identity inventory, consent event correlation, and post-consent activity analysis.
The reasoning to build an accurate detection logic for OAuth consent abuse must rely on the following questions:

- What identities exist and what is their exposure surface?
- How was access granted and established?
- How is granted access used over time?

To address this challenge, I built a simple helper, based on the above detection logic, to identify suspicious service principals. In practical terms, the logic translates roughly into the following set of actions.

#### Enumerating service principals and permissions

The tool will be based on an inventory of the tenant's service principals where `AppOwnerOrganizationId` differs from the current or organization's tenant IDs, as the detection primary signal.
Our supporting signal here would be based on the `verifiedPublisher` property to flag all applications with an unverified or untrusted publisher.

Next, attributes regarding permission grants will be used to enrich the service principal's profile. This is done by identifying application permissions and sensitive delegated scopes (e.g. `User.Read.All`, `Files.Read.All`).
Usually, investigating use cases with application permissions must be prioritized as they grant tenant-wide access (ConsentType = AllPrincipals).

#### Correlating consent events with identity object creation

Previous signals enable us to build a static inventory of suspicious applications at a given point in time. To move towards continuous monitoring, it is necessary to track consent-related events such as "Consent to application" and "Add app role assignment".

Additionally, temporal correlation between service principal creation and consent events must also be observed to reconstruct the identity provisioning chain. This enables the identification of anomalous lifecycle patterns where the provisioning and authorization occur in rapid successssion, indicating potential OAuth consent abuse scenarios.

#### Monitoring service principal activity

Continuous monitoring focuses on post-consent activity of service principals.
This includes:

- Unexpected or expanded API usage beyond previously observed patterns;
- Access to high-value resources aligned with granted permissions;
- Deviations in access context such as geography or network origin;

This layer completes the lifecycle analysis by identifying cases where applications exhibit behavior consistent with potential OAuth grant abuse, including active data exfiltration.

### 8.2 Mitigation and Hardening Controls

#### Preventive Controls (pre-consent)

**User Consent Restrictions**: User consent policies must be configured to limit the ability of users to grant permissions to applications.

By default, user consent settings follow Microsoft-managed policies. If the organization has stricter security requirements, the option `Do not allow user consent` would reduce exposure to consent phishing scenarios as admin consent would be required for all apps.
Alternatively, for organizations requiring more flexibility, `Allow user consent for apps from verified publishers, for selected permissions` would allow users to grant consent for an allowed scope defined by the admins (Low Permissions).
A careful governance approach to permissions classified as Low is crucial as these permissions define the exposure surface that do not require admin approval.

For admin consent, a review workflow is designated where reviewers can assess requests before approval; however, final consent remains restricted to administrators.

#### Governance Controls (periodic reviews)

**Service Principal Governance**: Overall, an organization must maintain ownership and a lifecycle management process covering creation, review of active principals and removal of unused or orphan identities.

During the service principals periodic reviews, grant objects must also be examined including `OAuth2PermissionGrant` (delegated permissions) and `AppRoleAssignment` (application permissions).
Moreover, applications without a `verifiedPublisher` should be treated as higher risk during the reviews.

> **📦 Detection Tool**: I've released a [Python-based detection tool](https://github.com/DimCrimson/dimcrimson.github.io/tree/main/lab/Azure/AzureOAuthExposureScanner) that implements the logic described in the article.
> The tool enumerates external service principals, analyzes their OAuth permission grants and app roles, correlates sign-in activity, and outputs prioritized risk cards.

#### Reactive Controls (post-detection)

Reactive controls focus on containment and remediation once suspicious applications are identified.
Depending on the risk level the security analyst could either:

- Revoke the unnecessary or high-risk grants;
- Disable or delete the service principal and associated application;
- Revoke any user session in delegated scenarios to prevent continued access;

In confirmed malicious use cases, the service principal object, and all associated artifacts (e.g. permission grants) must be removed.

OAuth consent abuse mitigation relies on combining detection with preventive, governance, and reactive controls.
This layered approach provides visibility into access, reduces exposure over time, and enables effective containment of suspicious applications.

## 9. Conclusion

That’s a wrap ! — OAuth grant abuse is an identity control-plane risk where application consent and permissions can be leveraged for persistent access, requiring continuous detection and control.
