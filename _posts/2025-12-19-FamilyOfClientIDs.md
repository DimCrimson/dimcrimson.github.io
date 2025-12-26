---
title: Family of Client IDs - Microsoft’s Pivot Playground
date: 2025-12-19 23:00:00 +0000
description: A practical guide to FOCI-driven token reuse 🔍
comments: false
categories: [Azure, Azure Entra ID]
tags: [aad,entra id,msal,tokens,azure,security]     # TAG names should always be lowercase
---

This article takes a closer look at FOCI — a Pandora's box of security risks opened by researchers at [SecureWorks](https://github.com/secureworks/family-of-client-ids-research) — which refers to a group of refresh tokens that can be used to forge access tokens for any application within the same Family of Client IDs.

It examines how this design choice amplifies the attack surface through Azure Entra ID tokens, focusing on where and how refresh and access tokens are stored across common application types (CLI, PowerShell, desktop brokers, mobile apps, SPAs), with concrete extraction examples. 

Broker-managed tokens are intentionally out of scope, as they are OS-protected, device-bound, and generally accessible only with system or root privileges.

> **TL;DR**: *`FOCI` lets some Microsoft client IDs reuse refresh tokens. This article describe how some refresh tokens are stored, demonstrates extraction examples, and gives practical mitigations — Not an exhaustive inventory.*

## 101 Security Tokens

Let's start from the beginning - Microsoft Identity relies on these types of security tokens:

- **Identity Token** - `"credential_type":"IdToken"` - A proof of authentication. A JWT token containing user information used in some OpenID Connect flows.
- **Access Token** - `"credential_type":"AccessToken"` - A JWT token confirming the right to access the resource. The access token provides temporary access (between **60 and 90 minutes**), to the resource server for which it is scoped. The token's [lifetime could be customizable](https://learn.microsoft.com/en-us/entra/identity-platform/configurable-token-lifetimes) for applications and some service principals.
- **Refresh Token** - `"credential_type":"RefreshToken"` - An opaque token that cannot be decoded, unlike JWT. This token starts with *0.A* or *1.A* and enables the forging of new security tokens.

    **📝 Note:** *Unlike access tokens, the lifetime of a refresh token is [no longer customizable](https://learn.microsoft.com/en-us/answers/questions/285630/refresh-token-and-conditional-access-policy). These tokens do not contain an expiration timestamp. Instead, Entra ID has a sliding inactivity window for refresh tokens with a maximum inactivity period of **24h for SPA or 90 days for all other applications**.*
    *Each successful use of the refresh token resets this inactivity window, allowing these tokens to persist indefinitely unless a security or policy event invalidates it (e.g. CA policy, session revocation...).*
- **Primary Refresh Token** - The strongest type of token. It's an opaque token, device-bound and used to silently obtain [refresh and access tokens for Microsoft applications](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token?tabs=windows-prt-issued%2Cbrowser-behavior-windows%2Cwindows-prt-used%2Cwindows-prt-renewal%2Cwindows-prt-protection%2Cwindows-apptokens%2Cwindows-browsercookies%2Cwindows-mfa#what-is-a-prt-used-for).

    **📝 Note:** *Contrary to the first three tokens, the Primary Refresh Token (PRT) is not an OAuth token and is not issued via MSAL.*

➡️ <span><b>Refresh tokens are a prime target for maintaining persistence through a valid Entra ID account. And it gets even more serious with a refresh token from the Family of Client IDs (FOCI), as it can be used to generate security tokens for other applications, effectively enabling lateral movement across any other service in the FOCI list. But where can these tokens be found?</b></span>

## DPAPI Decryption - Token Extraction

During the exploration and hunt for tokens, proper equipment is needed to decrypt and format the various files and caches that we will encounter.

Windows mostly uses **DPAPI - Data Protection API**, a built-in component that enables the storage of sensitive data using a master key derived from the user’s Windows credentials. As a result, decrypting DPAPI-protected data requires access to the user’s machine or an active session.

For this article, token extraction is performed exclusively using Mimikatz which include DPAPI decryption commands:

```Powershell
dpapi::blob /in:".\.Azure\msal_token_cache.bin" /unprotect
dpapi::blob /in:"$env:APPDATA\Local\.IdentityService\msal.cache.cae" /unprotect
```

This will return binary data in hex format, that must be converted to plaintext:

```powershell
($binary_token_data -replace '\s','' -split '(..)' | ? {$_} | foreach($_){[char][byte]("0x$_")}) -join ''
```

## Fantastical Tokens and Where to Find Them

 **📝 Note:** *This article focuses on user-interactive authentication. In these flows, tokens may be cached by MSAL or an OS-level broker. Non-interactive flows (e.g., service principals or managed identities) behave differently, and token persistence may vary depending on the client and environment; they are outside the scope of this analysis.*

Now that we have the proper tools to investigate, let's explore the various files:

### Automation & CLI Tools

- **`Azure CLI`** 
    - *For Non-Windows OS*: After authenticating with az login, a file is created on the user home directory `%USERPROFILE%/.azure/msal_token_cache.json` containing identity, access and refresh tokens in clear text.
    - *For Windows*: Since the [migration from ADAL to MSAL](https://learn.microsoft.com/fr-fr/cli/azure/msal-based-azure-cli?view=azure-cli-latest) starting from version 2.30, the tokens are stored in `%USERPROFILE%/.azure/msal_token_cache.bin`. A file that is encrypted with DPAPI - as mentioned previously, the file can still be decrypted to retrieve the tokens in clear text.
    ![AZCliTokenExample](/assets/Images/2025-12-19-FOCI/I-AzCliTokenExample.png)
    
  > **Client ID:** `04b07795-8ddb-461a-bbee-02f9e1bf7b46`  
  > **FOCI:** ✅ In FOCI

- **`Azure PowerShell`**
    - On older versions, clear-text tokens were stored under `%USERPROFILE%/.Azure/TokensCache.dat`. 
    For recent versions of Azure PowerShell, as indicated by the `%USERPROFILE%/.Azure/AzureRmContext.json`, the tokens are stored in `%USERPROFILE%\AppData\Local\.IdentityService\msal.cache.cae` or `msal.cache.nocae` depending on the continuous access evaluation configuration. Both msal.cache.* files are encrypted with DPAPI.

    ![AZPowershellTokenExample](/assets/Images/2025-12-19-FOCI/I-AzPowershellTokenExample.png)
    **📝 Note:** *Previously the file used was msal.cache before continuous access evaluation was rolled out.*

    **⚠️ Attention:** *Aside from DPAPI, tokens can be extracted with the command `Save-AzContext -Path ~/.Azure/azure_context.json` ...*

    
  > **Client ID:** `1950a258-227b-4e31-a9cf-717495945fc2`  
  > **FOCI:** ✅ In FOCI 

- **`Microsoft Graph PowerShell`**
    - While exploring the files under `%USERPROFILE%\AppData\Local\.IdentityService` we find two files : `mg.msal.cache.cae` & `mg.msal.cache.nocae` that are encrypted with DPAPI. Upon decryption, I was able to confirm that both files save all three security tokens forged for Microsoft Graph PowerShell.
    ![MGraphTokenExample](/assets/Images/2025-12-19-FOCI/I-MGraphTokenExample.png)
    Decoding the access token we read the following information, confirming our assumption:
        - `"aud"`: "00000003-0000-0000-c000-000000000000"
        - `"app_displayname"`: "Microsoft Graph Command Line Tools"
        - `"appid"`: "14d82eec-204b-4c2f-b7e8-296a70dab67e"
    ![MGraphTokenExample](/assets/Images/2025-12-19-FOCI/I-MGraphTokenDecoded.png)
  > **Client ID:** `14d82eec-204b-4c2f-b7e8-296a70dab67e`  
  > **FOCI:** ❌ Not in FOCI
- **`Cloud Shell`**
    - Cloud Shell launched from the Azure Portal, shell.azure.com, or any Microsoft documentation page that embeds a Cloud Shell panel (“Try It”), inherits the user’s browser session tokens. No tokens are stored in the Cloud Shell associated storage account.

### Microsoft 365 Applications (Desktop)

- **`Teams Desktop`**
    - Tokens were previously stored as plain text in a SQLite database. Now stored under: `%USERPROFILE%\AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\WV2Profile_tfl\Network\Cookies`
    The particularity of these tokens is that they're not encrypted with DPAPI but with Chromium as proven by the first hex binary characters in the encrypted_values : `76 31 30 -> v10`. Chromium decryption is out of scope for this article.
    As demonstrated by [RandoriSec](https://blog.randorisec.fr/ms-teams-access-tokens/), the tokens can indeed be extracted after decrypting the blob.
    ![TeamsTokenExample](/assets/Images/2025-12-19-FOCI/I-TeamsDesktopTokenExample.png)

    <small><span style="color:red; display:block; text-align:center;"> Teams tokens can be stored under <b>WV2Profile_tfl</b> or <b>WV2Profile_tfw</b>.</span></small>

- **`Word, Excel, Outlook`**
    - The path `%USERPROFILE%\AppData\Local\Microsoft\TokenBroker\Cache` lists multiple .TBRES files. These files are JSON-formatted and include encrypted values (evidenced by the flag "IsProtected":true).
    ![TBRESDecryption](/assets/Images/2025-12-19-FOCI/I-TBRES.png)
    When decrypted for analysis, the payloads do not resemble a traditional token cache, instead, they appear to be serialized authentication responses produced by MSAL. These responses may include token materials embedded within the response objects as demonstrated below:
    ![TBRESDecryption](/assets/Images/2025-12-19-FOCI/I-TBRES_Loop_Decryptor.png)
    This result is returned by using a loop on all the TBRES files to retrieve the protected values then decrypt them using mimikatz until we retrieve a valid access token.

      A PowerShell helper to extract and decrypt .tbres DPAPI blobs is available [here](https://raw.githubusercontent.com/DimCrimson/dimcrimson.github.io/refs/heads/main/assets/Scripts/TBRESLoop.ps1) — use only on systems you own or have explicit authorization to test.

    Unlike the automation and CLI tools explored previously, Microsoft 365 desktop applications rely on the Windows authentication broker - WAM (Web Account Manager), to securely manage and broker the security tokens on behalf of the application.

    Under WAM, long-lived credentials such as RT and PRT are protected by OS-level security boundaries and are not persisted as application-readable artifacts, making refresh token theft infeasible without full device compromise (e.g., administrative access combined with bypass of OS security protections).

    In the event of system-level access, refresh tokens could potentially be abused to mint new access tokens and pivot to other applications that are part of the FOCI or the Microsoft trust chain demonstrated later in this article.

> **Client IDs:** 
> - `1fec8e78-bce4-4aaf-ab1b-5451cc387264` (Microsoft Teams)
> - `d3590ed6-52b3-4102-aeff-aad2292ab01c` (Microsoft Office)
>
> **FOCI:** ✅ In FOCI

### Microsoft 365 Applications (Mobile)

Using a debugger with the outlook mobile app for Android, we observe that MSAL acquires and caches tokens via a broker application such as Microsoft Authenticator.  
When a broker is present, it manages account sessions and handles refresh token usage.
Tokens are therefore not stored in directly accessible storage and require root access to the mobile device to be retrieved.

In the observed below logs, we notice that:

- MSAL serves valid access tokens from its internal cache (`isFromCache: true`) without network calls.  
- The application delegates authentication to the broker, in this case Microsoft Authenticator for Android - `com.azure.authenticator`, which silently acquires access tokens using its managed refresh tokens: `Broker operation name: MSAL_ACQUIRE_TOKEN_SILENT brokerPackage: com.azure.authenticator`.

```log
12-18 19:12:08.252  TokenTelemetry: Token refresh request for accountId: 32768 accountType: OutlookHx cloudType: WorldWide correlationId: c3be00a0-d499-455a-94df-1025a3c7c47 claims: false tokenRefreshDuration: 0 ms isFromCache: true isSuccess: true tokenRefreshComponent: loki tokenResource: liveprofilecard.access
12-18 19:12:25.556  [OneAuth] Returning cached broker: com.azure.authenticator
12-18 19:12:25.557  OneAuthLog: prodMicrosoftAuthenticator is the active AccountManager broker
12-18 19:12:25.561  [OneAuth] Broker operation name: MSAL_GET_DEVICE_MODE brokerPackage: com.azure.authenticator
12-18 19:12:25.600  [OneAuth] Received successful result from Broker Content Provider
12-18 19:12:25.601  OneAuthLog: Broker operation name: MSAL_GET_PREFERRED_AUTH_METHOD brokerPackage: com.azure.authenticator
12-18 19:12:25.749  OneAuthLog: Request to BrokerContentProvider for uri path /getAccounts
12-18 19:12:25.749  [OneAuth] Request to BrokerContentProvider for uri path /getAccounts
12-18 19:12:27.381  OneAuthLog: Key: api_name, Value: AcquireTokenSilently
12-18 19:12:27.388  OneAuthLog: IsAccessTokenValid: The access token is expired
12-18 19:12:27.388  [Common] Broker operation name: MSAL_ACQUIRE_TOKEN_SILENT brokerPackage: com.azure.authenticator
12-18 19:12:27.410  [OneAuth] Broker Result, raw payload size:980 ,compressed bytes size: 540
12-18 19:12:27.411  [OneAuth] Request to BrokerContentProvider for uri path /acquireTokenSilent
```

According to MSAL [release notes](https://devblogs.microsoft.com/microsoft365dev/announcing-xamarin-broker-support-in-msal-net-4-9-0/) and [Microsoft documentation](https://learn.microsoft.com/en-us/entra/msal/android/single-sign-on?sso-through-brokered-authentication), the supported brokers are: `Microsoft Authenticator` (Android & iOS), `Intune Company Portal` (Android) & `Link To Windows` (Android).

MSAL delegates token acquisition to the first available broker installed, and if none is found, MSAL will fall back to a [system browser](https://learn.microsoft.com/en-us/entra/msal/android/single-sign-on?sso-through-system-browser).

Tokens are cached either by the authentication broker or within the application storage. On Android, this storage resides under /data which cannot be enumerated on modern non-rooted devices:
![ADBEnumeration](/assets/Images/2025-12-19-FOCI/I-AndroidFS.png)
In the event of a full device compromise (root / jailbreak), refresh tokens may be exfiltrated and could potentially be used to pivot to other applications leveraging FOCI.

  > **Client IDs:** 
  > - `27922004-5251-4030-b22d-91ecd9a37ea4` (Outlook Mobile)
  > - `1fec8e78-bce4-4aaf-ab1b-5451cc387264` (Microsoft Teams)
  > - `d3590ed6-52b3-4102-aeff-aad2292ab01c` (Microsoft Office)
  >
  > **FOCI:** ✅ In FOCI


### Microsoft 365 Applications (Web)

- **`Teams, Outlook & Office`**
    - The browser keeps in its local storage a refresh token that is like all SPA, 24 hours long but this time, an opaque token starting with'M.' that differs from the Entra ID refresh token.
    The access token is also stored but in JWE format (Json Web Encryption) instead of the usual JWT or JWS format. With JWE, the token is encrypted with Microsoft's internal keys, so it cannot be decrypted locally.

> **Client IDs:** 
> - `4b3e8f46-56d3-427f-b1e2-d239b2ea6bca`
> - `6b2d4bcd-1806-45eb-9a26-867acb42ab76`
> - `2821b473-fe24-4c86-ba16-62834d6e80c3`
>
> **FOCI:** ❌ Not in FOCI


### Azure Portal

 - For [Azure Portal](https://portal.azure.com/#home), the security tokens: refresh and access, are stored in the browser's session storage rather than the local storage. The tokens are therefore removed once the tab is closed, reducing the exposure to the attacks mentioned previously.

  > **Client ID:** `c44b4083-3bb0-49c1-b47d-974e53cbdf3c`  
  > **FOCI:** ❌ Not in FOCI

**📝 Note:** *SPAs like the two previous categories, seem to prevent the reuse of Entra ID refresh tokens to mint new tokens outside of the browser context - as illustrated by the error observed below when attempting refresh token reuse :*
![SPATokenReuseError](/assets/Images/2025-12-19-FOCI/SPAError.png)

## TokenTactics — Refresh Token Reuse

While decrypting the previous files, we noticed multiple fields, we'll focus on *client_id* (after all, it's in the title) and *aud*, *scp* :

- **client_id** : Value in the token entry (outside of the token itself), points to the application sending the authentication request (*caller / client*).
- **aud** : Value inside the token, points to the targeted application who your token is meant for (*resource server*).
- **scp** : Value inside the token, reflects the permissions in the scope of the access token.

Client IDs belonging to the FOCI list can be used interchangeably to forge new security tokens for any application listed in the Family of Client IDs.

➡️ <span style="color:darkred;"><b>Which means that in the case of the theft of a single refresh token, the blast radius includes all applications in the FOCI list.</b></span>

Let's demonstrate with Az CLI security tokens, using the previously discussed extraction techniques, we retrieve the refresh token stored in `msal_token_cache.json`:
![RefreshTokenExtraction](/assets/Images/2025-12-19-FOCI/II-AzCliExtractedRefreshToken.png)
Using TokenTactics, we can forge new security tokens for a FOCI Client ID:
![RefreshTokenTactics](/assets/Images/2025-12-19-FOCI/II-AzCliRefreshToMsGraph.png)
For those paying attention, you might notice that the client ID for Microsoft Graph PowerShell is not listed under FOCI. However, with TokenTactics, the client ID used is `d3590ed6-52b3-4102-aeff-aad2292ab01c` which is for Microsoft Office. The security tokens returned by TokenTactics have the correct graph audience and the scopes `Directory.#` enabling their use by Microsoft Graph PowerShell.

**🎯 Key Insight:** *In addition to FOCI, an additional nuance is a hidden trust model between some Microsoft Client IDs which enables access tokens to be validated based on their audience and scopes, rather than on the original caller client ID.*

*This behavior adds an important perspective on the blast radius that can be achieved with an Entra ID refresh token. While arbitrary client IDs are not accepted - even if the audience and scopes appear valid - access tokens do not need to originate from the same client ID as the calling application. As long as the token is issued to a Microsoft-owned application recognized by Entra ID, targets the correct resource audience, and includes the required scopes, token reuse across applications remains possible.*

As documented in this [Microsoft security blog post](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/), multiple events can invalidate refresh tokens with varying degrees of effectiveness.

FOCI allows a refresh token obtained for one application to be reused to silently acquire security tokens for other related Microsoft workloads.
![RevokingSessions](/assets/Images/2025-12-19-FOCI/II-AzCliRevokeAllSessions.png)
Using the `Revoke sessions` feature in Entra ID effectively logs out the user and revokes the security tokens for the Portal stored in the browser session storage.
It blocks any attempts to forge new security tokens using previously generated refresh tokens.
However any existing access tokens are still usable until their expiration (expires_in: 7200 ~ 2h)

![RevokingSessions](/assets/Images/2025-12-19-FOCI/II-AzCliAfterRevocation.png)

➡️ <span><b>Revoking sign-in sessions invalidates browser sessions and prevents users from acquiring new tokens. Existing access tokens remain valid until expiration.</b></span>

## FOCI Threat Model at a Glance

Multiple scenarios could allow an attacker to exfiltrate security tokens. At a high level, two main vectors emerge:

1. Abuse of OAuth flows:

    - For example, device code authentication using any client that directly returns refresh tokens.

2. Endpoint or token broker compromise:

    - Including local token caches, broker-managed storage, or token material residing in memory.

➡️ <span><b>Where FOCI applies, the threat model simplifies to these two vectors: abuse of OAuth flows that issue portable refresh tokens, and compromise of the endpoint or the token broker responsible for token issuance and storage.</b></span>

## Token Protection & Security Measures

Significant efforts have been made to reduce the exposure and portability of authentication tokens in Entra ID:

- Browser-bound refresh tokens for SPAs: Refresh tokens issued to browser-based applications cannot be reused outside the browser context.
- Short-lived access tokens with audience and scope restrictions: Access tokens are constrained to specific resources and expire quickly, limiting their usefulness if stolen.
- Modern authentication libraries (MSAL) : Standardized token handling, secure storage, and consistent enforcement of modern OAuth flows.
- Enforcement of MFA is being rolled out by Microsoft and will cover multiple applications including Azure CLI and PowerShell.
- OS-level token protection with authentication brokers: Tokens are encrypted and acquired via brokers (e.g., WAM, mobile brokers), which use device-bound credentials to prevent direct access by the application.

    **⚠️ Attention:** *While authentication brokers significantly reduce token exposure, a fully compromised endpoint may still allow attackers to abuse brokered credentials or mint new refresh tokens.*

As with any shared responsibility model, organizations must complement these protections:

- Awareness, awareness, awareness: Sensitize users and administrators on OAuth phishing techniques such as device code abuse.
- Endpoint protection: Secure all devices (computers & mobiles) accessing corporate resources with disk encryption, strong authentication, auto-lock, and remote wipe in case of theft or loss.
- Conditional Access policies: Enable Continuous Access Evaluation and Token Protection. In the policy, enforce MFA, device compliance, and rapidly invalidate sessions when risk changes.
  
  **⚠️ Attention:** *[Continuous Access Evaluation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation?conditional-access-policy-evaluation) and [Token Protection](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection#requirements) are currently enforced only for a subset of services, including Office 365 online, and mitigate certain access-token misuse scenarios when tokens are used from untrusted devices, IP addresses, or locations.*

- Harden automation tooling: Regularly update Azure CLI, PowerShell, and SDKs, and protect local token caches.
- Monitoring and logging: Detect anomalous sign-ins, unexpected client usage, and token replay patterns using identity logs and analytics, and respond by revoking or blocking affected sessions.
- Limit token persistence where possible : Disable context autosave or persistent sessions in sensitive environments (Disable-AzContextAutosave).

**📝 Note:** *The mitigations described above reduce the likelihood and impact of token compromise but do not fully eliminate it. Tokens remain exploitable if an attacker gains full access to a device or exfiltrates a refresh token for a client / device for which CAE or Token Protection is not yet supported.*

That’s a wrap ! – FOCI highlights how token portability can increase risk, but understanding token storage, browser and device boundaries, and applying the proper organizational controls can significantly reduce exposure.
