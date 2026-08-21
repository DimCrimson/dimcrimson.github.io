---
title: Federated Once, Owned Forever - When Federation Trust Becomes the Credential
date: 2026-08-03 23:00:00 +0000
description: Stress-testing Azure Federated Identity Credentials and how a rogue issuer can become a silent authentication path to an existing managed identity without changing RBAC.
comments: false
toc: true
categories: [Azure, Azure Kubernetes, AI, Federated Credentials]
tags: [aks,ai,agents,federation,azure,security]     # TAG names should always be lowercase
---

# Beyond RBAC: When Federation Trust Becomes the Credential

## 1. Introduction

As cloud security teams, we routinely review the entitlements and RBAC assignments attached to our identities:
**Which roles does this workload identity hold? Which resources can it access? Can it read secrets, modify infrastructure, or reach production data ?**
We periodically require secret rotation : **Was a secret rotated after an ownership change, handover, or operator departure? Are stale credentials still valid ?**

But these checks leave out a blind spot :  An entitlement review may accurately report what the identity can access while missing that a new external workload has become authorized to use those permissions. So a trust review must also be covered : **Who is allowed to effectively become this identity ?**

In my previous article, I looked at another way an application's effective authorization can change without modifying traditional Azure RBAC: abusing OAuth consent grants to authorize delegated or application permissions to APIs following user or administrator consent.

The trust boundary also materializes through Federated Identity Credentials. FICs eliminate the need for developers to manage long-lived credentials by establishing a trust relationship with an external identity provider. Assertions minted and signed by that trusted issuer can then be exchanged with Microsoft Entra ID for access tokens representing the federated identity, whose effective access is governed by the permissions already assigned to it.

With federation, managing a long-lived workload credential is replaced by a chain of trust. Somewhere underneath the workload and the token exchange sits the bottom turtle: the assumption that the configured issuer can be trusted. If that turtle is displaced by an attacker-controlled issuer, the earthquake propagates upward through every permission already resting on that identity

This is the point I wanted to stress-test: what happens if the permissions never change, but the trust underneath them does?

In this article, I will demonstrate how FIC can be abused to become a silent persistence vector through an AI-assisted platform that will influence that trust indirectly, by submitting a legitimate-looking request to a privileged provisioning service. But first, let us review some identity federation jargon.

## 2. Federated Identity Credentials 101

Trust me, I'm ~~an engineer~~ federated.

Federated Identity Credentials can be configured on Microsoft Entra applications and user-assigned managed identities. This article focuses on the latter.

Managed Identities remove the burden of managing credentials for Azure workloads and remain identity objects within their Entra tenant, this sometimes lull security teams into a false sense of security: While the managed identity itself is indeed tenant-bound, workload identity federation allows it to trust tokens issued by an external identity provider.
> A workload outside the tenant, and even outside Azure, can authenticate as that identity when its issuer and claims satisfy a configured FIC.

![FederationFlow](/assets/Images/2026-08-03-AzureIdentityFederation/FIC_Federation_Flow.png)

### The Trust Tuple

*Note: This article focuses on the traditional subject-based workload identity federation model. Flexible Federated Identity Credentials extend this model by allowing claims-matching expressions instead of an exact subject match, and can include certain additional claims in the matching logic.*

The trust decision relies primarily on three values carried by the external assertion and represented in the FIC: issuer, subject and audience.

- `issuer` : The URL representing the external identity provider that generates and signs a JWT token.
- `subject` : The unique identified for the specific workload user or process inside the issuer. e.g. system:serviceaccount:property-apps:property-indexer
- `audience` : The URL representing the intended recipient of the external assertion. For Microsoft Entra workload identity federation, this is typically api://AzureADTokenExchange.

Keep these three values in mind. They will reappear twice in the demo: first when the FIC is injected into the managed identity, and then again as the iss, sub and aud claims of the attacker-controlled assertion.

### One Identity, Multiple Trusts

Adding a rogue FIC does not require replacing an existing federation relationship. A managed identity may have multiple FICs  up to 20 Federated Identity Credentials, meaning the attacker-controlled authentication path can coexist with legitimate ones.
The legitimate workload continues to authenticate normally, reducing the likelihood that the trust modification causes an immediate operational signal.

FICs do not grant the managed identity additional Azure permissions. They change which external workload can obtain tokens representing it. Once authentication succeeds, the resulting token is constrained by whatever authorization the identity already holds.

RBAC tells us what the identity can do. Federation tells us who may be able to exercise it.

To have a better grasp of WIF and the associated dependencies, I built a simple lab to dissect each step of the flow.

## 3. Threat model : Know your trust boundaries

The lab is intentionally built around a common platform pattern: partner-controlled business data is consumed by internal automation, while the actual Azure privileges remain concentrated behind a provisioning service. The question is whether those boundaries remain meaningful if untrusted data can influence the trust configuration of an existing workload identity.

### 3.1 Business Scenario

Let's work up your imagination for this lab:

* **Meridian Co.** is an external partner whose data is consumed by the `property-indexer` service.
* As part of partner onboarding, the platform team provisions dedicated Azure resources when segregation is required. For the purpose of this lab, those resources are limited to a **user-assigned managed identity** and a **dedicated Storage account**, with the managed identity already authorized to access the relevant storage resources.
* These Azure resources belong to and are managed by the `property-indexer` platform. **Meridian staff do not have direct access to the UAMI or its Azure permissions.** The identity is used by internal `property-indexer` workloads to access the storage resources dedicated to Meridian.
* Partner onboarding information remains editable after the initial provisioning so that partners can reflect legitimate operational changes.
* Platform engineers use an **AI-assisted operations workflow** to retrieve those submissions and reconcile identity configuration through a privileged provisioning service.

![FunctionalArcSchema](/assets/Images/2026-08-03-AzureIdentityFederation/FIC_Attack_Path_Functional_Schema.png)

### 3.2 Trust Boundaries and Components

The lab is split into two independently controlled environments: the Property Indexer platform, which owns the Azure resources and provisioning privileges, and a separate external environment controlled by the attacker.

| Component | Why it matters |
|---|---|
| Partner onboarding catalogue | Contains partner-controlled data. In the lab, submissions are represented as JSON records. |
| Catalogue MCP Server | Read-only path used by the assistant to retrieve onboarding submissions. |
| Platform Operations Assistant | Consumes catalogue data and can invoke retrieval and provisioning tools, but holds no Azure credentials itself. |
| Provisioning MCP Server | Exposes managed-identity operations to the assistant. |
| Provisioning API | The privileged enforcement boundary. It holds the Azure credentials and performs ARM operations. |
| Existing UAMI | Already has the Storage permissions required by the workload before the attack starts. |
| Rogue OIDC issuer | Public external issuer controlled by the attacker. Initially, the victim tenant has no reason to trust anything it signs. |

![TechnicalArcSchema](/assets/Images/2026-08-03-AzureIdentityFederation/FIC_Attack_Path_Technical_Schema.png)

For this scenario, the attacker is a malicious Meridian employee with legitimate access to update the company's onboarding information. They also control a separate external environment hosting a rogue OIDC issuer, but have no access to the Property Indexer Azure tenant, its provisioning credentials, the target UAMI, or its role assignments.

At this point, the rogue issuer is useless from the victim tenant's perspective. It can sign as many JWTs as it wants; Microsoft Entra has no configured reason to accept them.

**📝 Note:** *Regarding the use of AI, it is only the attack vector demonstrated in this lab. The poisoned onboarding data is consumed by an agent capable of chaining MCP tools into a privileged provisioning API. The AI/MCP security implications deserve their own analysis and will be covered in a future article.*

## 4. Attack Demo : Moving the Trust Boundary

### 4.1 From Poisoned Data to Azure Trust

We start the lab with a simple Azure infrastructure with a managed identity `uami-property-indexer-partner-lab`. This identity already holds the Storage permissions required by the property-indexer workload, but no Federated Identity Credential is configured.

![InitAzureSetup](/assets/Images/2026-08-03-AzureIdentityFederation/FIC_Init_Setup_Azure.png)

On the attacker-controlled side, the first component required for the lab is a publicly reachable OIDC issuer. It is hosted on a VM with a public IP and DNS name: `https://fic-issuer-vm.francecentral.cloudapp.azure.com`.

At this stage, the issuer is entirely unrelated to the Property Indexer environment. It may be publicly reachable and fully controlled by the attacker, but Microsoft Entra has no configured reason to trust anything it signs.

![InitAzureAttackerSetup](/assets/Images/2026-08-03-AzureIdentityFederation/FIC_Init_Setup_Azure_Attacker.png)

To simulate a malicious partner update, the rogue Meridian employee modifies an otherwise legitimate free-text field in the onboarding record and embeds the indirect prompt injection payload.

The instruction is not submitted directly to the assistant. It sits inside business data and only enters the model context when the read-only Catalogue MCP returns the onboarding record.

The engineer's request itself is deliberately boring:

`Retrieve onboarding submission PRP-1842 and return its current JSON and platform status.`

Nothing in that request asks for Azure infrastructure or federation configuration to be modified.

The assistant first retrieves the submission, then crosses the read/write boundary:

`get_onboarding_submission` → `get_managed_identity` → `put_federated_identity_credential`

![PlatformAssistantGet](/assets/Images/2026-08-03-AzureIdentityFederation/FIC_PlaftomAssistant_GET.png)

![PlatformAssistantPut](/assets/Images/2026-08-03-AzureIdentityFederation/FIC_PlaftomAssistant_PUT.png)

The assistant itself does not possess Azure credentials. The write request is forwarded through the Provisioning MCP Server to the internal Provisioning API, which authenticates to Azure using its preconfigured service principal and performs the corresponding ARM operation against the existing UAMI.

The provisioning-side logs therefore show a second, privileged operation being executed as a consequence of what started as a simple retrieval request.

![ProvisioningAPIPut](/assets/Images/2026-08-03-AzureIdentityFederation/FIC_Provisioning_API_calls.png)

Checking the managed identity directly in Azure confirms that the previously unrelated external issuer has now been persisted as a Federated Identity Credential:

![UAMIPoisoned](/assets/Images/2026-08-03-AzureIdentityFederation/FIC_Provisioning.png)

No RBAC role assignment was modified during this phase, and the managed identity did not receive any additional Azure permissions. What changed was its authentication trust: an external issuer that previously had no relationship with the Property Indexer environment is now authorized to present assertions matching the configured federation tuple.

The next step is therefore no longer about influencing the AI workflow. Once the FIC exists, the attacker only needs to exercise the newly established trust from the external issuer.

### 4.2 From Malicious Trust to Azure Access

Now that a Federated Identity Credential trusting our rogue issuer has been configured on the Managed Identity, the second phase of the attack can be performed entirely from the external environment.

It starts with our external issuer, the VM with the public DNS, that will build assertions that Microsoft Entra ID can validate. This assertion is a signed JWT token but it is not an azure access token. It is a token that carries information or `claims` describing the external workload and is presented to Microsoft Entra ID as a credential. Entra validates the assertion and its signature, checks that its federation claims match the configured FIC, and can then issue a separate access token for the requested Azure resource.

To create the assertion, the VM holds an asymmetric RSA signing key pair, the private key remains on the issuer and is used to sign JWT assertions, while the corresponding public key is exposed through the issuer's JWKS endpoint. 

A freshly minted assertion can be decoded to inspect the claims:

![FICDecodedAssertion](/assets/Images/2026-08-03-AzureIdentityFederation/FIC_Assertion_Decoding.png)

Three values should look familiar as they match the value injected in the managed identity federated credentials:

- iss: https://fic-issuer-vm.francecentral.cloudapp.azure.com
- sub: partner-runtime/property-indexer
- aud: api://AzureADTokenExchange

**⚠️ Attention:** *[Microsoft Entra performs exact, case-sensitive matching of the FIC issuer, subject, and audience values](https://learn.microsoft.com/en-us/entra/identity-platform/reference-breaking-changes#federated-identity-credentials-now-use-case-sensitive-matching). In our lab, an unexpected trailing / in the configured issuer URL was enough to prevent the assertion from matching until both values were aligned.*

The attacker can now submit a request to the Microsoft identity platform token endpoint: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` to get an Azure access token: The request identifies the targeted UAMI through its `client_id` and provides the externally signed JWT as a `client_assertion`. The requested `scope` determines the Azure API for which the resulting access token should be issued.

The assertion itself does not change: `aud = api://AzureADTokenExchange`. What changes is the resource scope requested from Entra.

#### ARM

First, let's test Azure Resource Manager Access using `scope=https://management.azure.com/.default`:

![FICARMToken](/assets/Images/2026-08-03-AzureIdentityFederation/FIC_ARM_Entra_Token.png)

The returned bearer token can then be presented directly to the ARM REST API. Using it to list the resources visible to the UAMI demonstrates that the externally federated workload can exercise the identity's pre-existing control-plane permissions.

#### Storage

We repeat the exchange for Azure Storage using `scope=https://storage.azure.com/.default`:

![FICStorageToken](/assets/Images/2026-08-03-AzureIdentityFederation/FIC_Storage_Entra_Token.png)

Presenting that token to the Blob REST API allows us to enumerate the blobs available within the UAMI's already-authorized scope, demonstrating inheritance of the identity's existing data-plane permissions.

At this stage, both sides of the attack have been demonstrated. The first phase modified who Microsoft Entra was willing to trust as an authentication source for the UAMI. The second phase exercised that trust to obtain resource-specific access tokens and inherit the permissions the identity already possessed.

The role assignments never changed; the party capable of exercising them did.

## 5. Security Measures for Trust Issues

The AI agent was only the vector. Once the FIC is there, this becomes a workload identity problem.

**⚠️ Attention:** *Managed identities are currently [out of scope for Conditional Access for workload identities](https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity). In practice, this means we cannot restrict our UAMI to trusted network locations through CA. Once the rogue federation trust exists, the assertion exchange can be initiated from external infrastructure, just as it was in this lab.*

### 5.1 Preventive and Governance Controls

- Tightly restrict who can perform `Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write`.
This action allows a principal to add or update a FIC and is included in the built-in `Managed Identity Contributor` role. It should therefore be considered a privileged operation and scoped to the required identities only.

- A provisioning workflow should verify that the trust tuple: `issuer` + `subject` + `audience` is actually expected on the targeted identity. Particular attention should be given to the `issuer`, as it defines which external signing authority Entra is willing to trust. *Is this issuer approved for this specific UAMI, and are the associated subject and audience values consistent with that trust?*
That relationship should be checked against an approved workload identity baseline rather than derived from uncontrolled input.

- Federated credentials should also be part of the identity lifecycle: expected issuers and subjects, and removal conditions should be periodically reviewed alongside the UAMI's RBAC assignments.

### 5.2 Detection and Remediation

For detection, the event that matters most is the trust modification itself.

FIC creation, update and deletion are Azure control-plane operations. On sensitive managed identities, I would at least monitor for:

- Issuer URLs that are not expected or part of the approved federation baseline;
- FIC changes outside the expected provisioning workflow;

Once an unauthorized FIC is identified, removing it closes that federation path for future token exchanges. Azure also exposes `Microsoft.ManagedIdentity/userAssignedIdentities/revokeTokens/action` to revoke existing tokens for the UAMI.

The useful signal is the trust state itself: a federation relationship configured on the identity that should not exist.

## Conclusion

That's a wrap ! Security engineers must mind the Trust Gap. Reviewing what an identity can access is only half the job. The other half is knowing **who is allowed to become it**.