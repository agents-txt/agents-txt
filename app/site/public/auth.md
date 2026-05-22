# auth.md

You are an agent. This service supports **agentic registration**: discover → register → (claim if needed) → call API → handle revocation. Follow the steps in order; do not skip ahead.

This deployment hosts the [agents.txt](https://agents-txt.com) reference site. The agentic-registration walkthrough below is a working example of the [auth.md](https://github.com/workos/auth.md) shape advertised in `/agents.txt` under `Authorization: auth-md`. The OAuth metadata pair (`/.well-known/oauth-protected-resource` + `/.well-known/oauth-authorization-server`) is the same one used by the [`oauth2`](/spec#112-oauth2--oauth-20) protocol on this site; the additional `agent_auth` block on the AS metadata is what activates this flow.

Examples use the placeholder host `https://agents-txt.com`; substitute the host you read this document from.

## Step 1 — Discover

Discovery is two hops. You may have already done one.

The 401 response that pointed you here also carries a `WWW-Authenticate` header with the PRM URL:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://agents-txt.com/.well-known/oauth-protected-resource"
```

Pull the `resource_metadata` value from that header and fetch it (1a). If you do not have the 401 in hand, the conventional path on the resource server is `/.well-known/oauth-protected-resource`.

### 1a. Fetch the Protected Resource Metadata

```http
GET /.well-known/oauth-protected-resource
```

Response shape:

```json
{
  "resource": "https://agents-txt.com/",
  "resource_name": "agents.txt Standard",
  "authorization_servers": ["https://agents-txt.com/"],
  "scopes_supported": ["spec:read", "mcp:tools"],
  "bearer_methods_supported": ["header"]
}
```

What each field tells you:

- `resource` — the canonical URL of the API you are trying to call. Use this as the `aud` when minting an ID-JAG.
- `resource_name` / `resource_logo_uri` — display name and logo for the service. Surface these to the user when asking for consent.
- `authorization_servers` — base URLs of the OAuth Authorization Server(s) for this resource. The `agent_auth` block lives on one of these (see 1b).
- `scopes_supported` — scopes the resource server understands. The credential you receive will be scoped to some subset; you do not request specific scopes during registration.
- `bearer_methods_supported` — how you will send the credential in Step 5 (`"header"` = `Authorization: Bearer …`).

### 1b. Fetch the Authorization Server metadata

```http
GET <authorization_servers[0]>/.well-known/oauth-authorization-server
```

Response shape:

```json
{
  "resource": "https://agents-txt.com/",
  "authorization_servers": ["https://agents-txt.com/"],
  "scopes_supported": ["spec:read", "mcp:tools"],
  "bearer_methods_supported": ["header"],
  "agent_auth": {
    "skill": "https://agents-txt.com/auth.md",
    "register_uri": "https://agents-txt.com/agent/auth",
    "claim_uri": "https://agents-txt.com/agent/auth/claim",
    "revocation_uri": "https://agents-txt.com/agent/auth/revoke",
    "identity_types_supported": ["anonymous", "identity_assertion"],
    "anonymous": {
      "credential_types_supported": ["api_key"]
    },
    "identity_assertion": {
      "assertion_types_supported": [
        "urn:ietf:params:oauth:token-type:id-jag",
        "verified_email"
      ],
      "credential_types_supported": ["access_token", "api_key"]
    },
    "events_supported": [
      "https://schemas.workos.com/events/agent/auth/identity/assertion/revoked"
    ]
  }
}
```

The outer fields restate the PRM. The `agent_auth` block is the part written for you. Read it in full. Every field there is relevant:

- `skill` — the URL of this document.
- `register_uri` — where you POST to register (Step 3).
- `claim_uri` — where you POST the claim invite (Step 4, anonymous flow only).
- `revocation_uri` — where the provider POSTs a `logout+jwt` to revoke your credential. You do not call this; it tells you what to expect.
- `identity_types_supported` — which registration methods this service accepts. Pick yours from Step 2.
- `anonymous.credential_types_supported` — credential shapes available when registering anonymously.
- `identity_assertion.assertion_types_supported` — which assertion types this service accepts (ID-JAG, verified email, etc.).
- `identity_assertion.credential_types_supported` — credential shapes available when registering with an assertion.
- `events_supported` — security event schemas this service can ingest (currently revocation). Informational; you do not act on these directly.

## Step 2 — Pick a method

Use this decision tree:

1. **You have a session tied to a user identity and can exchange it for an ID-JAG, audience-bound to this service** → [identity_assertion + id-jag](#identity_assertion--id-jag).
2. **You have only the user's email** → [identity_assertion + email](#identity_assertion--email). Claim ceremony required.
3. **You have neither** → [anonymous](#anonymous). Claim ceremony optional; deferred until the user wants to take ownership.

Before sending: cross-check your choice against the `agent_auth` block. If the matching `*_supported` array does not list your method, this service will not accept that registration shape. Pick another or stop.

## Step 3 — Register

Before sending an `identity_assertion` (either variant), surface the service's `resource_name` and `resource_logo_uri` (from Step 1a) and the scope set you will be acting under, and confirm with the user. This is the user's only consent gate before their identity is asserted to the service. Skip this for `anonymous`. There is no user identity to assert.

### identity_assertion + id-jag

Before minting the ID-JAG, confirm your provider is on this service's trust list (publishing format is service-specific; check the AS metadata or service docs). If it is not, fall back to `identity_assertion + email` or `anonymous`.

Mint the assertion with:

- `aud` = the `resource` from the PRM
- `iss` = your provider's issuer URL (must be on the trust list above)
- `email_verified: true` OR `phone_number_verified: true`
- Fresh `jti`
- Near-term `exp` (~5 minutes)

```http
POST /agent/auth
Content-Type: application/json

{
  "type": "identity_assertion",
  "assertion_type": "urn:ietf:params:oauth:token-type:id-jag",
  "assertion": "<your ID-JAG JWT>",
  "requested_credential_type": "access_token"
}
```

Response (200):

```json
{
  "registration_id": "reg_...",
  "registration_type": "agent-provider",
  "credential_type": "access_token",
  "credential": "<token>",
  "credential_expires": "2026-06-04T13:00:00.000Z",
  "scopes": ["spec:read", "mcp:tools"]
}
```

Extract `credential`. Go to [Step 5](#step-5--use-the-credential).

### identity_assertion + email

```http
POST /agent/auth
Content-Type: application/json

{
  "type": "identity_assertion",
  "assertion_type": "verified_email",
  "assertion": "user@example.com",
  "requested_credential_type": "api_key"
}
```

Response (200):

```json
{
  "registration_id": "reg_...",
  "registration_type": "email-verification",
  "claim_url": "https://agents-txt.com/agent/auth/claim",
  "claim_token": "clm_...",
  "claim_token_expires": "2026-05-23T17:31:25.994Z",
  "post_claim_scopes": ["spec:read", "mcp:tools"]
}
```

There is no credential yet. The service has already emailed the user. Keep `claim_token` and go to [Step 4](#step-4--claim-ceremony). `claim_token` is returned exactly once. Hold it in memory for the duration of the ceremony; do not persist it past Step 4.

### anonymous

```http
POST /agent/auth
Content-Type: application/json

{
  "type": "anonymous",
  "requested_credential_type": "api_key"
}
```

Response (200):

```json
{
  "registration_id": "reg_...",
  "registration_type": "anonymous",
  "credential_type": "api_key",
  "credential": "sk_demo_...",
  "credential_expires": null,
  "scopes": ["spec:read"],
  "claim_url": "https://agents-txt.com/agent/auth/claim",
  "claim_token": "clm_...",
  "claim_token_expires": "2026-05-23T17:26:32.915Z",
  "post_claim_scopes": ["spec:read", "mcp:tools"]
}
```

You have a usable credential immediately at pre-claim scopes. If you also want a human to take ownership and unlock `post_claim_scopes`, go to [Step 4](#step-4--claim-ceremony). Otherwise skip to [Step 5](#step-5--use-the-credential). `claim_token` is returned exactly once. Hold it in memory for the duration of the ceremony; do not persist it past Step 4.

## Step 4 — Claim ceremony

The end goal: get the user to read a 6-digit OTP back to you.

### 4a. Trigger the claim email (anonymous only)

Skip this for `email` registrations. The email was sent during Step 3.

```http
POST /agent/auth/claim
Content-Type: application/json

{
  "claim_token": "clm_...",
  "email": "user@example.com"
}
```

Response (200):

```json
{
  "registration_id": "reg_...",
  "claim_attempt_id": "...",
  "status": "initiated",
  "expires_at": "..."
}
```

### 4b. Wait for the user's OTP

The user receives an email, clicks the link, sees a 6-digit OTP, reads it back to you. Surface this in your agent UI:

- Default ask: "Check your email and tell me the 6-digit code."
- If the user pastes the URL back instead of the code: "Open the link in your browser. The page will show a 6-digit code. Read it back to me."
- If the code is rejected: "That code did not work. Re-read it carefully, or open the email link again for a fresh one."

### 4c. Submit the OTP

```http
POST /agent/auth/claim/complete
Content-Type: application/json

{
  "claim_token": "clm_...",
  "otp": "123456"
}
```

Response on success (anonymous):

```json
{ "registration_id": "reg_...", "status": "claimed" }
```

Your existing pre-claim API key keeps working. Its scope set is upgraded in place. No new credential is issued.

Response on success (email-verification):

```json
{
  "registration_id": "reg_...",
  "status": "claimed",
  "credential_type": "access_token",
  "credential": "<token>",
  "credential_expires": "...",
  "scopes": ["spec:read", "mcp:tools"]
}
```

Extract `credential`.

## Step 5 — Use the credential

Whether `access_token` or `api_key`, present as a bearer token:

```http
GET /api/some-resource
Authorization: Bearer <credential>
```

- `access_token` from an ID-JAG: when it expires, mint a **fresh** ID-JAG and re-register. There is no refresh flow.
- `access_token` from a claim ceremony: when it expires, re-run the ceremony or present a fresh assertion.
- `api_key`: typically no expiry (`credential_expires: null`), but still subject to revocation.

If you get a 401 on a previously-working credential, drop it and restart at [Step 1](#step-1--discover). Do not stash the credential and retry.

For this deployment, the credential is usable against the MCP server at [`/mcp`](https://agents-txt.com/mcp) for any scope the credential carries. Full API reference: [`agents-txt.com/spec`](https://agents-txt.com/spec).

## Errors

| Code                          | Where                        | What to do                                                                             |
| ----------------------------- | ---------------------------- | -------------------------------------------------------------------------------------- |
| `invalid_signature`           | `/agent/auth` (ID-JAG)       | Signature did not verify. Mint a fresh ID-JAG.                                         |
| `replay_detected`             | `/agent/auth` (ID-JAG)       | `jti` already used. Mint a fresh ID-JAG with a new `jti`.                              |
| `audience_mismatch`           | `/agent/auth` (ID-JAG)       | `aud` wrong. Mint with the correct `aud` (this service's AS base URL).                 |
| `credential_expired`          | `/agent/auth` (ID-JAG)       | ID-JAG `exp` is past. Mint a fresh one.                                                |
| `anonymous_not_enabled`       | `/agent/auth`                | This service does not accept anonymous. Pick another method from Step 2.               |
| `verified_email_not_enabled`  | `/agent/auth`                | Email verification disabled here. Pick another method.                                 |
| `issuer_not_enabled`          | `/agent/auth`                | Provider not on this service's trust list. Pick another method.                        |
| `unsupported_credential_type` | `/agent/auth`                | Requested credential not supported for this method. Re-read AS metadata and adjust.    |
| `rate_limited` (429)          | any                          | Back off and retry.                                                                    |
| `invalid_claim_token`         | `/agent/auth/claim/complete` | `claim_token` wrong or expired. Restart at Step 3.                                     |
| `otp_invalid`                 | `/agent/auth/claim/complete` | OTP mismatch. Ask the user to re-read the code.                                        |
| `otp_expired`                 | `/agent/auth/claim/complete` | OTP window passed. Re-trigger the claim email (Step 4a) or restart at Step 3.          |
| `claim_expired`               | `/agent/auth/claim/complete` | The whole registration expired. Restart at Step 3.                                     |
| `previously_claimed`          | `/agent/auth/claim/complete` | Someone already finished this claim. Restart at Step 3 if you need a fresh credential. |

Retry policy:

- 5xx → exponential backoff, retry the same request.
- 4xx → do not retry the same payload; act on the table above.
- 401 on a previously-working credential → drop the credential and restart at [Step 1](#step-1--discover).

## Revocation

You do not initiate revocation yourself. Two paths exist:

- **Provider-driven (ID-JAG flows)**: the provider that minted your ID-JAG can POST a `logout+jwt` to this service's `revocation_uri`. Your credential will be invalidated. You discover this on the next API call returning 401. Restart at [Step 1](#step-1--discover).
- **Email / anonymous flows**: there is no agent-facing revoke endpoint. On a 401 for a previously-working credential, drop it and restart at Step 1.
