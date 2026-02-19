# gogcli-proxy Infra (CDK)

This folder contains a small Python AWS CDK app that deploys:

- 1 Lambda: Google API proxy (injects Google credentials based on `X-GOG-Account`)
- 1 API Gateway REST API: `ANY /{proxy+}` to the Lambda
  - Authorization: IAM (SigV4)
  - API key required (usage plan)

The gogcli client is already wired to:

- send `X-GOG-Account: <email>`
- send `x-api-key: <api-key>`
- SigV4-sign the request for `execute-api`

## Deploy

From `infra/`:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cdk bootstrap
cdk deploy
```

Outputs include:

- `ProxyBaseUrl`: set this as `GOG_PROXY_BASE_URL` in the client
- `ApiKeyId`: use AWS CLI to fetch the API key value

Fetch API key value:

```bash
aws apigateway get-api-key --api-key <ApiKeyId> --include-value
```

Client env:

```bash
export GOG_PROXY_BASE_URL='https://abc123.execute-api.us-east-1.amazonaws.com/prod/'
export GOG_PROXY_API_KEY='...value from get-api-key...'
```

## SSM Parameters

The Lambda reads SSM parameters under `GOG_SSM_PREFIX` (default: `/gogcli-proxy`).

Parameter names use base64url (no padding) encoding for safety.

### Allowlist (deny-by-default)

Name:

- `<prefix>/allow/<caller_id_enc>`

Value JSON:

```json
{
  "emails": ["user@example.com"],
  "domains": ["example.com"]
}
```

Notes:

- `caller_id` is taken from `requestContext.identity.cognitoIdentityId` when present, else `requestContext.identity.userArn`.
- Matching is case-insensitive. `emails` entries may also be `"*"` to allow any email for that caller.

### Google Credentials (per account)

Name:

- `<prefix>/google/accounts/<email_enc>`

Value JSON: one of:

Service account (domain-wide delegation):

```json
{
  "type": "service_account",
  "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
  "service_account": {
    "type": "service_account",
    "project_id": "my-project",
    "private_key_id": "....",
    "private_key": "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----\\n",
    "client_email": "svc@my-project.iam.gserviceaccount.com",
    "client_id": "....",
    "token_uri": "https://oauth2.googleapis.com/token"
  }
}
```

OAuth refresh token:

```json
{
  "type": "oauth_refresh",
  "client_id": "....apps.googleusercontent.com",
  "client_secret": "....",
  "refresh_token": "....",
  "token_uri": "https://oauth2.googleapis.com/token"
}
```

Notes:

- For `service_account`, the proxy impersonates the requested `X-GOG-Account` email (domain-wide delegation subject).
- For `oauth_refresh`, omit `scopes` unless you know the refresh token was minted with those scopes.

## Policy Enforcement (Lambda)

Policy is enforced in the proxy Lambda (deny-by-default) when `GOG_POLICY_ENABLED=true` (default).

Policy SSM prefix defaults to:

- `<GOG_SSM_PREFIX>/policy` (for example `/gogcli-proxy/policy`)

Policy document lookup order:

1. `<policy_prefix>/default`
2. `<policy_prefix>/caller/<caller_id_enc>`
3. `<policy_prefix>/account/<email_enc>`

If no policy document exists, requests are denied with `{"error":"policy_not_found"}`.

### Policy JSON schema (v1)

```json
{
  "version": 1,
  "default_effect": "deny",
  "rules": [
    {
      "id": "gmail-read",
      "effect": "allow",
      "priority": 100,
      "match": {
        "methods": ["GET"],
        "hosts": ["gmail.googleapis.com"],
        "path_regex": "^/gmail/v1/users/me/(labels|messages|threads)(/.*)?$",
        "query": {
          "forbid_keys": ["uploadtype"]
        }
      },
      "constraints": {
        "max_request_bytes": 1048576,
        "require_account_domain": ["frunkholdings.ltd"]
      },
      "on_match": {
        "emit_event": true,
        "event_type": "proxy.policy.allow.gmail_read",
        "detail": {
          "policyVersion": "v1"
        }
      }
    },
    {
      "id": "deny-mutations",
      "effect": "deny",
      "priority": 90,
      "match": {
        "methods": ["POST", "PUT", "PATCH", "DELETE"]
      }
    }
  ]
}
```

Notes:

- Rules are evaluated by `priority` desc, then source specificity (account > caller > default), then declaration order.
- First matching rule wins.
- Unknown keys are rejected (fail closed).

### Policy trigger events (optional)

Enable match-triggered events:

```bash
export GOG_POLICY_EVENTS_ENABLED=true
export GOG_POLICY_EVENT_BUS_ARN='arn:aws:events:...:event-bus/your-bus'
```

When enabled and a matching rule has `on_match.emit_event=true`, Lambda emits an EventBridge event with decision metadata.
Trigger failures are logged but do not change allow/deny results.
