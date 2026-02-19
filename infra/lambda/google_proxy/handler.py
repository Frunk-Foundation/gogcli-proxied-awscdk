import base64
import json
import os
import re
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    import boto3
except Exception:  # pragma: no cover - runtime dependency in Lambda
    boto3 = None

try:
    import botocore.exceptions as botocore_exceptions
except Exception:  # pragma: no cover - local test fallback
    class _FallbackClientError(Exception):
        pass

    class _FallbackBotocoreExceptions:
        ClientError = _FallbackClientError

    botocore_exceptions = _FallbackBotocoreExceptions()

try:
    import requests
except Exception:  # pragma: no cover - local test fallback
    class _RequestsFallback:
        class Session:
            def request(self, *args: Any, **kwargs: Any) -> Any:
                raise RuntimeError("requests unavailable")

    requests = _RequestsFallback()

try:
    from google.auth.transport.requests import Request as GoogleAuthRequest
except Exception:  # pragma: no cover - local test fallback
    GoogleAuthRequest = None

try:
    from google.oauth2 import service_account
except Exception:  # pragma: no cover - local test fallback
    service_account = None

_SSM = boto3.client("ssm") if boto3 is not None else None
_EVENTS = boto3.client("events") if boto3 is not None else None
_HTTP = requests.Session()


class ProxyError(Exception):
    def __init__(self, status_code: int, message: str, *, extra: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.extra = extra or {}


def _json_response(status_code: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store",
        },
        "body": body,
        "isBase64Encoded": False,
    }


def _log_event(event_type: str, **fields: Any) -> None:
    payload: Dict[str, Any] = {"event": event_type}
    payload.update(fields)
    try:
        print(json.dumps(payload, separators=(",", ":"), sort_keys=True))
    except Exception:
        # Last-resort log safety to avoid breaking request flow.
        print(f'{{"event":"{event_type}","log_error":"serialization_failed"}}')


def _parse_bool_env(raw: Optional[str], *, default: bool) -> bool:
    if raw is None:
        return default
    val = raw.strip().lower()
    if val in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if val in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


def _policy_enabled() -> bool:
    return _parse_bool_env(os.getenv("GOG_POLICY_ENABLED"), default=True)


def _policy_cache_ttl_seconds() -> int:
    raw = os.getenv("GOG_POLICY_CACHE_TTL_SECONDS") or "30"
    try:
        val = int(raw)
    except ValueError:
        return 30
    if val < 1:
        return 1
    return val


def _policy_events_enabled() -> bool:
    return _parse_bool_env(os.getenv("GOG_POLICY_EVENTS_ENABLED"), default=False)


def _policy_ssm_prefix(default_ssm_prefix: str) -> str:
    override = (os.getenv("GOG_POLICY_SSM_PREFIX") or "").strip()
    if override != "":
        return override.rstrip("/")
    return f"{default_ssm_prefix.rstrip('/')}/policy"


def _b64url_nopad(raw: str) -> str:
    b = raw.encode("utf-8")
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _normalize_email(s: str) -> str:
    return s.strip().lower()


def _get_header(headers: Mapping[str, Any], name: str) -> str:
    want = name.lower()
    for k, v in headers.items():
        if k is None:
            continue
        if str(k).lower() == want and v is not None:
            return str(v)
    return ""


def _assumed_role_session_name(raw: str) -> str:
    val = str(raw or "").strip()
    if not val:
        return ""
    marker = ":assumed-role/"
    if marker in val:
        # ARN form: arn:aws:sts::<acct>:assumed-role/<role-name>/<session-name>
        tail = val.rsplit("/", 1)
        if len(tail) == 2 and tail[1].strip():
            return tail[1].strip()
    # STS caller form: <role-id>:<session-name>
    if val.startswith("AROA") and ":" in val:
        _, session = val.split(":", 1)
        session = session.strip()
        if session:
            return session
    return ""


def _caller_id(event: Mapping[str, Any]) -> str:
    rc = event.get("requestContext") or {}
    ident = (rc.get("identity") or {}) if isinstance(rc, dict) else {}
    if isinstance(ident, dict):
        cid = str(ident.get("cognitoIdentityId") or "").strip()
        if cid:
            return cid
        arn = str(ident.get("userArn") or "").strip()
        if arn:
            session = _assumed_role_session_name(arn)
            if session:
                return session
            return arn
        caller = str(ident.get("caller") or "").strip()
        if caller:
            session = _assumed_role_session_name(caller)
            if session:
                return session
            return caller
    return "unknown"


def _ssm_get_json(name: str, *, cache_ttl_seconds: int = 60) -> Optional[Dict[str, Any]]:
    if _SSM is None:
        raise ProxyError(500, "ssm client unavailable in runtime")

    now = time.time()
    cached = _CACHE.get(name)
    if cached is not None:
        value, exp = cached
        if exp > now:
            return value
        _CACHE.pop(name, None)

    try:
        resp = _SSM.get_parameter(Name=name, WithDecryption=True)
    except botocore_exceptions.ClientError as e:
        code = (e.response.get("Error") or {}).get("Code") if hasattr(e, "response") else None
        if code in ("ParameterNotFound",):
            _CACHE[name] = (None, now + cache_ttl_seconds)
            return None
        raise

    raw = (resp.get("Parameter") or {}).get("Value")
    if raw is None:
        _CACHE[name] = (None, now + cache_ttl_seconds)
        return None
    try:
        out = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ProxyError(500, f"invalid JSON in SSM parameter: {name}") from e
    if not isinstance(out, dict):
        raise ProxyError(500, f"SSM parameter must be a JSON object: {name}")

    _CACHE[name] = (out, now + cache_ttl_seconds)
    return out


def _ssm_get_policy_json(name: str) -> Optional[Dict[str, Any]]:
    return _ssm_get_json(name, cache_ttl_seconds=_policy_cache_ttl_seconds())


def _is_allowed(allow: Mapping[str, Any], email: str) -> bool:
    email = _normalize_email(email)
    if "*" in [str(x).strip() for x in (allow.get("emails") or []) if x is not None]:
        return True
    if "*" in [str(x).strip() for x in (allow.get("domains") or []) if x is not None]:
        return True

    allowed_emails = {_normalize_email(str(x)) for x in (allow.get("emails") or []) if x is not None}
    if email in allowed_emails:
        return True

    if "@" in email:
        domain = email.split("@", 1)[1]
        allowed_domains = {str(x).strip().lower() for x in (allow.get("domains") or []) if x is not None}
        if domain in allowed_domains:
            return True

    return False


def _default_scopes() -> List[str]:
    raw = os.getenv("GOG_DEFAULT_SCOPES", "")
    scopes = [s.strip() for s in raw.split(",") if s.strip()]
    # Keep stable ordering for readability/debugging.
    return sorted(set(scopes))


def _mint_access_token(account_email: str, cfg: Mapping[str, Any]) -> str:
    typ = str(cfg.get("type") or "").strip().lower()
    if typ == "":
        raise ProxyError(500, "google credential config missing required field: type")

    if typ == "service_account":
        if GoogleAuthRequest is None or service_account is None:
            raise ProxyError(500, "google service_account dependencies unavailable in runtime")
        info = cfg.get("service_account") or cfg.get("serviceAccount") or cfg.get("service_account_info") or cfg.get("serviceAccountInfo")
        if not isinstance(info, dict):
            raise ProxyError(500, "service_account config missing service_account object")

        scopes = cfg.get("scopes")
        if scopes is None:
            scope_list = _default_scopes()
        elif isinstance(scopes, list):
            scope_list = [str(s).strip() for s in scopes if str(s).strip()]
        else:
            raise ProxyError(500, "service_account scopes must be a JSON array of strings")

        delegate_subject = cfg.get("delegate_subject")
        if delegate_subject is None:
            subject = _normalize_email(account_email)
        else:
            subject = str(delegate_subject).strip()
            if subject == "":
                subject = None  # no domain-wide delegation

        if subject:
            creds = service_account.Credentials.from_service_account_info(info, scopes=scope_list, subject=subject)
        else:
            creds = service_account.Credentials.from_service_account_info(info, scopes=scope_list)

        try:
            creds.refresh(GoogleAuthRequest())
        except Exception as e:
            raise ProxyError(502, "failed to mint Google access token") from e

        token = str(getattr(creds, "token", "") or "").strip()
        if not token:
            raise ProxyError(502, "Google access token missing after refresh")
        return token

    elif typ == "oauth_refresh":
        client_id = str(cfg.get("client_id") or "").strip()
        client_secret = str(cfg.get("client_secret") or "").strip()
        refresh_token = str(cfg.get("refresh_token") or "").strip()
        token_uri = str(cfg.get("token_uri") or "https://oauth2.googleapis.com/token").strip()

        if not client_id or not client_secret or not refresh_token:
            raise ProxyError(500, "oauth_refresh config missing client_id/client_secret/refresh_token")

        scopes = cfg.get("scopes")
        if scopes is None:
            scope_str = ""
        elif isinstance(scopes, list):
            scope_str = " ".join(str(s).strip() for s in scopes if str(s).strip())
        else:
            raise ProxyError(500, "oauth_refresh scopes must be a JSON array of strings")

        form_data = {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
        }
        if scope_str:
            form_data["scope"] = scope_str

        try:
            token_resp = _HTTP.post(token_uri, data=form_data, timeout=20)
        except Exception as e:
            raise ProxyError(502, "failed to mint Google access token") from e

        if int(getattr(token_resp, "status_code", 0) or 0) != 200:
            raise ProxyError(502, "failed to mint Google access token")

        try:
            token_json = token_resp.json()
        except Exception as e:
            raise ProxyError(502, "failed to parse Google token response") from e

        token = str(token_json.get("access_token") or "").strip()
        if not token:
            raise ProxyError(502, "Google access token missing after refresh")
        return token

    else:
        raise ProxyError(500, f"unsupported google credential type: {typ}")


def _resolve_google_host_and_path(proxy_path: str) -> Tuple[str, str]:
    p = proxy_path.lstrip("/")
    if p == "":
        raise ProxyError(400, "missing Google API path")

    # Google upload endpoints use a prefix on the same host/path routing.
    prefix = ""
    rest = p
    if rest.startswith("resumable/upload/"):
        prefix = "resumable/upload/"
        rest = rest[len(prefix) :]
    elif rest.startswith("upload/"):
        prefix = "upload/"
        rest = rest[len(prefix) :]

    rest_lc = rest.lower()

    if rest_lc.startswith("gmail/"):
        host = "gmail.googleapis.com"
    elif rest_lc.startswith("drive/"):
        host = "www.googleapis.com"
    elif rest_lc.startswith("calendar/"):
        host = "www.googleapis.com"
    elif rest_lc.startswith("tasks/"):
        host = "tasks.googleapis.com"
    elif rest_lc.startswith("v4/"):
        # Sheets API: https://sheets.googleapis.com/v4/...
        host = "sheets.googleapis.com"
    elif rest_lc.startswith("v1/"):
        # Many modern Google APIs use per-product hosts with /v1/...
        parts = rest_lc.split("/")
        first = parts[1] if len(parts) > 1 else ""
        if first in ("documents",):
            host = "docs.googleapis.com"
        elif first in ("presentations",):
            host = "slides.googleapis.com"
        elif first in ("forms",):
            host = "forms.googleapis.com"
        elif first in ("projects",):
            host = "script.googleapis.com"
        elif first in ("spaces", "users"):
            host = "chat.googleapis.com"
        elif first in ("courses", "invitations", "registrations", "userprofiles", "teachers", "students"):
            host = "classroom.googleapis.com"
        elif first in ("people", "othercontacts", "contactgroups"):
            host = "people.googleapis.com"
        elif first in ("notes",):
            host = "keep.googleapis.com"
        elif first in ("groups", "devices"):
            host = "cloudidentity.googleapis.com"
        else:
            raise ProxyError(400, f"unrecognized Google API path: /{proxy_path.lstrip('/')}")
    else:
        raise ProxyError(400, f"unrecognized Google API path: /{proxy_path.lstrip('/')}")

    forward_path = "/" + prefix + rest
    return host, forward_path


_POLICY_TOP_KEYS = {"version", "default_effect", "rules"}
_POLICY_RULE_KEYS = {"id", "effect", "priority", "match", "constraints", "on_match"}
_POLICY_MATCH_KEYS = {"methods", "hosts", "path_regex", "query"}
_POLICY_QUERY_KEYS = {"require_keys", "forbid_keys"}
_POLICY_CONSTRAINT_KEYS = {"max_request_bytes", "require_account_domain"}
_POLICY_ON_MATCH_KEYS = {"emit_event", "event_type", "detail"}


def _as_lower_str_list(value: Any, *, field: str) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ProxyError(500, f"policy field {field} must be a JSON array")
    out = []
    for item in value:
        s = str(item).strip().lower()
        if s != "":
            out.append(s)
    return out


def _as_upper_str_list(value: Any, *, field: str) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ProxyError(500, f"policy field {field} must be a JSON array")
    out = []
    for item in value:
        s = str(item).strip().upper()
        if s != "":
            out.append(s)
    return out


def _normalize_policy_rule(rule: Any, *, source: str, source_rank: int, index: int) -> Dict[str, Any]:
    if not isinstance(rule, dict):
        raise ProxyError(500, f"policy rule {source}[{index}] must be an object")

    unknown_rule = sorted(set(rule.keys()) - _POLICY_RULE_KEYS)
    if unknown_rule:
        raise ProxyError(500, f"policy rule {source}[{index}] has unknown keys: {','.join(unknown_rule)}")

    rule_id = str(rule.get("id") or f"{source}-rule-{index}").strip()
    if rule_id == "":
        raise ProxyError(500, f"policy rule {source}[{index}] has empty id")

    effect = str(rule.get("effect") or "deny").strip().lower()
    if effect not in {"allow", "deny"}:
        raise ProxyError(500, f"policy rule {source}[{index}] effect must be allow|deny")

    priority = rule.get("priority", 0)
    try:
        priority_int = int(priority)
    except (TypeError, ValueError):
        raise ProxyError(500, f"policy rule {source}[{index}] priority must be an integer")

    match = rule.get("match") or {}
    if not isinstance(match, dict):
        raise ProxyError(500, f"policy rule {source}[{index}] match must be an object")

    unknown_match = sorted(set(match.keys()) - _POLICY_MATCH_KEYS)
    if unknown_match:
        raise ProxyError(500, f"policy rule {source}[{index}] match has unknown keys: {','.join(unknown_match)}")

    methods = sorted(set(_as_upper_str_list(match.get("methods"), field="methods")))
    hosts = sorted(set(_as_lower_str_list(match.get("hosts"), field="hosts")))

    path_regex = match.get("path_regex")
    if path_regex is None:
        path_regex_str = ""
    else:
        path_regex_str = str(path_regex).strip()
    if path_regex_str != "":
        try:
            re.compile(path_regex_str)
        except re.error as e:
            raise ProxyError(500, f"policy rule {source}[{index}] has invalid path_regex") from e

    query = match.get("query") or {}
    if not isinstance(query, dict):
        raise ProxyError(500, f"policy rule {source}[{index}] query must be an object")
    unknown_query = sorted(set(query.keys()) - _POLICY_QUERY_KEYS)
    if unknown_query:
        raise ProxyError(500, f"policy rule {source}[{index}] query has unknown keys: {','.join(unknown_query)}")
    query_require_keys = sorted(set(_as_lower_str_list(query.get("require_keys"), field="require_keys")))
    query_forbid_keys = sorted(set(_as_lower_str_list(query.get("forbid_keys"), field="forbid_keys")))

    constraints = rule.get("constraints") or {}
    if not isinstance(constraints, dict):
        raise ProxyError(500, f"policy rule {source}[{index}] constraints must be an object")
    unknown_constraints = sorted(set(constraints.keys()) - _POLICY_CONSTRAINT_KEYS)
    if unknown_constraints:
        raise ProxyError(
            500,
            f"policy rule {source}[{index}] constraints has unknown keys: {','.join(unknown_constraints)}",
        )

    max_request_bytes = constraints.get("max_request_bytes")
    if max_request_bytes is None:
        max_request_bytes_int = None
    else:
        try:
            max_request_bytes_int = int(max_request_bytes)
        except (TypeError, ValueError):
            raise ProxyError(500, f"policy rule {source}[{index}] max_request_bytes must be an integer")
        if max_request_bytes_int < 0:
            raise ProxyError(500, f"policy rule {source}[{index}] max_request_bytes must be >= 0")

    require_account_domain = sorted(
        set(_as_lower_str_list(constraints.get("require_account_domain"), field="require_account_domain"))
    )

    on_match = rule.get("on_match") or {}
    if not isinstance(on_match, dict):
        raise ProxyError(500, f"policy rule {source}[{index}] on_match must be an object")
    unknown_on_match = sorted(set(on_match.keys()) - _POLICY_ON_MATCH_KEYS)
    if unknown_on_match:
        raise ProxyError(500, f"policy rule {source}[{index}] on_match has unknown keys: {','.join(unknown_on_match)}")

    emit_event = bool(on_match.get("emit_event", False))
    event_type = str(on_match.get("event_type") or f"proxy.policy.{effect}.{rule_id}").strip()
    if event_type == "":
        event_type = f"proxy.policy.{effect}.{rule_id}"
    detail = on_match.get("detail") or {}
    if not isinstance(detail, dict):
        raise ProxyError(500, f"policy rule {source}[{index}] on_match.detail must be an object")

    return {
        "id": rule_id,
        "effect": effect,
        "priority": priority_int,
        "source": source,
        "source_rank": source_rank,
        "source_index": index,
        "match": {
            "methods": methods,
            "hosts": hosts,
            "path_regex": path_regex_str,
            "query_require_keys": query_require_keys,
            "query_forbid_keys": query_forbid_keys,
        },
        "constraints": {
            "max_request_bytes": max_request_bytes_int,
            "require_account_domain": require_account_domain,
        },
        "on_match": {
            "emit_event": emit_event,
            "event_type": event_type,
            "detail": detail,
        },
    }


def _normalize_policy_document(doc: Any, *, source: str, source_rank: int) -> Dict[str, Any]:
    if not isinstance(doc, dict):
        raise ProxyError(500, f"policy {source} must be a JSON object")

    unknown_keys = sorted(set(doc.keys()) - _POLICY_TOP_KEYS)
    if unknown_keys:
        raise ProxyError(500, f"policy {source} has unknown keys: {','.join(unknown_keys)}")

    version_raw = doc.get("version", 1)
    try:
        version = int(version_raw)
    except (TypeError, ValueError):
        raise ProxyError(500, f"policy {source} version must be an integer")
    if version != 1:
        raise ProxyError(500, f"policy {source} has unsupported version: {version}")

    default_effect = str(doc.get("default_effect") or "deny").strip().lower()
    if default_effect not in {"allow", "deny"}:
        raise ProxyError(500, f"policy {source} default_effect must be allow|deny")

    rules = doc.get("rules") or []
    if not isinstance(rules, list):
        raise ProxyError(500, f"policy {source} rules must be a JSON array")

    normalized_rules = [
        _normalize_policy_rule(rule, source=source, source_rank=source_rank, index=idx) for idx, rule in enumerate(rules)
    ]

    return {
        "version": version,
        "default_effect": default_effect,
        "rules": normalized_rules,
        "source": source,
        "source_rank": source_rank,
    }


def _merge_policy_documents(docs: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {"version": 1, "default_effect": "deny", "rules": []}
    for doc in docs:
        merged["default_effect"] = doc["default_effect"]
        merged["rules"].extend(doc["rules"])

    merged["rules"].sort(
        key=lambda r: (
            -int(r["priority"]),
            -int(r["source_rank"]),
            int(r["source_index"]),
        )
    )
    return merged


def _extract_account_domain(account_email: str) -> str:
    email = _normalize_email(account_email)
    if "@" not in email:
        return ""
    return email.split("@", 1)[1]


def _build_query_keys(event: Mapping[str, Any]) -> List[str]:
    keys = set()
    qs_multi = event.get("multiValueQueryStringParameters")
    if isinstance(qs_multi, dict):
        for k in qs_multi.keys():
            if k is None:
                continue
            keys.add(str(k).strip().lower())
    qs_single = event.get("queryStringParameters")
    if isinstance(qs_single, dict):
        for k in qs_single.keys():
            if k is None:
                continue
            keys.add(str(k).strip().lower())
    return sorted(k for k in keys if k != "")


def _rule_match(rule: Mapping[str, Any], ctx: Mapping[str, Any]) -> Tuple[bool, str]:
    match = rule["match"]
    constraints = rule["constraints"]

    methods = match["methods"]
    if methods and ctx["method"] not in methods:
        return False, "method_not_allowed"

    hosts = match["hosts"]
    if hosts and ctx["host"] not in hosts:
        return False, "host_not_allowed"

    path_regex = match["path_regex"]
    if path_regex != "" and re.match(path_regex, ctx["path"]) is None:
        return False, "path_not_allowed"

    query_keys = set(ctx["query_keys"])
    for req_key in match["query_require_keys"]:
        if req_key not in query_keys:
            return False, "required_query_key_missing"
    for forbid_key in match["query_forbid_keys"]:
        if forbid_key in query_keys:
            return False, "forbidden_query_key_present"

    max_request_bytes = constraints["max_request_bytes"]
    if max_request_bytes is not None and int(ctx["request_size_bytes"]) > int(max_request_bytes):
        return False, "request_too_large"

    required_domains = constraints["require_account_domain"]
    if required_domains and ctx["account_domain"] not in required_domains:
        return False, "account_domain_not_allowed"

    return True, "matched"


def _evaluate_policy(policy: Mapping[str, Any], ctx: Mapping[str, Any]) -> Dict[str, Any]:
    for rule in policy["rules"]:
        matched, reason = _rule_match(rule, ctx)
        if not matched:
            continue
        return {
            "effect": rule["effect"],
            "rule_id": rule["id"],
            "source": rule["source"],
            "reason": reason,
            "on_match": rule["on_match"],
        }

    return {
        "effect": policy["default_effect"],
        "rule_id": "",
        "source": "default_effect",
        "reason": "default_effect",
        "on_match": {"emit_event": False, "event_type": "", "detail": {}},
    }


def _load_effective_policy(policy_prefix: str, caller_id: str, account_email: str) -> Dict[str, Any]:
    entries = [
        ("default", 0, f"{policy_prefix}/default"),
        ("caller", 1, f"{policy_prefix}/caller/{_b64url_nopad(caller_id)}"),
        ("account", 2, f"{policy_prefix}/account/{_b64url_nopad(_normalize_email(account_email))}"),
    ]
    docs: List[Dict[str, Any]] = []
    for source, rank, name in entries:
        raw = _ssm_get_policy_json(name)
        if raw is None:
            continue
        docs.append(_normalize_policy_document(raw, source=source, source_rank=rank))
    if not docs:
        raise ProxyError(403, "policy_not_found")
    return _merge_policy_documents(docs)


def _maybe_emit_policy_event(decision: Mapping[str, Any], ctx: Mapping[str, Any], status_code: int) -> None:
    if not _policy_events_enabled():
        return
    on_match = decision.get("on_match") or {}
    if not bool(on_match.get("emit_event")):
        return

    bus_arn = (os.getenv("GOG_POLICY_EVENT_BUS_ARN") or "").strip()
    if bus_arn == "":
        _log_event("policy_trigger_skipped", reason="missing_event_bus_arn")
        return
    if _EVENTS is None:
        _log_event("policy_trigger_skipped", reason="events_client_unavailable")
        return

    detail = {
        "decision": str(decision.get("effect", "")),
        "rule_id": str(decision.get("rule_id", "")),
        "reason": str(decision.get("reason", "")),
        "caller_id": str(ctx.get("caller_id", "")),
        "account_email": str(ctx.get("account_email", "")),
        "method": str(ctx.get("method", "")),
        "host": str(ctx.get("host", "")),
        "path": str(ctx.get("path", "")),
        "status_code": int(status_code),
        "request_id": str(ctx.get("request_id", "")),
        "timestamp": int(time.time()),
    }
    extra_detail = on_match.get("detail") or {}
    if isinstance(extra_detail, dict):
        detail["extra"] = extra_detail

    try:
        _EVENTS.put_events(
            Entries=[
                {
                    "EventBusName": bus_arn,
                    "Source": "gogcli.proxy.policy",
                    "DetailType": str(on_match.get("event_type") or "proxy.policy.match"),
                    "Detail": json.dumps(detail, separators=(",", ":"), sort_keys=True),
                }
            ]
        )
    except Exception as e:  # pragma: no cover - best effort side effect
        _log_event("policy_trigger_error", error_type=type(e).__name__)


def _iter_query_pairs(qs_multi: Optional[Mapping[str, Any]], qs_single: Optional[Mapping[str, Any]]) -> Iterable[Tuple[str, str]]:
    if qs_multi:
        for k, vs in qs_multi.items():
            if k is None or vs is None:
                continue
            if isinstance(vs, list):
                for v in vs:
                    if v is None:
                        continue
                    yield str(k), str(v)
            else:
                yield str(k), str(vs)
        return

    if qs_single:
        for k, v in qs_single.items():
            if k is None or v is None:
                continue
            yield str(k), str(v)


def _build_query_string(event: Mapping[str, Any]) -> str:
    from urllib.parse import urlencode

    qs_multi = event.get("multiValueQueryStringParameters")
    qs_single = event.get("queryStringParameters")
    pairs = list(_iter_query_pairs(qs_multi, qs_single))
    if not pairs:
        return ""
    return urlencode(pairs, doseq=True, safe="~")


def _sanitize_outgoing_headers(in_headers: Mapping[str, Any]) -> Dict[str, str]:
    hop_by_hop = {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
    strip = {
        "host",
        "authorization",
        "x-amz-date",
        "x-amz-security-token",
        "x-api-key",
        "x-gog-account",
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-port",
        "via",
        "content-length",
    }

    out: Dict[str, str] = {}
    for k, v in in_headers.items():
        if k is None or v is None:
            continue
        key = str(k).strip()
        if key == "":
            continue
        key_lc = key.lower()
        if key_lc in hop_by_hop or key_lc in strip:
            continue
        out[key] = str(v)
    return out


def _is_textual_content_type(content_type: str) -> bool:
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if ct == "":
        return True
    if ct.startswith("text/"):
        return True
    if ct in ("application/json", "application/xml", "application/x-www-form-urlencoded"):
        return True
    if ct.endswith("+json") or ct.endswith("+xml"):
        return True
    return False


def _sanitize_response_headers(in_headers: Mapping[str, Any]) -> Dict[str, str]:
    strip = {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "content-length",
        # requests may transparently decompress; avoid lying to the client.
        "content-encoding",
    }
    out: Dict[str, str] = {}
    for k, v in in_headers.items():
        if k is None or v is None:
            continue
        key = str(k).strip()
        if key == "":
            continue
        if key.lower() in strip:
            continue
        out[key] = str(v)
    return out


def _read_event_body(event: Mapping[str, Any], *, max_bytes: int) -> bytes:
    body = event.get("body")
    if body is None:
        return b""
    if not isinstance(body, str):
        body = str(body)

    if event.get("isBase64Encoded") is True:
        try:
            raw = base64.b64decode(body)
        except Exception as e:
            raise ProxyError(400, "invalid base64 request body") from e
    else:
        raw = body.encode("utf-8")

    if len(raw) > max_bytes:
        raise ProxyError(413, "request body too large for proxy")
    return raw


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    try:
        ssm_prefix = (os.getenv("GOG_SSM_PREFIX") or "/gogcli-proxy").rstrip("/")
        policy_prefix = _policy_ssm_prefix(ssm_prefix)
        policy_is_enabled = _policy_enabled()
        max_req = int(os.getenv("GOG_MAX_REQUEST_BYTES") or "9500000")
        max_resp = int(os.getenv("GOG_MAX_RESPONSE_BYTES") or "5500000")

        headers = event.get("headers") or {}
        if not isinstance(headers, dict):
            headers = {}

        account = _normalize_email(_get_header(headers, "X-GOG-Account"))
        if account == "" or " " in account or "@" not in account:
            raise ProxyError(400, "missing or invalid X-GOG-Account header")

        caller = _caller_id(event)
        allow_param = f"{ssm_prefix}/allow/{_b64url_nopad(caller)}"
        allow_cfg = _ssm_get_json(allow_param)
        if allow_cfg is None or not _is_allowed(allow_cfg, account):
            raise ProxyError(403, "caller not authorized for requested account")

        acct_param = f"{ssm_prefix}/google/accounts/{_b64url_nopad(account)}"
        acct_cfg = _ssm_get_json(acct_param)
        if acct_cfg is None:
            raise ProxyError(403, "requested account is not configured in proxy")

        method = str(event.get("httpMethod") or "GET").upper()

        pp = event.get("pathParameters") or {}
        proxy = pp.get("proxy") if isinstance(pp, dict) else None
        path = "/" + str(proxy) if proxy else str(event.get("path") or "/")

        host, forward_path = _resolve_google_host_and_path(path)
        query = _build_query_string(event)
        url = f"https://{host}{forward_path}"
        if query:
            url = f"{url}?{query}"

        body_bytes = _read_event_body(event, max_bytes=max_req)
        query_keys = _build_query_keys(event)
        request_id = str((event.get("requestContext") or {}).get("requestId") or "")
        policy_decision = {
            "effect": "allow",
            "rule_id": "",
            "source": "disabled",
            "reason": "policy_disabled",
            "on_match": {"emit_event": False, "event_type": "", "detail": {}},
        }
        policy_ctx = {
            "caller_id": caller,
            "account_email": account,
            "account_domain": _extract_account_domain(account),
            "method": method,
            "host": host.lower(),
            "path": forward_path,
            "query_keys": query_keys,
            "request_size_bytes": len(body_bytes),
            "request_id": request_id,
        }

        if policy_is_enabled:
            policy = _load_effective_policy(policy_prefix, caller, account)
            policy_decision = _evaluate_policy(policy, policy_ctx)
            _log_event(
                "policy_decision",
                decision=policy_decision["effect"],
                rule_id=policy_decision["rule_id"],
                reason=policy_decision["reason"],
                source=policy_decision["source"],
                caller_id=caller,
                account_email=account,
                method=method,
                host=host.lower(),
                path=forward_path,
            )
            if policy_decision["effect"] != "allow":
                _maybe_emit_policy_event(policy_decision, policy_ctx, 403)
                raise ProxyError(
                    403,
                    "policy_denied",
                    extra={
                        "rule_id": policy_decision["rule_id"],
                        "reason": policy_decision["reason"],
                        "source": policy_decision["source"],
                    },
                )
        else:
            _log_event("policy_decision", decision="allow", reason="policy_disabled", source="disabled")

        token = _mint_access_token(account, acct_cfg)

        out_headers = _sanitize_outgoing_headers(headers)
        out_headers["Authorization"] = f"Bearer {token}"

        resp = _HTTP.request(
            method,
            url,
            headers=out_headers,
            data=body_bytes if body_bytes else None,
            stream=True,
            allow_redirects=False,
            timeout=(5, 30),
        )

        # Enforce Lambda response limit by streaming with a cap.
        chunks: List[bytes] = []
        total = 0
        for chunk in resp.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_resp:
                raise ProxyError(502, "upstream response too large for Lambda")
            chunks.append(chunk)
        payload = b"".join(chunks)

        resp_headers = _sanitize_response_headers(resp.headers)
        content_type = resp_headers.get("Content-Type") or resp.headers.get("Content-Type") or ""

        if _is_textual_content_type(content_type):
            body_out = payload.decode("utf-8", errors="replace")
            is_b64 = False
        else:
            body_out = base64.b64encode(payload).decode("ascii")
            is_b64 = True

        response = {
            "statusCode": int(resp.status_code),
            "headers": resp_headers,
            "body": body_out,
            "isBase64Encoded": is_b64,
        }
        if policy_is_enabled:
            _maybe_emit_policy_event(policy_decision, policy_ctx, int(resp.status_code))
        return response

    except ProxyError as e:
        payload = {"error": e.message}
        payload.update(e.extra)
        return _json_response(e.status_code, payload)
    except Exception as e:
        # Avoid leaking secrets in exception strings.
        _log_event("proxy_internal_error", error_type=type(e).__name__)
        return _json_response(500, {"error": "internal proxy error"})


# Simple in-memory cache for SSM JSON blobs.
# Key: param name; Value: (json or None, expires_epoch_seconds)
_CACHE: Dict[str, Tuple[Optional[Dict[str, Any]], float]] = {}
