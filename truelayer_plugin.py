"""TrueLayer bank provider plugin for Securo.

A port of the TrueLayer side of truelayer2actual (github.com/jasmucrai/truelayer2actual)
to Securo's bank provider plugin contract. Securo calls ``oauth_url`` and
``oauth_exchange`` during Connect Bank, then ``sync`` on the integration's
schedule. ``sync`` returns bank records that Securo writes through the same
pipeline it uses for Pluggy, Enable Banking and SimpleFIN.

Only the Python standard library is used: the plugin runner has no third-party
packages unless the manifest names a hashed lockfile.
"""

from __future__ import annotations

import base64
import datetime as dt
import functools
import ipaddress
import json
import random
import struct
import sys
import traceback
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections.abc import Mapping
from contextlib import suppress
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from functools import lru_cache
from typing import Any

DEFAULT_SCOPES = "accounts balance transactions cards offline_access"
DEFAULT_PROVIDERS = "uk-cs-mock uk-ob-all uk-oauth-all"
DEFAULT_HISTORY_DAYS = 7
MIN_HISTORY_DAYS = 1
MAX_HISTORY_DAYS = 365
TOKEN_BUFFER_SECONDS = 60
HTTP_TIMEOUT_SECONDS = 15
MAX_PAGES = 50
CENT = Decimal("0.01")

HOSTS = frozenset(
    {
        "auth.truelayer.com",
        "auth.truelayer-sandbox.com",
        "api.truelayer.com",
        "api.truelayer-sandbox.com",
    }
)
CARD_KINDS = frozenset({"credit_card", "checking", "savings"})
LIABILITY_ACCOUNT_TYPES = frozenset({"credit_card", "loan"})
BALANCE_FIELDS = frozenset({"available", "current"})
DEFAULT_BALANCE_FIELD = "available"
# Securo sums every imported row when it derives the synthetic opening balance,
# including pending ones. A pending row carries an unconvertible currency so
# Securo's balance maths sees zero while the row itself stays visible with its
# original amount. The balance we report comes from TrueLayer's `available`
# for spendable accounts, the number the bank app shows after pending holds;
# liabilities keep `current`, where `available` means remaining credit instead.
PENDING_CURRENCY = "XXX"
PENDING_FALLBACK_CURRENCY = "ZZZ"

# GB ISP IPv4 ranges from ipverse/as-ip-blocks (CC0), packed as (start, size)
# uint32 pairs and zlib-compressed. Bundling a snapshot keeps every sync free
# of a 17 MB archive download and ~24 s of tar/JSON parsing. The data is only
# used to make a plausible X-PSU-IP address; refresh the snapshot with a new
# plugin release when the upstream dataset changes materially.
_GB_ISP_RANGES_B64 = """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"""


@lru_cache(maxsize=1)
def _gb_isp_ranges() -> tuple[tuple[int, int], ...]:
    """The bundled ranges, decoded once and kept as plain integer pairs."""
    packed = zlib.decompress(base64.b64decode(_GB_ISP_RANGES_B64))
    return tuple(
        struct.unpack_from(">II", packed, offset)
        for offset in range(0, len(packed), 8)
    )


def random_gb_isp_ip() -> str:
    """One random address from a GB ISP range, without any network access."""
    start, size = random.choice(_gb_isp_ranges())
    address = start + random.randrange(size)
    return f"{address >> 24}.{(address >> 16) & 0xFF}.{(address >> 8) & 0xFF}.{address & 0xFF}"


class NeedsAuth(Exception):
    """The consent or token is no longer usable. Securo shows 'expired'."""


class RateLimited(Exception):
    """TrueLayer asked us to slow down. Securo keeps the connection healthy."""


class UpstreamError(Exception):
    """A TrueLayer call failed for a reason the person may be able to fix."""

    def __init__(self, status: int | None, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.code = code


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------

_LOG_SAFE_KEYS = frozenset(
    {"redirect_uri", "since", "last_sync_at", "client_id", "providers", "history_days", "card_kind"}
)
_LOG_SECRET_HINTS = ("secret", "token", "code", "state", "password", "key", "auth")


def _sensitive_values(*sources: Any) -> list[str]:
    """Values that must never appear in a plugin log line."""
    values: set[str] = set()
    for source in sources:
        if not isinstance(source, Mapping):
            continue
        for key, value in source.items():
            name = str(key).lower()
            if name in _LOG_SAFE_KEYS or value is None or isinstance(value, bool):
                continue
            if any(hint in name for hint in _LOG_SECRET_HINTS):
                text = str(value)
                if len(text) >= 4:
                    values.add(text)
    return sorted(values, key=len, reverse=True)


def _mask(text: str, values: list[str]) -> str:
    for value in values:
        text = text.replace(value, "***")
    return text


def _clip_log(text: Any, limit: int = 500) -> str:
    value = str(text)
    return value if len(value) <= limit else f"{value[:limit]}..."


def _log_failure(method: str, exc: BaseException, params: Any, context: Any) -> None:
    """Print one safe error line to stderr; the runner logs it as plugin output."""
    values = _sensitive_values(
        params, getattr(context, "secrets", None), getattr(context, "config", None)
    )
    message = _mask(_clip_log(exc), values)
    extra = ""
    if isinstance(exc, UpstreamError):
        extra = f" status={exc.status} upstream_code={_mask(str(exc.code or ''), values)}"

    safe: dict[str, Any] = {}
    config = getattr(context, "config", None)
    if isinstance(config, Mapping) and config.get("client_id"):
        safe["client_id"] = str(config["client_id"])
    if isinstance(params, Mapping):
        for key in ("redirect_uri", "since"):
            if params.get(key):
                safe[key] = str(params[key])

    print(
        f"truelayer_plugin.{method} failed: {type(exc).__name__}: {message}{extra} "
        f"context={json.dumps(safe, sort_keys=True)}",
        file=sys.stderr,
        flush=True,
    )
    if not isinstance(exc, (NeedsAuth, RateLimited, UpstreamError, ValueError)):
        print(_mask(traceback.format_exc(), values), file=sys.stderr, flush=True)


def _logged(method: str):
    """Log and re-raise, so Securo still gets its structured error reply."""

    def decorate(func):
        @functools.wraps(func)
        def wrapper(self, params: Any, context: Any):
            try:
                return func(self, params, context)
            except Exception as exc:
                _log_failure(method, exc, params, context)
                raise

        return wrapper

    return decorate


# ---------------------------------------------------------------------------
# Environments and HTTP
# ---------------------------------------------------------------------------


def is_sandbox(client_id: str) -> bool:
    """TrueLayer marks sandbox apps with a ``sandbox-`` client id prefix."""
    return client_id.strip().lower().startswith("sandbox-")


def auth_base_url(client_id: str) -> str:
    return "https://auth.truelayer-sandbox.com" if is_sandbox(client_id) else "https://auth.truelayer.com"


def api_base_url(client_id: str) -> str:
    return "https://api.truelayer-sandbox.com" if is_sandbox(client_id) else "https://api.truelayer.com"


def token_url(client_id: str) -> str:
    return f"{auth_base_url(client_id)}/connect/token"


def _error_code(payload: Any) -> str | None:
    if isinstance(payload, dict):
        code = payload.get("error")
        if isinstance(code, str) and code.strip():
            return code.strip().lower()
        # Data API failures use an `errors` array instead of top-level fields.
        errors = payload.get("errors")
        if isinstance(errors, list):
            for entry in errors:
                if isinstance(entry, dict):
                    for key in ("error", "code", "type"):
                        value = entry.get(key)
                        if isinstance(value, str) and value.strip():
                            return value.strip().lower()
    return None


def _flatten_detail(value: Any, prefix: str = "") -> list[str]:
    """Flatten one level of `error_details` into `key=value` bits."""
    bits: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            name = f"{prefix}{key}" if isinstance(key, str) and key.strip() else prefix
            if isinstance(item, dict):
                bits.extend(_flatten_detail(item, f"{name}."))
            elif isinstance(item, list):
                joined = ", ".join(str(i).strip() for i in item if str(i).strip())
                if joined:
                    bits.append(f"{name}={joined}" if name else joined)
            elif item is not None and str(item).strip():
                bits.append(f"{name}={str(item).strip()}" if name else str(item).strip())
    elif isinstance(value, list):
        joined = ", ".join(str(i).strip() for i in value if str(i).strip())
        if joined:
            bits.append(joined)
    elif value is not None and str(value).strip():
        bits.append(str(value).strip())
    return bits


def _error_message(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    code = payload.get("error")
    description = payload.get("error_description")
    parts = [part.strip() for part in (code, description) if isinstance(part, str) and part.strip()]
    details = payload.get("error_details")
    if details is not None:
        parts.extend(_flatten_detail(details))
    if parts:
        return ": ".join(parts)[:400]
    # Data API shape: {"errors": [{"error": ..., "message": ...}], "status": "failed"}.
    errors = payload.get("errors")
    if isinstance(errors, list):
        for entry in errors:
            if isinstance(entry, dict):
                bits = [
                    str(entry.get(key)).strip()
                    for key in ("error", "message", "detail")
                    if isinstance(entry.get(key), str) and str(entry.get(key)).strip()
                ]
                if bits:
                    return ": ".join(bits)[:400]
    return None


def _tl_correlation_id(headers: Any) -> str | None:
    """TrueLayer's per-request debug ID, for support tickets."""
    if headers is None:
        return None
    try:
        items = headers.items()
    except AttributeError:
        return None
    lowered = {str(k).lower(): str(v).strip() for k, v in items if str(v).strip()}
    return (
        lowered.get("x-tl-correlation-id")
        or lowered.get("x-request-id")
        or lowered.get("x-credentials-id")
        or None
    )


def _read_json(stream: Any) -> Any:
    try:
        return json.loads(stream.read().decode("utf-8"))
    except (AttributeError, OSError, UnicodeError, ValueError):
        return None


def _psu_ip(context: Any, params: Any) -> str | None:
    """The end-user's real IP for TrueLayer's `X-PSU-IP` header, if configured.

    Precedence: explicit `params["psu_ip"]`, then the runner-supplied
    `context.securo` mapping (`psu_ip`/`x_psu_ip`/`client_ip`), then the
    connection's `psu_ip` config value (set in the dashboard). Anything that
    is not a valid IPv4/IPv6 address is ignored, so a typo can never be sent
    to TrueLayer as if it were you.
    """
    candidates: list[Any] = []
    if isinstance(params, Mapping):
        candidates.append(params.get("psu_ip"))
    securo = getattr(context, "securo", None)
    if isinstance(securo, Mapping):
        for key in ("psu_ip", "x_psu_ip", "client_ip"):
            candidates.append(securo.get(key))
    elif securo is not None:
        for key in ("psu_ip", "x_psu_ip", "client_ip"):
            candidates.append(getattr(securo, key, None))
    config = getattr(context, "config", None)
    if isinstance(config, Mapping):
        candidates.append(config.get("psu_ip"))
    elif config is not None:
        candidates.append(getattr(config, "psu_ip", None))
    for candidate in candidates:
        if candidate is None:
            continue
        text = str(candidate).strip()
        if not text:
            continue
        try:
            return ipaddress.ip_address(text).compressed
        except ValueError:
            continue
    return None


def _request(
    url: str,
    *,
    method: str = "GET",
    form: dict[str, str] | None = None,
    json_body: dict[str, str] | None = None,
    token: str | None = None,
    psu_ip: str | None = None,
) -> dict[str, Any]:
    """One JSON request. Raises UpstreamError with a compact, safe message."""
    headers = {"Accept": "application/json", "User-Agent": "securo-truelayer-plugin/1.0"}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if psu_ip:
        # Example: headers["X-PSU-IP"] = "203.0.113.7"
        # TrueLayer uses the end-user's real IP to attribute user-present
        # requests; only ever send the genuine PSU address.
        headers["X-PSU-IP"] = psu_ip

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        payload = _read_json(exc)
        message = _error_message(payload) or f"HTTP {exc.code}"
        correlation = _tl_correlation_id(getattr(exc, "headers", None))
        if correlation:
            message = f"{message} (tl-correlation-id: {correlation})"
        raise UpstreamError(exc.code, message, _error_code(payload)) from None
    except urllib.error.URLError as exc:
        raise UpstreamError(None, f"network error: {exc.reason}") from None

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise UpstreamError(None, "TrueLayer returned invalid JSON") from None
    if not isinstance(payload, dict):
        raise UpstreamError(None, "TrueLayer returned an unexpected response")
    return payload


def _get_json(
    url: str, token: str | _AccessToken, *, allow_missing: bool = False, psu_ip: str | None = None
) -> dict[str, Any] | None:
    """A data read, with the error mapping the bank connection relies on.

    A 401 gets one forced refresh and retry. If the freshly minted token is
    still rejected, this is a retryable upstream error — not a reason to make
    the person reconnect. Only a 403 (consent gone) needs a new sign-in.
    """
    value = token.value if isinstance(token, _AccessToken) else token
    try:
        return _request(url, token=value, psu_ip=psu_ip)
    except UpstreamError as exc:
        if exc.status == 401 and isinstance(token, _AccessToken) and token.refresh():
            try:
                return _request(url, token=token.value, psu_ip=psu_ip)
            except UpstreamError as retried:
                exc = retried
        if allow_missing and exc.status in (404, 501):
            return None
        if exc.status == 401:
            path = urllib.parse.urlsplit(url).path
            detail = f": {exc.message}" if exc.message and exc.message != "HTTP 401" else ""
            raise UpstreamError(
                401,
                f"TrueLayer rejected the access token on {path}{detail}; Securo will retry next sync",
                exc.code,
            ) from None
        if exc.status == 403:
            raise NeedsAuth("TrueLayer consent has expired; reconnect this bank in Securo.") from None
        if exc.status == 429:
            raise RateLimited("TrueLayer rate-limited this request; Securo will retry later.") from None
        raise


def _next_url(payload: dict[str, Any]) -> str | None:
    """Follow TrueLayer's next-page hint when it is one of our declared hosts."""
    candidates: list[Any] = [payload.get("next"), payload.get("next_url")]
    for container in ("pagination", "links"):
        value = payload.get(container)
        if isinstance(value, dict):
            candidates.extend([value.get("next"), value.get("next_url")])
    for candidate in candidates:
        if not isinstance(candidate, str) or not candidate.startswith("https://"):
            continue
        parts = urllib.parse.urlsplit(candidate)
        if parts.hostname and parts.hostname.lower() in HOSTS:
            return candidate
    return None


def _fetch_collection(
    url: str | None, token: str | _AccessToken, psu_ip: str | None = None
) -> list[dict[str, Any]] | None:
    """Every result across TrueLayer's pages, or None when the feed is unsupported."""
    results: list[dict[str, Any]] = []
    pages = 0
    while url and pages < MAX_PAGES:
        payload = _get_json(url, token, allow_missing=True, psu_ip=psu_ip)
        if payload is None:
            return None if not results else results
        results.extend(item for item in (payload.get("results") or []) if isinstance(item, dict))
        url = _next_url(payload)
        pages += 1
    if pages >= MAX_PAGES and url:
        raise UpstreamError(None, "TrueLayer returned too many pages of transactions")
    return results


def _fetch_balance(
    url: str, token: str | _AccessToken, psu_ip: str | None = None
) -> dict[str, Any] | None:
    payload = _get_json(url, token, allow_missing=True, psu_ip=psu_ip)
    if not payload:
        return None
    results = payload.get("results") or []
    first = results[0] if results else None
    return first if isinstance(first, dict) else None


# ---------------------------------------------------------------------------
# Connection form values
# ---------------------------------------------------------------------------


def _client_id(context: Any) -> str:
    return str(context.config.get("client_id") or context.secrets.get("client_id") or "").strip()


def _client_secret(context: Any) -> str:
    return str(context.secrets.get("client_secret") or context.config.get("client_secret") or "").strip()


def _providers(context: Any) -> str:
    return str(context.config.get("providers") or "").strip() or DEFAULT_PROVIDERS


def _history_days(context: Any) -> int:
    raw = context.config.get("history_days")
    try:
        days = int(raw) if raw not in (None, "") else DEFAULT_HISTORY_DAYS
    except (TypeError, ValueError):
        days = DEFAULT_HISTORY_DAYS
    return max(MIN_HISTORY_DAYS, min(days, MAX_HISTORY_DAYS))


def _card_kind(context: Any) -> str:
    value = str(context.config.get("card_kind") or "credit_card").strip().lower()
    return value if value in CARD_KINDS else "credit_card"


def _balance_field(context: Any) -> str:
    """Which TrueLayer balance figure to report for spendable accounts."""
    value = str(context.config.get("balance_field") or "").strip().lower()
    return value if value in BALANCE_FIELDS else DEFAULT_BALANCE_FIELD


# ---------------------------------------------------------------------------
# OAuth
# ---------------------------------------------------------------------------


def build_auth_url(client_id: str, redirect_uri: str, state: str, providers: str = DEFAULT_PROVIDERS) -> str:
    """TrueLayer's hosted consent screen, with Securo's callback and state."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "scope": DEFAULT_SCOPES,
        "redirect_uri": redirect_uri,
        "providers": providers,
        "prompt": "consent",
        "state": state,
    }
    return f"{auth_base_url(client_id)}/?{urllib.parse.urlencode(params)}"


def build_reauth_url(client_id: str, refresh_token: str, redirect_uri: str, state: str) -> str:
    """TrueLayer's lightweight re-consent link for an existing connection.

    Kept as a fallback for when a real consent expiry needs a person: it reuses
    the existing TrueLayer connection instead of creating a new one. Nothing
    calls it on the normal sync path.
    """
    data = _request(
        f"{auth_base_url(client_id)}/v1/reauthuri",
        method="POST",
        json_body={
            "response_type": "code",
            "refresh_token": refresh_token,
            "redirect_uri": redirect_uri,
            "state": state,
        },
    )
    url = data.get("result")
    if not isinstance(url, str) or urllib.parse.urlsplit(url).scheme != "https":
        raise UpstreamError(None, "TrueLayer returned no re-auth URL")
    return url


def _post_token(client_id: str, form: dict[str, str]) -> dict[str, Any]:
    try:
        return _request(token_url(client_id), method="POST", form=form)
    except UpstreamError as exc:
        if exc.code == "invalid_grant" or exc.status in (401, 400) and exc.code == "invalid_client":
            # Keep TrueLayer's own reason: it is the difference between a wrong
            # client secret, an expired code and a redirect-URI mismatch.
            status = f"HTTP {exc.status} " if exc.status else ""
            detail = f" TrueLayer said: {status}{exc.message}" if exc.message else ""
            raise NeedsAuth(
                f"TrueLayer needs a fresh sign-in; reconnect this bank in Securo.{detail}"
            ) from None
        raise UpstreamError(exc.status, f"TrueLayer token request failed: {exc.message}", exc.code) from None


def _refresh_token(client_id: str, client_secret: str, refresh: str) -> tuple[str, dict[str, str]]:
    """Exchange a refresh token for a new access token and the secrets to keep."""
    data = _post_token(
        client_id,
        {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh,
        },
    )
    new_access = data.get("access_token")
    if not isinstance(new_access, str) or not new_access:
        raise UpstreamError(None, "TrueLayer returned no access token when refreshing")
    expires_in = data.get("expires_in", 3600)
    try:
        seconds = int(expires_in)
    except (TypeError, ValueError):
        seconds = 3600
    expires_at = (dt.datetime.now(dt.UTC) + dt.timedelta(seconds=seconds)).isoformat()
    patch = {
        "access_token": new_access,
        # TrueLayer may omit this on refresh; the old token is still valid then.
        "refresh_token": str(data.get("refresh_token") or refresh),
        "expires_at": expires_at,
    }
    return new_access, patch


def _expiry(value: Any) -> dt.datetime | None:
    if not value:
        return None
    try:
        moment = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=dt.timezone.utc)


def _needs_refresh(expires_at: Any, now: dt.datetime | None = None) -> bool:
    expiry = _expiry(expires_at)
    if expiry is None:
        return True
    return (now or dt.datetime.now(dt.UTC)) + dt.timedelta(seconds=TOKEN_BUFFER_SECONDS) >= expiry


def _access_token(context: Any) -> tuple[str, dict[str, str]]:
    """The stored access token while it is usable, otherwise a refreshed one.

    TrueLayer warns that repeated refreshes can leave data calls holding a
    superseded token: only the newest access token is valid. So we refresh
    when the stored token is close to expiry (or TrueLayer rejects it in
    ``_get_json``), not merely because a sync started.
    """
    client_id = _client_id(context)
    if not client_id:
        raise NeedsAuth("Add your TrueLayer client ID in the connection settings.")

    access = str(context.secrets.get("access_token") or "")
    refresh = str(context.secrets.get("refresh_token") or "")
    if not refresh:
        raise NeedsAuth("This TrueLayer connection hasn't finished signing in; reconnect it.")

    if access and not _needs_refresh(context.secrets.get("expires_at")):
        return access, {}

    client_secret = _client_secret(context)
    if not client_secret:
        raise NeedsAuth("Add your TrueLayer client secret in the connection settings.")

    return _refresh_token(client_id, client_secret, refresh)


class _AccessToken:
    """One sync's token, with a single forced refresh if TrueLayer rejects it."""

    def __init__(self, value: str, patch: dict[str, str], context: Any) -> None:
        self.value = value
        self.patch = patch
        self.context = context
        self.refreshed = False

    def refresh(self) -> bool:
        """Refresh once, reusing any rotation already seen in this sync."""
        if self.refreshed:
            return False
        self.refreshed = True
        secrets = dict(self.context.secrets)
        secrets.update(self.patch)
        refresh = str(secrets.get("refresh_token") or "")
        client_secret = _client_secret(self.context)
        if not refresh or not client_secret:
            return False
        value, patch = _refresh_token(_client_id(self.context), client_secret, refresh)
        self.value = value
        self.patch.update(patch)
        return True


# ---------------------------------------------------------------------------
# Mapping TrueLayer records to Securo's contract
# ---------------------------------------------------------------------------


def _clip(value: Any, limit: int) -> str:
    return str(value or "").strip()[:limit]


def _money(value: Any, default: str = "0.00") -> str:
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        number = Decimal(default)
    if not number.is_finite():
        number = Decimal(default)
    return str(number.quantize(CENT, rounding=ROUND_HALF_UP))


def _date(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return dt.date.fromisoformat(value[:10]).isoformat()
    except ValueError:
        return None


def _currency(value: Any) -> str:
    code = str(value or "").strip().upper()
    return code if len(code) == 3 and code.isalpha() else "GBP"


def _as_pending(transaction: dict[str, Any]) -> dict[str, Any]:
    """TrueLayer's pending feed has no status field, but Securo needs one."""
    return {**transaction, "status": "pending"}


def _pending_currency(account_currency: Any) -> str:
    """A currency code Securo cannot convert to the account's currency."""
    return PENDING_FALLBACK_CURRENCY if _currency(account_currency) == PENDING_CURRENCY else PENDING_CURRENCY


def _account_type(record: dict[str, Any]) -> str:
    raw = str(record.get("account_type") or "").lower()
    if "credit" in raw:
        return "credit_card"
    if "savings" in raw or "saver" in raw:
        return "savings"
    if "invest" in raw:
        return "investment"
    if "loan" in raw:
        return "loan"
    return "checking"


def _masked_number(record: dict[str, Any]) -> str | None:
    raw = "".join(char for char in str(record.get("partial_card_number") or "") if char.isalnum())
    return raw[-4:] if len(raw) >= 4 else None


def _stable_external_id(transaction: dict[str, Any], account_external_id: str) -> str | None:
    # TrueLayer's transaction_id can change when a bank amends a transaction.
    # normalised_provider_transaction_id is documented as stable, so prefer it.
    stable = _clip(transaction.get("normalised_provider_transaction_id"), 200)
    if not stable:
        stable = _clip(transaction.get("transaction_id"), 200)
    return f"{account_external_id}:{stable}" if stable else None


def map_transactions(
    transactions: list[dict[str, Any]] | None,
    account_external_id: str,
    *,
    is_card: bool = False,
    account_currency: Any = None,
) -> list[dict[str, Any]]:
    """Map a TrueLayer feed, deduplicating on the stable external id."""
    mapped: dict[str, dict[str, Any]] = {}
    for transaction in transactions or []:
        external_id = _stable_external_id(transaction, account_external_id)
        date = _date(transaction.get("timestamp"))
        if not external_id or not date:
            continue
        try:
            signed = Decimal(str(transaction.get("amount", 0)))
        except (InvalidOperation, ValueError, TypeError):
            continue
        if not signed.is_finite():
            continue

        explicit = str(transaction.get("transaction_type") or "").strip().lower()
        if is_card and signed != 0:
            # TrueLayer card amounts are positive for purchases (money out)
            # and negative for refunds (money back), the reverse of accounts.
            # transaction_type is not always present on pending rows.
            kind = "debit" if signed > 0 else "credit"
        elif explicit in ("debit", "credit"):
            kind = explicit
        elif is_card:
            kind = "debit"
        else:
            kind = "debit" if signed < 0 else "credit"

        description = _clip(
            transaction.get("description") or transaction.get("merchant_name") or "TrueLayer transaction",
            500,
        )
        payee = _clip(transaction.get("merchant_name") or transaction.get("description"), 200) or None
        classification = transaction.get("transaction_classification") or []
        categories = ", ".join(str(item) for item in classification[:3] if item) if isinstance(classification, list) else ""

        status = "pending" if str(transaction.get("status") or "").lower() == "pending" else "posted"
        record: dict[str, Any] = {
            "external_id": external_id[:255],
            "description": description,
            "amount": str(abs(signed).quantize(CENT, rounding=ROUND_HALF_UP)),
            "type": kind,
            "date": date,
            "status": status,
            "currency": (
                _pending_currency(account_currency)
                if status == "pending"
                else _currency(transaction.get("currency"))
            ),
            "provider_category": _clip(categories, 100) or None,
            "payee": payee,
            "raw_data": {
                key: transaction[key]
                for key in (
                    "transaction_id",
                    "provider_transaction_id",
                    "normalised_provider_transaction_id",
                    "transaction_type",
                    "merchant_name",
                    "status",
                    "transaction_classification",
                )
                if key in transaction
            },
        }
        previous = mapped.get(record["external_id"])
        if previous is None or (previous["status"] == "pending" and record["status"] == "posted"):
            mapped[record["external_id"]] = record
    return list(mapped.values())


def _running_balance(transactions: list[dict[str, Any]] | None) -> dict[str, Any] | None:
    """Last running balance TrueLayer supplied, used if /balance is unavailable."""
    found = None
    for transaction in transactions or []:
        running = transaction.get("running_balance")
        if isinstance(running, dict) and running.get("amount") is not None:
            found = running
    return found


def _signed_total(
    transactions: list[dict[str, Any]] | None,
    today: dt.date,
    *,
    statuses: frozenset[str] = frozenset({"posted"}),
) -> Decimal:
    """Signed sum of rows with the given statuses, dated today or earlier."""
    total = Decimal(0)
    cutoff = today.isoformat()
    for transaction in transactions or []:
        if transaction.get("status") not in statuses:
            continue
        date = transaction.get("date")
        if not date or date > cutoff:
            continue
        amount = Decimal(str(transaction["amount"]))
        total += amount if transaction["type"] == "credit" else -amount
    return total


def _resolve_since(since: Any, history_days: int, today: dt.date) -> str:
    """Securo's overlap (14 days) and our own lookback; take the wider window."""
    floor = (today - dt.timedelta(days=history_days)).isoformat()
    if not since:
        return floor
    try:
        given = dt.date.fromisoformat(str(since)[:10])
    except ValueError:
        return floor
    return min(given, dt.date.fromisoformat(floor)).isoformat()


def _map_account(
    record: dict[str, Any],
    external_id: str,
    *,
    is_card: bool,
    current_balance: str,
    currency_hint: Any,
    account_type: str,
) -> dict[str, Any]:
    provider = record.get("provider")
    institution = provider.get("display_name") if isinstance(provider, dict) else None
    fallback_name = "TrueLayer card" if is_card else "TrueLayer account"
    account: dict[str, Any] = {
        "external_id": external_id,
        "name": _clip(record.get("display_name") or fallback_name, 255),
        "type": account_type,
        "balance": current_balance,
        "currency": _currency(record.get("currency") or currency_hint),
        "institution_name": _clip(institution, 255) or None,
    }
    if is_card:
        masked = _masked_number(record)
        if masked:
            account["masked_number"] = masked
    return account


# ---------------------------------------------------------------------------
# The plugin Securo calls
# ---------------------------------------------------------------------------


class Plugin:
    @_logged("oauth_url")
    def oauth_url(self, params: dict[str, Any], context: Any) -> dict[str, str]:
        """Build a TrueLayer link for a new or previously connected bank.

        A connection that already has a refresh token uses TrueLayer's
        lightweight ``/v1/reauthuri`` link, as truelayer2actual does, so a
        manual reconnect reuses the same TrueLayer connection. If TrueLayer
        says the grace window has lapsed, fall back to the full consent screen.
        Normal syncs never call this — the reauth link is only a fallback for a
        genuine consent expiry.
        """
        client_id = _client_id(context)
        if not client_id:
            raise NeedsAuth("Add your TrueLayer client ID in the connection settings.")
        redirect_uri = str(params.get("redirect_uri") or "")
        state = str(params.get("state") or "")
        if not redirect_uri or not state:
            raise ValueError("Securo did not provide a redirect URI and state")

        refresh = str(context.secrets.get("refresh_token") or "")
        if refresh:
            try:
                return {"url": build_reauth_url(client_id, refresh, redirect_uri, state)}
            except UpstreamError as exc:
                # Reauth is only available while the old connection is still in
                # TrueLayer's grace window. Outside it (or if the endpoint is
                # unavailable), a full authorization is the only way back.
                if exc.status not in (400, 401, 404):
                    raise
        return {"url": build_auth_url(client_id, redirect_uri, state, _providers(context))}

    @_logged("oauth_exchange")
    def oauth_exchange(self, params: dict[str, Any], context: Any) -> dict[str, Any]:
        """Trade the callback code for tokens Securo keeps sealed."""
        client_id, client_secret = _client_id(context), _client_secret(context)
        if not client_id or not client_secret:
            raise NeedsAuth("Add your TrueLayer client ID and secret in the connection settings.")
        code = str(params.get("code") or "")
        redirect_uri = str(params.get("redirect_uri") or "")
        if not code or not redirect_uri:
            raise ValueError("Securo did not provide an authorization code and redirect URI")

        data = _post_token(
            client_id,
            {
                "grant_type": "authorization_code",
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "code": code,
            },
        )
        access = data.get("access_token")
        if not isinstance(access, str) or not access:
            raise UpstreamError(None, "TrueLayer returned no access token")
        refresh = str(data.get("refresh_token") or context.secrets.get("refresh_token") or "")
        if not refresh:
            raise NeedsAuth("TrueLayer returned no refresh token; reconnect this bank.")
        expires_in = data.get("expires_in", 3600)
        try:
            seconds = int(expires_in)
        except (TypeError, ValueError):
            seconds = 3600
        expires_at = (dt.datetime.now(dt.UTC) + dt.timedelta(seconds=seconds)).isoformat()
        return {
            "secrets": {
                "access_token": access,
                "refresh_token": refresh,
                "expires_at": expires_at,
                "last_auth_at": dt.datetime.now(dt.UTC).isoformat(),
            }
        }

    @_logged("sync")
    def sync(self, params: dict[str, Any], context: Any) -> dict[str, Any]:
        """Fetch accounts, cards and their transactions for one connection."""
        client_id = _client_id(context)
        if not client_id:
            raise NeedsAuth("Add your TrueLayer client ID in the connection settings.")

        access, token_patch = _access_token(context)
        token = _AccessToken(access, token_patch, context)
        api = api_base_url(client_id)
        # The end-user's real IP, forwarded as X-PSU-IP on data calls. Prefer a
        # genuine address supplied in the config/context; otherwise pick one
        # from the bundled GB ISP ranges. This stays off the network entirely.
        psu_ip = _psu_ip(context, params) or random_gb_isp_ip()
        state = dict(params.get("state") or {})
        balances: dict[str, str] = {
            str(key): str(value) for key, value in (state.get("balances") or {}).items()
        }
        today = dt.date.today()
        since = _resolve_since(params.get("since"), _history_days(context), today)
        card_kind = _card_kind(context)

        # Account and card feeds are separate at TrueLayer. Fetch once per
        # account, reusing the result for all of Securo's downstream matching.
        sources: list[tuple[dict[str, Any], bool, str]] = []
        for record in _fetch_collection(f"{api}/data/v1/accounts", token, psu_ip) or []:
            sources.append((record, False, f"account:{record.get('account_id')}"))
        for record in _fetch_collection(f"{api}/data/v1/cards", token, psu_ip) or []:
            sources.append((record, True, f"card:{record.get('account_id')}"))

        accounts: list[dict[str, Any]] = []
        seen: set[str] = set()
        for record, is_card, external_id in sources:
            account_id = _clip(record.get("account_id"), 255)
            if not account_id or external_id in seen:
                continue
            seen.add(external_id)

            quoted = urllib.parse.quote(account_id, safe="")
            kind = "cards" if is_card else "accounts"
            account_type = card_kind if is_card else _account_type(record)
            raw_transactions = _fetch_collection(
                f"{api}/data/v1/{kind}/{quoted}/transactions?from={since}&to={today.isoformat()}",
                token,
                psu_ip,
            )
            balance = _fetch_balance(f"{api}/data/v1/{kind}/{quoted}/balance", token, psu_ip)
            provider_current = balance.get("current") if balance else None
            available = balance.get("available") if balance else None
            # `available` is the spendable figure the bank app shows after
            # pending holds. For a liability it is the credit still left rather
            # than the debt owed, so `current` stays authoritative there.
            use_available = (
                _balance_field(context) == "available"
                and account_type not in LIABILITY_ACCOUNT_TYPES
                and available is not None
            )
            current = available if use_available else provider_current
            if current is None:
                running = _running_balance(raw_transactions)
                current = running.get("amount") if running else None
                source_field = "running" if current is not None else "state"
            else:
                source_field = "available" if use_available else "current"
            currency_hint = _currency(record.get("currency") or (balance or {}).get("currency"))

            # TrueLayer's dated endpoint is settled-only for most providers;
            # holds live on the separate /transactions/pending endpoint (which
            # returns all current holds, not a date range). Fetch both so
            # Securo shows pending + posted rows. 404/501 means the provider
            # has no pending feed; keep the settled rows. Any pending row stays
            # visible but is made balance-neutral by map_transactions.
            pending = _fetch_collection(
                f"{api}/data/v1/{kind}/{quoted}/transactions/pending", token, psu_ip
            )
            transactions = None
            if raw_transactions is not None:
                feed = list(raw_transactions)
                if pending:
                    pending_ids = {
                        _stable_external_id(item, external_id) for item in pending
                    }
                    pending_ids.discard(None)
                    feed = [
                        _as_pending(item)
                        if _stable_external_id(item, external_id) in pending_ids
                        else item
                        for item in feed
                    ]
                    feed.extend(_as_pending(item) for item in pending)
                transactions = map_transactions(
                    feed,
                    external_id,
                    is_card=is_card,
                    account_currency=currency_hint,
                )

            pending_total = _signed_total(
                transactions, today, statuses=frozenset({"pending"})
            )
            posted_total = _signed_total(transactions, today)
            is_liability = account_type in LIABILITY_ACCOUNT_TYPES
            balance_source = "state"
            if current is not None:
                try:
                    base = Decimal(str(current))
                except (InvalidOperation, ValueError, TypeError):
                    base = None
                if base is not None:
                    # The selected provider figure is what the bank shows the
                    # person. Pending rows are balance-neutral in Securo, so no
                    # adjustment: this number is the right target as-is.
                    balances[external_id] = _money(base)
                    balance_source = "provider"
            elif transactions is not None:
                # No `/balance` and no running balance. Derive from posted rows
                # only. Liabilities are stored as positive debt, hence the
                # negated total.
                balances[external_id] = _money(-posted_total if is_liability else posted_total)
                balance_source = "transactions"
            current_balance = balances.get(external_id, "0.00")
            print(
                f"truelayer_plugin.sync balance external_id={external_id} type={account_type} "
                f"source={balance_source} field={source_field} "
                f"current={provider_current} available={available} "
                f"pending_total={pending_total} "
                f"posted_total={posted_total} reported={current_balance}",
                file=sys.stderr,
                flush=True,
            )

            account = _map_account(
                record,
                external_id,
                is_card=is_card,
                current_balance=current_balance,
                currency_hint=(balance or {}).get("currency"),
                account_type=account_type,
            )
            # None means the feed could not be fetched; an empty list means it
            # was fetched and is empty. Securo treats those differently.
            if transactions is not None:
                account["transactions"] = transactions
            accounts.append(account)

        # Connection metadata is best effort: a /me failure never costs us a
        # successful account fetch (and never loses a rotated refresh token).
        me_payload: dict[str, Any] | None = None
        with suppress(NeedsAuth, RateLimited, UpstreamError, ValueError, TypeError, KeyError):
            me_payload = _fetch_balance(f"{api}/data/v1/me", token, psu_ip)
        if me_payload:
            if me_payload.get("consent_status") is not None:
                state["consent_status"] = str(me_payload.get("consent_status"))
            if me_payload.get("consent_expires_at") is not None:
                state["consent_expires_at"] = str(me_payload.get("consent_expires_at"))

        state["balances"] = balances
        state["last_sync"] = today.isoformat()
        result: dict[str, Any] = {"state": state}
        if token.patch:
            result["secrets"] = token.patch
        # An empty TrueLayer response is treated as "nothing fetched", so a
        # transient outage cannot look like the person closed every account.
        result["data"] = {"contract": 1, "accounts": accounts} if accounts else None
        return result


plugin = Plugin()

# Kept for tests and type checkers that import the module directly.
__all__ = [
    "NeedsAuth",
    "Plugin",
    "RateLimited",
    "_resolve_since",
    "build_auth_url",
    "map_transactions",
    "plugin",
]
