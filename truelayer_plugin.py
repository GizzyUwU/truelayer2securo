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

import datetime as dt
import functools
import json
import sys
import traceback
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
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
        if isinstance(code, str):
            return code.strip().lower()
    return None


def _error_message(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    code = payload.get("error")
    description = payload.get("error_description")
    parts = [part.strip() for part in (code, description) if isinstance(part, str) and part.strip()]
    return ": ".join(parts)[:300] if parts else None


def _read_json(stream: Any) -> Any:
    try:
        return json.loads(stream.read().decode("utf-8"))
    except Exception:
        return None


def _request(
    url: str,
    *,
    method: str = "GET",
    form: dict[str, str] | None = None,
    token: str | None = None,
) -> dict[str, Any]:
    """One JSON request. Raises UpstreamError with a compact, safe message."""
    headers = {"Accept": "application/json", "User-Agent": "securo-truelayer-plugin/1.0"}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        payload = _read_json(exc)
        raise UpstreamError(exc.code, _error_message(payload) or f"HTTP {exc.code}", _error_code(payload)) from None
    except urllib.error.URLError as exc:
        raise UpstreamError(None, f"network error: {exc.reason}") from None

    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        raise UpstreamError(None, "TrueLayer returned invalid JSON") from None
    if not isinstance(payload, dict):
        raise UpstreamError(None, "TrueLayer returned an unexpected response")
    return payload


def _get_json(
    url: str, token: str | _AccessToken, *, allow_missing: bool = False
) -> dict[str, Any] | None:
    """A data read, with the error mapping the bank connection relies on.

    A 401 is worth one forced refresh: the stored expiry can be wrong, or
    TrueLayer can retire an access token early. Only a 401 that survives the
    retry means the person has to sign in again.
    """
    value = token.value if isinstance(token, _AccessToken) else token
    try:
        return _request(url, token=value)
    except UpstreamError as exc:
        if exc.status == 401 and isinstance(token, _AccessToken) and token.refresh():
            try:
                return _request(url, token=token.value)
            except UpstreamError as retried:
                exc = retried
        if allow_missing and exc.status in (404, 501):
            return None
        if exc.status in (401, 403):
            detail = "TrueLayer rejected the access token" if exc.status == 401 else "TrueLayer consent has expired"
            raise NeedsAuth(f"{detail}; reconnect this bank in Securo.") from None
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


def _fetch_collection(url: str, token: str | _AccessToken) -> list[dict[str, Any]] | None:
    """Every result across TrueLayer's pages, or None when the feed is unsupported."""
    results: list[dict[str, Any]] = []
    pages = 0
    while url and pages < MAX_PAGES:
        payload = _get_json(url, token, allow_missing=True)
        if payload is None:
            return None if not results else results
        results.extend(item for item in (payload.get("results") or []) if isinstance(item, dict))
        url = _next_url(payload)
        pages += 1
    if pages >= MAX_PAGES and url:
        raise UpstreamError(None, "TrueLayer returned too many pages of transactions")
    return results


def _fetch_balance(url: str, token: str | _AccessToken) -> dict[str, Any] | None:
    payload = _get_json(url, token, allow_missing=True)
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
    return (now or dt.datetime.now(dt.timezone.utc)) + dt.timedelta(seconds=TOKEN_BUFFER_SECONDS) >= expiry


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
    expires_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds)).isoformat()
    patch = {
        "access_token": new_access,
        # TrueLayer may omit this on refresh; the old token is still valid then.
        "refresh_token": str(data.get("refresh_token") or refresh),
        "expires_at": expires_at,
    }
    return new_access, patch


def _access_token(context: Any) -> tuple[str, dict[str, str]]:
    """A usable access token and any rotated secrets Securo must store."""
    client_id = _client_id(context)
    if not client_id:
        raise NeedsAuth("Add your TrueLayer client ID in the connection settings.")

    access = str(context.secrets.get("access_token") or "")
    refresh = str(context.secrets.get("refresh_token") or "")
    if not access or not refresh:
        raise NeedsAuth("This TrueLayer connection hasn't finished signing in; reconnect it.")

    if not _needs_refresh(context.secrets.get("expires_at")):
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
    total = Decimal("0")
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
        """Build the TrueLayer consent link for a new connection."""
        client_id = _client_id(context)
        if not client_id:
            raise NeedsAuth("Add your TrueLayer client ID in the connection settings.")
        redirect_uri = str(params.get("redirect_uri") or "")
        state = str(params.get("state") or "")
        if not redirect_uri or not state:
            raise ValueError("Securo did not provide a redirect URI and state")
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
        expires_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds)).isoformat()
        return {
            "secrets": {
                "access_token": access,
                "refresh_token": refresh,
                "expires_at": expires_at,
                "last_auth_at": dt.datetime.now(dt.timezone.utc).isoformat(),
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
        for record in _fetch_collection(f"{api}/data/v1/accounts", token) or []:
            sources.append((record, False, f"account:{record.get('account_id')}"))
        for record in _fetch_collection(f"{api}/data/v1/cards", token) or []:
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
            )
            balance = _fetch_balance(f"{api}/data/v1/{kind}/{quoted}/balance", token)
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
                f"{api}/data/v1/{kind}/{quoted}/transactions/pending", token
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
        try:
            me_payload = _fetch_balance(f"{api}/data/v1/me", token)
            if me_payload:
                if me_payload.get("consent_status") is not None:
                    state["consent_status"] = str(me_payload.get("consent_status"))
                if me_payload.get("consent_expires_at") is not None:
                    state["consent_expires_at"] = str(me_payload.get("consent_expires_at"))
        except Exception:
            pass

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
    "RateLimited",
    "Plugin",
    "plugin",
    "build_auth_url",
    "map_transactions",
    "_resolve_since",
]
