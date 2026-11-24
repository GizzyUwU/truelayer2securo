# truelayer2securo

A [Securo](https://docs.usesecuro.com/) bank provider plugin that brings
[TrueLayer](https://truelayer.com) accounts, cards and transactions into
Securo's normal bank sync pipeline. It is a port of the TrueLayer side of
[truelayer2actual](https://github.com/jasmucrai/truelayer2actual) — same
OAuth flow, token handling, stable transaction IDs and re-read behaviour, but
Securo replaces Actual Budget as the destination.

No Node.js, Docker image, dashboard or state files are needed: the code runs
in Securo's plugin runner and Securo stores the sealed tokens, state and
synced records.

## What it does

| truelayer2actual | This plugin |
| --- | --- |
| TrueLayer hosted OAuth with client ID/secret | Securo's **Connect Bank → TrueLayer** sign-in; register Securo's callback URL in the TrueLayer console |
| Refresh-token rotation with 60-second buffer | A fresh token is minted at the start of every sync; rotated tokens are returned to Securo |
| Sandbox detected from `sandbox-` client ID prefix | Same |
| Accounts **and** cards | Both, as separate TrueLayer feeds; cards default to Securo `credit_card` accounts |
| Stable `normalised_provider_transaction_id` for dedupe | Same, prefixed with the account ID to avoid cross-account collisions |
| 7-day lookback so pending transactions settle | Securo's 14-day overlap is used; first sync defaults to 7 days |
| Re-read pending transactions | Dated + `/transactions/pending` feeds merged; `pending` rows stay visible but are balance-neutral |
| Payee from `merchant_name`, notes from `description` | Payee from `merchant_name`, description from `description`; classification becomes Securo's provider category |
| Per-bank isolation; one dead bank doesn't stop the rest | One Securo plugin connection per bank, each with its own status and schedule |
| Consent expiry / reauth prompts | 403 becomes `NeedsAuth`; a 401 is retried with a fresh token instead of forcing a reconnect |
| Re-consent link (`/v1/reauthuri`) | Used only when you press **Sign in again**, with full-auth fallback; never used by normal sync |
| 429 backoff | `RateLimited`, so Securo keeps the connection healthy and retries later |
| Hourly sync interval | `sync_minutes: 60` in the manifest; `BANK_SYNC_MIN_INTERVAL_HOURS` applies only to native bank providers, not plugins |

Not applicable in Securo: Actual budget pairing and multi-budget fan-out (use
Securo workspaces/accounts), the built-in Express dashboard (Securo's Accounts
page covers it), balance-drift logging (Securo writes the fetched balance),
and ntfy/Home Assistant notifications (Securo's connection status shows the
same expiry/reconnect state).

## Requirements

- Securo **0.21.0+** with code plugins enabled and the plugin runner running.
- A TrueLayer application with a registered redirect URI.

## Install on your Securo instance

```bash
PLUGINS_ENABLED=true
PLUGINS_RUNNER_URL=http://plugins-runner:8090
PLUGINS_RUNNER_TOKEN=...      # shared by the backend and the runner
PLUGINS_EGRESS_SECRET=...     # shared by the runner and the egress proxy
COMPOSE_PROFILES=plugins      # docker compose --profile plugins up -d
```

The generated `.env` in this repository is production-shaped: fresh secrets,
registration disabled, loopback-bound ports, external-proxy trust and the
public catalog. Replace `REPLACE_ME` in `FRONTEND_URL` before starting, create
`/srv/securo/backups`, and load the file explicitly if it is not next to your
compose file:

```bash
docker compose -f docker-compose.prod.yml --env-file /path/to/truelayer2securo/.env --profile plugins up -d
```

Your compose file hardcodes the Postgres credentials (`postgres/postgres`) and
the frontend container's own `FRONTEND_URL`; change those in the compose file
too before exposing the instance publicly. The Helm chart does not ship the
plugin runner yet.

## Register the redirect URI

In the [TrueLayer console](https://console.truelayer.com), add this exact URL
to your application's redirect URIs:

```
https://<your-securo-host>/plugins/oauth/callback
```

Securo generates it from `FRONTEND_URL`. It must match exactly (scheme, host,
port and path). Sandbox apps use the same callback URL; use a client ID that
starts with `sandbox-` to switch all API calls to the sandbox hosts.

## Add the connection

1. Install **TrueLayer** from Securo's plugin catalog (owner/manager; code
   plugins require approval of the declared hosts).
2. **Accounts → Connect Bank → TrueLayer**.
3. Fill in:
   - **TrueLayer client ID** — from the console; `sandbox-…` for sandbox.
   - **TrueLayer client secret** — stored encrypted, never shown again.
   - **Providers** (optional) — space-separated TrueLayer provider filter.
     Defaults to `uk-cs-mock uk-ob-all uk-oauth-all`, the same UK list as
     truelayer2actual.
   - **Days of history on first sync** (optional, default `7`).
    - **Balance to report** (optional) — `available` (default, the spendable
      figure your bank app shows) or `current` (settled only). Credit cards and
      loans always use `current`, where `available` means remaining credit.
   - **Card account type** (optional) — `credit_card` (default), `checking`
     or `savings`. Set `checking` for debit cards whose balance is money you
     own rather than an amount owed.
4. Sign in at the bank. Securo creates the bank connection and lists its
   accounts; the first sync runs immediately, then every 6 hours.
5. **Sync now** works from the connection card. Reconnect after consent
   expires; account IDs are stable, so nothing is imported twice.

## Pending transactions and the opening balance

TrueLayer's dated `/transactions?from=&to=` endpoint returns settled rows for
most providers; holds live on the separate `/transactions/pending` endpoint
(which returns all current holds, not a date range). This plugin fetches both,
so Securo shows pending + posted rows together. A provider that returns no
pending feed (404/501) just yields settled rows. If the same hold appears in
both feeds it is imported once, as `pending`; when it settles, the posted row
replaces it via the stable `normalised_provider_transaction_id`.

Every pending row stays visible in Securo with its original amount and
`status: pending`, but is given an unconvertible currency (`XXX`, or `ZZZ` if
the account itself is `XXX`). Securo sums every imported row when it derives
the synthetic opening balance; a row it cannot convert to the account's
currency contributes zero, the same way Actual leaves uncleared rows out of its
balance.

By default the plugin reports TrueLayer's `available` balance for spendable
accounts — the figure your bank app shows after pending purchases are deducted.
Set **Balance to report** to `current` if you would rather use the settled-only
figure. Credit cards and loans always use `current`: for a liability TrueLayer's
`available` is the credit still left, not the amount owed.

Visible pending rows are balance-neutral, so they don't move Securo's
synthetic opening balance through the transaction sum. The opening row is still
computed by Securo as `reported balance − sum(imported rows)`; it fills the gap
between the imported lookback window and the bank's real balance, and is
overwritten on the next sync. A manual edit never sticks.

Securo 0.21.0 does not support the `complete_feed` manifest flag, so this
manifest deliberately omits it. A cancelled hold therefore stays visible until
removed manually or until TrueLayer stops returning it and a re-sync without it
is followed by manual cleanup; future Securo versions that support
`complete_feed` can enable automatic cancelled-hold expiry, but the field must
not be present for a 0.21.0 install.

## Troubleshooting OAuth 502

Securo turns any exception from the plugin into `502 {"detail":"The plugin failed: ..."}`.
A proxy in front of Securo may replace that JSON with its own 502 page, so the
browser is not a reliable place to read the cause.

Version **1.1.2+** prints every plugin failure to stderr with tokens, client
secrets, OAuth codes and state values redacted. The plugin runner captures that
stderr:

```bash
docker compose logs plugins-runner | grep truelayer_plugin
```

A failed token exchange now appears in the runner log with the real TrueLayer reason, for example:

```text
truelayer_plugin.oauth_exchange failed: NeedsAuth: TrueLayer needs a fresh sign-in; reconnect this bank in Securo. TrueLayer said: HTTP 400 invalid_client: Client authentication failed context={"client_id":"app-123","redirect_uri":"https://securo.example/plugins/oauth/callback"}
```

`invalid_client` means the client ID/secret or live/sandbox environment is
wrong. `invalid_grant` means the code expired/was reused or the redirect URI
does not match. `egress refused: ... is not allowed` in
`docker compose logs plugins-egress` means the installed manifest is stale and
must be updated.

From **1.2.2** every sync starts by minting a fresh access token from the
refresh token, so a stale or unexpectedly revoked stored token cannot fail a
run. If TrueLayer still returns `401` after one extra refresh and retry, the
connection shows a retryable error and Securo tries again on the next schedule
— no manual reconnect. A `403` means the consent itself has gone and does need
a reconnect.

From **1.2.3** that reconnect uses TrueLayer's `/v1/reauthuri` link when the
connection still has a refresh token, preserving the same TrueLayer connection.
If the grace window has lapsed (HTTP 400/401/404), it falls back to the full
consent screen. Normal sync never requests a reauth link.

From **1.2.4** the plugin's manifest schedule is hourly (`sync_minutes: 60`).
Securo's `BANK_SYNC_MIN_INTERVAL_HOURS` env var does not control plugin
connections; they use the manifest interval, with backoff after failures.
Hourly is more often than PSD2's usual four unattended accesses per day, so
only keep it if your bank/provider tolerates it.

Version **1.1.3+** also logs one balance line per account on every sync. From
**1.1.5** it shows both provider figures and which one was used:

```text
truelayer_plugin.sync balance external_id=account:abc type=checking source=provider field=available current=18.14 available=17.10 pending_total=0 posted_total=20.14 reported=17.10
```

`field=available` is the default for spendable accounts; `field=current` means
the settled figure was selected (always the case for liabilities). `source=provider`
means TrueLayer supplied the balance; `source=transactions` means it was derived
from posted rows because neither `/balance` nor a running balance was available.
`pending_total` is informational only: pending rows stay visible but are
balance-neutral, so no hold is deducted a second time.

## Test locally before publishing

The plugin has no third-party dependencies, so a local catalog is enough:

```bash
git clone https://github.com/securo-finance/plugins securo-plugins
python3 securo-plugins/build_index.py local /path/to/truelayer2securo --out site
# Bind to all interfaces: the backend container reaches the catalog through
# host.docker.internal, not 127.0.0.1.
python3 -m http.server 8787 --bind 0.0.0.0 --directory site
```

Point Securo at it (the provided `.env` already does this):

```env
PLUGINS_ENABLED=true
PLUGINS_INDEX_URL=http://host.docker.internal:8787/v1/index.json
COMPOSE_PROFILES=plugins
```

Install the plugin as the workspace owner or a manager, add a connection and
press **Sync now**. Runner logs: `docker compose logs plugins-runner`;
egress decisions: `docker compose logs plugins-egress`. Rebuild the catalog
after every change.

Unit tests (no dependencies, Python 3.11+):

```bash
python3 -m unittest -v
```

To confirm the re-auth link fallback is still present (and still absent from
the normal sync path), run:

```bash
node check_reauth.js
```

It checks the plugin source and exercises the behaviour with a short Python
runtime check. It also checks `../truelayer2actual` when that checkout exists;
set `TRUELAYER2ACTUAL_DIR` to check it elsewhere.

## Publish

Before publishing, change `id` and `repository` in `securo-plugin.json` to
your own GitHub repository (the catalog requires them to match), then:

1. Push to a public repository.
2. Add the `securo-plugin` topic.
3. Publish a release (for example `v1.1.5`).

The catalog picks it up on its next rebuild (about every 6 hours).

## Files

```
truelayer_plugin.py      # OAuth, TrueLayer client, mapping, sync (stdlib only)
securo-plugin.json       # manifest: oauth integration, network, provides
test_truelayer_plugin.py # stdlib unit tests
check_reauth.js          # checks the reauth-link fallback is still present
.env                     # generated local Compose settings; ignored by git
.env.example             # sanitized production template; safe to commit
```

## License

MIT — see [LICENSE](LICENSE). Original TrueLayer logic ported from
[truelayer2actual](https://github.com/jasmucrai/truelayer2actual) by
jasmucrai.
