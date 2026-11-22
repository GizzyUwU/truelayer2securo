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
| Refresh-token rotation with 60-second buffer | Same, with rotated tokens returned to Securo even if a later step fails |
| Sandbox detected from `sandbox-` client ID prefix | Same |
| Accounts **and** cards | Both, as separate TrueLayer feeds; cards default to Securo `credit_card` accounts |
| Stable `normalised_provider_transaction_id` for dedupe | Same, prefixed with the account ID to avoid cross-account collisions |
| 7-day lookback so pending transactions settle | Securo's 14-day overlap is used; first sync defaults to 7 days |
| Payee from `merchant_name`, notes from `description` | Payee from `merchant_name`, description from `description`; classification becomes Securo's provider category |
| Per-bank isolation; one dead bank doesn't stop the rest | One Securo plugin connection per bank, each with its own status and schedule |
| Consent expiry / reauth prompts | 401/403 become `NeedsAuth`, shown as an expired bank connection with a reconnect action |
| 429 backoff | `RateLimited`, so Securo keeps the connection healthy and retries later |
| Six-hour sync interval | `sync_minutes: 360` in the manifest |

Not applicable in Securo: Actual budget pairing and multi-budget fan-out (use
Securo workspaces/accounts), the built-in Express dashboard (Securo's Accounts
page covers it), balance-drift logging (Securo writes the fetched balance),
and ntfy/Home Assistant notifications (Securo's connection status shows the
same expiry/reconnect state).

## Requirements

- Securo **0.20.0+** with code plugins enabled and the plugin runner running.
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
   - **Card account type** (optional) — `credit_card` (default), `checking`
     or `savings`. Set `checking` for debit cards whose balance is money you
     own rather than an amount owed.
4. Sign in at the bank. Securo creates the bank connection and lists its
   accounts; the first sync runs immediately, then every 6 hours.
5. **Sync now** works from the connection card. Reconnect after consent
   expires; account IDs are stable, so nothing is imported twice.

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

## Publish

Before publishing, change `id` and `repository` in `securo-plugin.json` to
your own GitHub repository (the catalog requires them to match), then:

1. Push to a public repository.
2. Add the `securo-plugin` topic.
3. Publish a release (for example `v1.0.0`).

The catalog picks it up on its next rebuild (about every 6 hours).

## Files

```
truelayer_plugin.py      # OAuth, TrueLayer client, mapping, sync (stdlib only)
securo-plugin.json       # manifest: oauth integration, network, provides
test_truelayer_plugin.py # stdlib unit tests
.env                     # generated local Compose settings; ignored by git
.env.example             # sanitized production template; safe to commit
```

## License

MIT — see [LICENSE](LICENSE). Original TrueLayer logic ported from
[truelayer2actual](https://github.com/jasmucrai/truelayer2actual) by
jasmucrai.
