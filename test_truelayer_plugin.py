"""Standard-library tests for the TrueLayer Securo plugin.

Run with: python3 -m unittest -v
"""

from __future__ import annotations

import io
import json
import pathlib
import sys
import unittest
import urllib.parse
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import patch

import truelayer_plugin as plugin_module
from truelayer_plugin import NeedsAuth, RateLimited, UpstreamError


def context(*, config=None, secrets=None):
    return SimpleNamespace(config=config or {}, secrets=secrets or {})


def valid_context():
    return context(
        config={"client_id": "app-123"},
        secrets={
            "access_token": "access-1",
            "refresh_token": "refresh-1",
            "expires_at": "2099-01-01T00:00:00+00:00",
        },
    )


class AuthUrlTests(unittest.TestCase):
    def test_build_auth_url_contains_truelayer_params(self):
        url = plugin_module.build_auth_url(
            "app-123", "https://securo.example/plugins/oauth/callback", "state-xyz"
        )
        parts = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qs(parts.query)
        self.assertEqual(parts.scheme, "https")
        self.assertEqual(parts.netloc, "auth.truelayer.com")
        self.assertEqual(query["response_type"], ["code"])
        self.assertEqual(query["client_id"], ["app-123"])
        self.assertEqual(query["state"], ["state-xyz"])
        self.assertEqual(query["redirect_uri"], ["https://securo.example/plugins/oauth/callback"])
        self.assertEqual(query["scope"], [plugin_module.DEFAULT_SCOPES])
        self.assertEqual(query["providers"], [plugin_module.DEFAULT_PROVIDERS])

    def test_sandbox_client_uses_sandbox_hosts(self):
        client_id = "sandbox-app-123"
        self.assertEqual(
            urllib.parse.urlsplit(plugin_module.build_auth_url(client_id, "https://x/cb", "s")).netloc,
            "auth.truelayer-sandbox.com",
        )
        self.assertEqual(
            plugin_module.api_base_url(client_id), "https://api.truelayer-sandbox.com"
        )

    def test_oauth_url_method(self):
        result = plugin_module.plugin.oauth_url(
            {"redirect_uri": "https://securo.example/plugins/oauth/callback", "state": "s1"},
            context(config={"client_id": "app-123", "providers": "uk-ob-all"}),
        )
        self.assertTrue(result["url"].startswith("https://auth.truelayer.com/"))
        self.assertIn("providers=uk-ob-all", result["url"])


class TokenTests(unittest.TestCase):
    def test_oauth_exchange_keeps_tokens(self):
        payload = {"access_token": "access-2", "refresh_token": "refresh-2", "expires_in": 3600}
        with patch.object(plugin_module, "_request", return_value=payload) as request:
            result = plugin_module.plugin.oauth_exchange(
                {"code": "code-1", "redirect_uri": "https://securo.example/plugins/oauth/callback"},
                context(
                    config={"client_id": "app-123"},
                    secrets={"client_secret": "secret-1"},
                ),
            )
        self.assertEqual(result["secrets"]["access_token"], "access-2")
        self.assertEqual(result["secrets"]["refresh_token"], "refresh-2")
        self.assertIn("expires_at", result["secrets"])
        form = request.call_args.kwargs["form"]
        self.assertEqual(form["grant_type"], "authorization_code")
        self.assertEqual(form["client_secret"], "secret-1")

    def test_oauth_exchange_invalid_grant_needs_auth(self):
        error = UpstreamError(400, "invalid_grant: code expired", "invalid_grant")
        with patch.object(plugin_module, "_request", side_effect=error):
            with self.assertRaises(NeedsAuth) as raised:
                plugin_module.plugin.oauth_exchange(
                    {"code": "old", "redirect_uri": "https://x/cb"},
                    context(config={"client_id": "app-123"}, secrets={"client_secret": "s"}),
                )
        # The actionable TrueLayer detail must survive the NeedsAuth mapping.
        self.assertIn("HTTP 400", str(raised.exception))
        self.assertIn("code expired", str(raised.exception))

    def test_failures_are_logged_without_secrets(self):
        stderr = io.StringIO()
        ctx = context(
            config={"client_id": "app-123"},
            secrets={"client_secret": "super-secret-value"},
        )
        error = UpstreamError(
            400, "invalid_client: super-secret-value was rejected", "invalid_client"
        )
        with patch.object(plugin_module, "_request", side_effect=error), patch.object(sys, "stderr", stderr):
            with self.assertRaises(NeedsAuth):
                plugin_module.plugin.oauth_exchange(
                    {
                        "code": "oauth-code-abcdef",
                        "redirect_uri": "https://securo.example/plugins/oauth/callback",
                    },
                    ctx,
                )
        output = stderr.getvalue()
        self.assertIn("truelayer_plugin.oauth_exchange failed", output)
        self.assertIn("invalid_client", output)
        self.assertIn("app-123", output)
        self.assertNotIn("super-secret-value", output)
        self.assertNotIn("oauth-code-abcdef", output)

    def test_expired_token_is_refreshed_and_returned_as_secrets(self):
        expired = context(
            config={"client_id": "app-123"},
            secrets={
                "client_secret": "secret-1",
                "access_token": "old-access",
                "refresh_token": "old-refresh",
                "expires_at": "2000-01-01T00:00:00+00:00",
            },
        )

        def fake_request(url, **kwargs):
            if "/connect/token" in url:
                return {"access_token": "new-access", "expires_in": 1800}
            return {"results": [], "status": "success"}

        with patch.object(plugin_module, "_request", side_effect=fake_request):
            result = plugin_module.plugin.sync({}, expired)
        self.assertEqual(result["secrets"]["access_token"], "new-access")
        # TrueLayer omitted refresh_token on refresh; the old one is kept.
        self.assertEqual(result["secrets"]["refresh_token"], "old-refresh")
        self.assertIsNone(result["data"])


class MappingTests(unittest.TestCase):
    def test_transactions_use_stable_ids_and_card_semantics(self):
        txns = [
            {
                "transaction_id": "tl-unstable-1",
                "normalised_provider_transaction_id": "bank-stable-1",
                "timestamp": "2026-11-20T12:00:00Z",
                "amount": -12.34,
                "currency": "GBP",
                "transaction_type": "debit",
                "transaction_classification": ["groceries"],
                "merchant_name": "Corner Shop",
                "description": "CORNER SHOP LONDON",
                "status": "booked",
            },
            {
                "transaction_id": "tl-2",
                "timestamp": "2026-11-21T12:00:00Z",
                "amount": 20.0,
                "currency": "GBP",
                "merchant_name": "Refund Ltd",
                "description": "REFUND",
                "status": "pending",
            },
        ]
        mapped = plugin_module.map_transactions(txns, "account:a1")
        self.assertEqual(len(mapped), 2)
        first, second = mapped
        self.assertEqual(first["external_id"], "account:a1:bank-stable-1")
        self.assertEqual(first["amount"], "12.34")
        self.assertEqual(first["type"], "debit")
        self.assertEqual(first["status"], "posted")
        self.assertEqual(first["payee"], "Corner Shop")
        self.assertEqual(first["provider_category"], "groceries")
        self.assertEqual(second["external_id"], "account:a1:tl-2")
        self.assertEqual(second["type"], "credit")
        self.assertEqual(second["status"], "pending")

        card = plugin_module.map_transactions([txns[1]], "card:c1", is_card=True)
        self.assertEqual(card[0]["type"], "debit")

        # TrueLayer card refunds arrive negative; they are credits, not debits.
        refund = plugin_module.map_transactions(
            [{**txns[1], "amount": -2.0, "transaction_type": "DEBIT"}], "card:c1", is_card=True
        )
        self.assertEqual(refund[0]["type"], "credit")
        self.assertEqual(refund[0]["amount"], "2.00")

    def test_duplicate_ids_prefer_posted(self):
        base = {
            "transaction_id": "same",
            "timestamp": "2026-11-20T12:00:00Z",
            "amount": 1.0,
            "description": "Shop",
        }
        mapped = plugin_module.map_transactions(
            [{**base, "status": "pending"}, {**base, "status": "booked"}], "account:a1"
        )
        self.assertEqual(len(mapped), 1)
        self.assertEqual(mapped[0]["status"], "posted")

    def test_since_uses_wider_window(self):
        today = plugin_module.dt.date(2026, 11, 22)
        self.assertEqual(plugin_module._resolve_since(None, 7, today), "2026-11-15")
        self.assertEqual(plugin_module._resolve_since("2026-11-01", 7, today), "2026-11-01")
        self.assertEqual(plugin_module._resolve_since("2026-11-20", 7, today), "2026-11-15")


class SyncTests(unittest.TestCase):
    def test_sync_maps_accounts_cards_balances_and_state(self):
        account = {
            "account_id": "acc-1",
            "display_name": "Current Account",
            "currency": "GBP",
            "account_type": "checking",
            "provider": {"display_name": "Mock Bank"},
        }
        card = {
            "account_id": "card-1",
            "display_name": "Credit Card",
            "currency": "GBP",
            "card_type": "VISA",
            "partial_card_number": "4242",
            "provider": {"display_name": "Mock Bank"},
        }
        account_txn = {
            "transaction_id": "t-1",
            "normalised_provider_transaction_id": "stable-1",
            "timestamp": "2026-11-21T10:00:00Z",
            "amount": -5.5,
            "transaction_type": "debit",
            "merchant_name": "Coffee",
            "description": "COFFEE",
            "status": "booked",
        }
        card_txn = {
            "transaction_id": "t-2",
            "timestamp": "2026-11-21T11:00:00Z",
            "amount": 30.0,
            "merchant_name": "Shop",
            "description": "SHOP",
            "status": "pending",
        }

        def fake_request(url, **kwargs):
            if url.endswith("/data/v1/accounts"):
                return {"results": [account], "status": "success"}
            if url.endswith("/data/v1/cards"):
                return {"results": [card], "status": "success"}
            if "/transactions/pending" in url:
                return {"results": [], "status": "success"}
            if "/accounts/acc-1/transactions" in url:
                self.assertIn("from=2026-11-15", url)
                return {"results": [account_txn], "status": "success"}
            if "/cards/card-1/transactions" in url:
                return {"results": [card_txn], "status": "success"}
            if "/accounts/acc-1/balance" in url:
                return {"results": [{"current": 123.45, "available": 100.0, "currency": "GBP"}]}
            if "/cards/card-1/balance" in url:
                return {"results": [{"current": 50.0, "available": 450.0, "currency": "GBP"}]}
            if url.endswith("/data/v1/me"):
                return {
                    "results": [
                        {
                            "consent_status": "active",
                            "consent_expires_at": "2027-01-01T00:00:00Z",
                            "provider": {"provider_id": "mock", "display_name": "Mock Bank"},
                        }
                    ]
                }
            raise AssertionError(f"unexpected URL: {url}")

        with patch.object(plugin_module, "_request", side_effect=fake_request):
            result = plugin_module.plugin.sync({}, valid_context())

        data = result["data"]
        self.assertEqual(data["contract"], 1)
        self.assertEqual(len(data["accounts"]), 2)
        checking, credit = data["accounts"]
        self.assertEqual(checking["external_id"], "account:acc-1")
        self.assertEqual(checking["type"], "checking")
        self.assertEqual(checking["balance"], "123.45")
        self.assertEqual(checking["institution_name"], "Mock Bank")
        self.assertEqual(checking["transactions"][0]["external_id"], "account:acc-1:stable-1")

        self.assertEqual(credit["external_id"], "card:card-1")
        self.assertEqual(credit["type"], "credit_card")
        # `current` (50) excludes the pending 30 purchase; the reported
        # balance includes it so Securo's opening balance stays unchanged.
        self.assertEqual(credit["balance"], "80.00")
        self.assertEqual(credit["masked_number"], "4242")
        self.assertEqual(credit["transactions"][0]["type"], "debit")
        self.assertEqual(credit["transactions"][0]["status"], "pending")

        self.assertEqual(result["state"]["balances"]["account:acc-1"], "123.45")
        self.assertEqual(result["state"]["consent_status"], "active")
        self.assertNotIn("secrets", result)

    def test_pending_feed_is_imported_without_shifting_opening_balance(self):
        today = plugin_module.dt.date.today().isoformat()
        account = {"account_id": "acc-1", "display_name": "Current", "currency": "GBP"}
        settled = {
            "transaction_id": "t-1",
            "timestamp": f"{today}T10:00:00Z",
            "amount": -5.0,
            "transaction_type": "DEBIT",
            "description": "COFFEE",
        }
        hold = {
            "transaction_id": "hold-1",
            "timestamp": f"{today}T11:00:00Z",
            "amount": 2.0,
            "transaction_type": "CREDIT",
            "description": "REFUND",
        }

        def fake_request(url, **kwargs):
            if url.endswith("/data/v1/accounts"):
                return {"results": [account]}
            if url.endswith("/data/v1/cards"):
                return {"results": []}
            if "/accounts/acc-1/transactions/pending" in url:
                return {"results": [hold]}
            if "/accounts/acc-1/transactions" in url:
                return {"results": [settled]}
            if "/accounts/acc-1/balance" in url:
                return {"results": [{"current": 100.0, "currency": "GBP"}]}
            if url.endswith("/data/v1/me"):
                return {"results": []}
            raise AssertionError(f"unexpected URL: {url}")

        with patch.object(plugin_module, "_request", side_effect=fake_request):
            result = plugin_module.plugin.sync({}, valid_context())

        synced = result["data"]["accounts"][0]
        self.assertEqual(synced["balance"], "102.00")
        transactions = {tx["external_id"]: tx for tx in synced["transactions"]}
        self.assertEqual(len(transactions), 2)
        self.assertEqual(transactions["account:acc-1:hold-1"]["status"], "pending")
        self.assertEqual(transactions["account:acc-1:hold-1"]["type"], "credit")

        signed = sum(
            (Decimal(tx["amount"]) if tx["type"] == "credit" else -Decimal(tx["amount"]))
            for tx in transactions.values()
        )
        # The opening balance Securo derives is unchanged by importing the hold.
        self.assertEqual(Decimal(synced["balance"]) - signed, Decimal("105.00"))

    def test_pending_row_in_dated_feed_is_marked_pending_once(self):
        today = plugin_module.dt.date.today().isoformat()
        account = {"account_id": "acc-1", "display_name": "Current", "currency": "GBP"}
        row = {
            "transaction_id": "same",
            "normalised_provider_transaction_id": "stable-same",
            "timestamp": f"{today}T10:00:00Z",
            "amount": -2.0,
            "transaction_type": "DEBIT",
            "description": "CARD HOLD",
        }

        def fake_request(url, **kwargs):
            if url.endswith("/data/v1/accounts"):
                return {"results": [account]}
            if url.endswith("/data/v1/cards"):
                return {"results": []}
            if "/accounts/acc-1/transactions/pending" in url:
                return {"results": [row]}
            if "/accounts/acc-1/transactions" in url:
                return {"results": [row]}
            if "/accounts/acc-1/balance" in url:
                return {"results": [{"current": 50.0, "currency": "GBP"}]}
            if url.endswith("/data/v1/me"):
                return {"results": []}
            raise AssertionError(f"unexpected URL: {url}")

        with patch.object(plugin_module, "_request", side_effect=fake_request):
            result = plugin_module.plugin.sync({}, valid_context())

        transactions = result["data"]["accounts"][0]["transactions"]
        self.assertEqual(len(transactions), 1)
        self.assertEqual(transactions[0]["status"], "pending")
        # -2 hold is not in `current`, so the reported balance includes it.
        self.assertEqual(result["data"]["accounts"][0]["balance"], "48.00")

    def test_unsupported_pending_feed_keeps_settled_transactions(self):
        today = plugin_module.dt.date.today().isoformat()
        account = {"account_id": "acc-1", "display_name": "Current", "currency": "GBP"}
        settled = {
            "transaction_id": "t-1",
            "timestamp": f"{today}T10:00:00Z",
            "amount": -5.0,
            "transaction_type": "DEBIT",
            "description": "COFFEE",
        }

        def fake_request(url, **kwargs):
            if url.endswith("/data/v1/accounts"):
                return {"results": [account]}
            if url.endswith("/data/v1/cards"):
                return {"results": []}
            if "/transactions/pending" in url:
                raise UpstreamError(501, "not supported", "endpoint_not_supported")
            if "/accounts/acc-1/transactions" in url:
                return {"results": [settled]}
            if "/accounts/acc-1/balance" in url:
                return {"results": [{"current": 100.0, "currency": "GBP"}]}
            if url.endswith("/data/v1/me"):
                return {"results": []}
            raise AssertionError(f"unexpected URL: {url}")

        with patch.object(plugin_module, "_request", side_effect=fake_request):
            result = plugin_module.plugin.sync({}, valid_context())

        synced = result["data"]["accounts"][0]
        self.assertEqual(synced["balance"], "100.00")
        self.assertEqual(len(synced["transactions"]), 1)
        self.assertEqual(synced["transactions"][0]["status"], "posted")

    def test_card_pending_purchases_and_refunds_adjust_debt(self):
        today = plugin_module.dt.date.today().isoformat()
        card = {"account_id": "card-1", "display_name": "Card", "currency": "GBP"}

        def fake_request(url, **kwargs):
            if url.endswith("/data/v1/accounts"):
                return {"results": []}
            if url.endswith("/data/v1/cards"):
                return {"results": [card]}
            if "/cards/card-1/transactions/pending" in url:
                return {
                    "results": [
                        {
                            "transaction_id": "hold-buy",
                            "timestamp": f"{today}T10:00:00Z",
                            "amount": 20.0,
                            "description": "PENDING SHOP",
                        },
                        {
                            "transaction_id": "hold-refund",
                            "timestamp": f"{today}T11:00:00Z",
                            "amount": -5.0,
                            "description": "PENDING REFUND",
                        },
                    ]
                }
            if "/cards/card-1/transactions" in url:
                return {
                    "results": [
                        {
                            "transaction_id": "posted-buy",
                            "timestamp": f"{today}T09:00:00Z",
                            "amount": 30.0,
                            "description": "POSTED SHOP",
                        }
                    ]
                }
            if "/cards/card-1/balance" in url:
                return {"results": [{"current": 50.0, "currency": "GBP"}]}
            if url.endswith("/data/v1/me"):
                return {"results": []}
            raise AssertionError(f"unexpected URL: {url}")

        with patch.object(plugin_module, "_request", side_effect=fake_request):
            result = plugin_module.plugin.sync({}, valid_context())

        synced = result["data"]["accounts"][0]
        self.assertEqual(synced["balance"], "65.00")
        by_id = {tx["external_id"]: tx for tx in synced["transactions"]}
        self.assertEqual(by_id["card:card-1:hold-buy"]["type"], "debit")
        self.assertEqual(by_id["card:card-1:hold-buy"]["status"], "pending")
        self.assertEqual(by_id["card:card-1:hold-refund"]["type"], "credit")
        self.assertEqual(by_id["card:card-1:hold-refund"]["status"], "pending")

        signed = sum(
            (Decimal(tx["amount"]) if tx["type"] == "credit" else -Decimal(tx["amount"]))
            for tx in by_id.values()
        )
        # The remaining -20 is the debt from before this 7-day window;
        # importing the holds does not change it.
        self.assertEqual(-Decimal(synced["balance"]) - signed, Decimal("-20.00"))

    def test_checking_card_pending_purchase_keeps_asset_opening_balance(self):
        today = plugin_module.dt.date.today().isoformat()
        card = {"account_id": "card-1", "display_name": "Debit Card", "currency": "GBP"}
        hold = {
            "transaction_id": "hold-buy",
            "timestamp": f"{today}T10:00:00Z",
            "amount": 20.0,
            "description": "PENDING SHOP",
        }

        def fake_request(url, **kwargs):
            if url.endswith("/data/v1/accounts"):
                return {"results": []}
            if url.endswith("/data/v1/cards"):
                return {"results": [card]}
            if "/cards/card-1/transactions/pending" in url:
                return {"results": [hold]}
            if "/cards/card-1/transactions" in url:
                return {"results": []}
            if "/cards/card-1/balance" in url:
                return {"results": [{"current": 50.0, "currency": "GBP"}]}
            if url.endswith("/data/v1/me"):
                return {"results": []}
            raise AssertionError(f"unexpected URL: {url}")

        ctx = valid_context()
        ctx.config["card_kind"] = "checking"
        with patch.object(plugin_module, "_request", side_effect=fake_request):
            result = plugin_module.plugin.sync({}, ctx)

        synced = result["data"]["accounts"][0]
        self.assertEqual(synced["type"], "checking")
        # A debit card's balance is money owned: a 20 purchase lowers it.
        self.assertEqual(synced["balance"], "30.00")
        self.assertEqual(synced["transactions"][0]["type"], "debit")
        # The opening balance Securo derives stays at the pre-pending 50.
        self.assertEqual(
            Decimal(synced["balance"]) + Decimal(synced["transactions"][0]["amount"]),
            Decimal("50.00"),
        )

    def test_empty_response_does_not_look_like_closed_accounts(self):
        with patch.object(plugin_module, "_request", return_value={"results": []}):
            result = plugin_module.plugin.sync({}, valid_context())
        self.assertIsNone(result["data"])
        self.assertEqual(result["state"]["balances"], {})

    def test_data_errors_are_mapped(self):
        ctx = valid_context()
        with patch.object(plugin_module, "_request", side_effect=UpstreamError(429, "too many", None)):
            with self.assertRaises(RateLimited):
                plugin_module.plugin.sync({}, ctx)
        with patch.object(plugin_module, "_request", side_effect=UpstreamError(403, "forbidden", None)):
            with self.assertRaises(NeedsAuth):
                plugin_module.plugin.sync({}, ctx)


class ManifestTests(unittest.TestCase):
    def test_manifest_matches_plugin_and_contract(self):
        root = pathlib.Path(__file__).parent
        manifest = json.loads((root / "securo-plugin.json").read_text())
        self.assertEqual(manifest["runtime"]["entrypoint"], "truelayer_plugin:plugin")
        self.assertTrue(manifest["id"].startswith("gizzy/"))
        self.assertEqual(manifest["repository"], f"https://github.com/{manifest['id']}")
        integration = manifest["contributes"]["integrations"][0]
        self.assertEqual(integration["auth"], "oauth")
        self.assertEqual(integration["provides"], ["accounts", "transactions"])
        # Securo 0.21.0 rejects unknown integration fields; `complete_feed`
        # was added after that release, so it must stay out of the manifest.
        self.assertNotIn("complete_feed", integration)
        fields = {field["key"] for field in integration["fields"]}
        self.assertTrue({"client_id", "client_secret"} <= fields)
        hosts = {entry["host"] for entry in manifest["network"]}
        self.assertTrue(hosts <= plugin_module.HOSTS)


if __name__ == "__main__":
    unittest.main()
