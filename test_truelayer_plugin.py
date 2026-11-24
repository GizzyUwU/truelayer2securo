"""Standard-library tests for the TrueLayer Securo plugin.

Run with: python3 -m unittest -v
"""

from __future__ import annotations

import datetime as dt
import io
import ipaddress
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

    def test_build_reauth_url_posts_truelayer_reauthuri(self):
        calls = []

        def fake_request(url, **kwargs):
            calls.append((url, kwargs))
            return {"result": "https://auth.truelayer.com/reauth?x=1", "success": True}

        with patch.object(plugin_module, "_request", side_effect=fake_request):
            url = plugin_module.build_reauth_url(
                "app-123", "refresh-1", "https://securo.example/plugins/oauth/callback", "s1"
            )

        self.assertEqual(url, "https://auth.truelayer.com/reauth?x=1")
        self.assertEqual(len(calls), 1)
        request_url, request = calls[0]
        self.assertEqual(request_url, "https://auth.truelayer.com/v1/reauthuri")
        self.assertEqual(request["method"], "POST")
        self.assertEqual(
            request["json_body"],
            {
                "response_type": "code",
                "refresh_token": "refresh-1",
                "redirect_uri": "https://securo.example/plugins/oauth/callback",
                "state": "s1",
            },
        )

    def test_oauth_url_uses_reauth_link_for_existing_connection(self):
        params = {"redirect_uri": "https://securo.example/plugins/oauth/callback", "state": "s1"}
        ctx = context(
            config={"client_id": "app-123"},
            secrets={"refresh_token": "refresh-1"},
        )
        with (
            patch.object(plugin_module, "build_reauth_url", return_value="https://auth.truelayer.com/reauth") as reauth,
            patch.object(plugin_module, "build_auth_url") as full,
        ):
            result = plugin_module.plugin.oauth_url(params, ctx)

        self.assertEqual(result, {"url": "https://auth.truelayer.com/reauth"})
        reauth.assert_called_once_with("app-123", "refresh-1", params["redirect_uri"], "s1")
        full.assert_not_called()

    def test_oauth_url_falls_back_to_full_auth_when_reauth_unavailable(self):
        params = {"redirect_uri": "https://securo.example/plugins/oauth/callback", "state": "s1"}
        ctx = context(
            config={"client_id": "app-123"},
            secrets={"refresh_token": "refresh-1"},
        )
        for status in (400, 401, 404):
            with self.subTest(status=status):
                with (
                    patch.object(plugin_module, "build_reauth_url", side_effect=UpstreamError(status, "no reauth")),
                    patch.object(plugin_module, "build_auth_url", return_value="https://auth.truelayer.com/full") as full,
                ):
                    result = plugin_module.plugin.oauth_url(params, ctx)
                self.assertEqual(result, {"url": "https://auth.truelayer.com/full"})
                full.assert_called_once_with(
                    "app-123", params["redirect_uri"], "s1", plugin_module.DEFAULT_PROVIDERS
                )

    def test_oauth_url_does_not_ask_for_reauth_on_fresh_connection(self):
        params = {"redirect_uri": "https://securo.example/plugins/oauth/callback", "state": "s1"}
        with (
            patch.object(plugin_module, "build_reauth_url") as reauth,
            patch.object(plugin_module, "build_auth_url", return_value="https://auth.truelayer.com/full"),
        ):
            result = plugin_module.plugin.oauth_url(params, context(config={"client_id": "app-123"}))

        self.assertEqual(result, {"url": "https://auth.truelayer.com/full"})
        reauth.assert_not_called()

    def test_oauth_url_does_not_hide_unexpected_reauth_errors(self):
        params = {"redirect_uri": "https://securo.example/plugins/oauth/callback", "state": "s1"}
        ctx = context(config={"client_id": "app-123"}, secrets={"refresh_token": "refresh-1"})
        with (
            patch.object(plugin_module, "build_reauth_url", side_effect=UpstreamError(500, "server error")),
            patch.object(plugin_module, "build_auth_url") as full,
        ):
            with self.assertRaises(UpstreamError):
                plugin_module.plugin.oauth_url(params, ctx)
        full.assert_not_called()


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
        self.assertEqual(second["currency"], "XXX")

        card = plugin_module.map_transactions(
            [txns[1]], "card:c1", is_card=True, account_currency="GBP"
        )
        self.assertEqual(card[0]["type"], "debit")
        self.assertEqual(card[0]["currency"], "XXX")

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
    def setUp(self):
        # Sync now always mints a token at the start; these tests exercise the
        # mapping/pipeline, so keep the HTTP fakes focused on the data calls.
        refresh = patch.object(plugin_module, "_access_token", return_value=("access-1", {}))
        refresh.start()
        self.addCleanup(refresh.stop)

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
                self.assertIn("from=", url)
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

        stderr = io.StringIO()
        with patch.object(plugin_module, "_request", side_effect=fake_request), patch.object(
            sys, "stderr", stderr
        ):
            result = plugin_module.plugin.sync({}, valid_context())

        data = result["data"]
        self.assertEqual(data["contract"], 1)
        self.assertEqual(len(data["accounts"]), 2)
        checking, credit = data["accounts"]
        self.assertEqual(checking["external_id"], "account:acc-1")
        self.assertEqual(checking["type"], "checking")
        # Spendable accounts report `available`, the bank-app figure.
        self.assertEqual(checking["balance"], "100.00")
        self.assertIn(
            "field=available current=123.45 available=100.0 "
            "pending_total=0 posted_total=-5.50 reported=100.00",
            stderr.getvalue(),
        )
        self.assertEqual(checking["institution_name"], "Mock Bank")
        self.assertEqual(checking["transactions"][0]["external_id"], "account:acc-1:stable-1")

        self.assertEqual(credit["external_id"], "card:card-1")
        self.assertEqual(credit["type"], "credit_card")
        # TrueLayer's `current` (50) excludes the pending 30 purchase. The row
        # stays visible, but is balance-neutral, so no adjustment is needed.
        # A liability keeps `current`: `available` there is remaining credit.
        self.assertEqual(credit["balance"], "50.00")
        self.assertIn("type=credit_card source=provider field=current", stderr.getvalue())
        self.assertEqual(credit["masked_number"], "4242")
        self.assertEqual(credit["transactions"][0]["type"], "debit")
        self.assertEqual(credit["transactions"][0]["status"], "pending")
        self.assertEqual(credit["transactions"][0]["currency"], "XXX")

        self.assertEqual(result["state"]["balances"]["account:acc-1"], "100.00")
        self.assertEqual(result["state"]["consent_status"], "active")
        self.assertNotIn("secrets", result)

    def test_balance_field_current_uses_settled_figure(self):
        def fake_request(url, **kwargs):
            if url.endswith("/data/v1/accounts"):
                return {"results": [{"account_id": "acc-1", "currency": "GBP"}]}
            if url.endswith("/data/v1/cards"):
                return {"results": []}
            if "/accounts/acc-1/transactions" in url:
                return {"results": []}
            if "/accounts/acc-1/balance" in url:
                return {"results": [{"current": 18.14, "available": 17.10, "currency": "GBP"}]}
            if url.endswith("/data/v1/me"):
                return {"results": []}
            raise AssertionError(f"unexpected URL: {url}")

        ctx = valid_context()
        ctx.config["balance_field"] = "current"
        with patch.object(plugin_module, "_request", side_effect=fake_request):
            result = plugin_module.plugin.sync({}, ctx)
        self.assertEqual(result["data"]["accounts"][0]["balance"], "18.14")

    def test_debit_card_uses_available_like_an_account(self):
        def fake_request(url, **kwargs):
            if url.endswith("/data/v1/accounts"):
                return {"results": []}
            if url.endswith("/data/v1/cards"):
                return {"results": [{"account_id": "card-1", "currency": "GBP"}]}
            if "/cards/card-1/transactions" in url:
                return {"results": []}
            if "/cards/card-1/balance" in url:
                return {"results": [{"current": 18.14, "available": 17.10, "currency": "GBP"}]}
            if url.endswith("/data/v1/me"):
                return {"results": []}
            raise AssertionError(f"unexpected URL: {url}")

        ctx = valid_context()
        ctx.config["card_kind"] = "checking"
        with patch.object(plugin_module, "_request", side_effect=fake_request):
            result = plugin_module.plugin.sync({}, ctx)
        account = result["data"]["accounts"][0]
        self.assertEqual(account["type"], "checking")
        self.assertEqual(account["balance"], "17.10")

    def test_pending_row_in_dated_feed_is_visible_but_balance_neutral(self):
        today = plugin_module.dt.date.today().isoformat()
        account = {"account_id": "acc-1", "display_name": "Current", "currency": "GBP"}
        settled = {
            "transaction_id": "t-1",
            "timestamp": f"{today}T10:00:00Z",
            "amount": -5.0,
            "transaction_type": "DEBIT",
            "description": "COFFEE",
            "status": "booked",
        }
        hold = {
            "transaction_id": "hold-1",
            "timestamp": f"{today}T11:00:00Z",
            "amount": 2.0,
            "transaction_type": "CREDIT",
            "description": "REFUND",
            "status": "pending",
        }

        def fake_request(url, **kwargs):
            if url.endswith("/data/v1/accounts"):
                return {"results": [account]}
            if url.endswith("/data/v1/cards"):
                return {"results": []}
            if "/transactions/pending" in url:
                return {"results": [], "status": "success"}
            if "/accounts/acc-1/transactions" in url:
                return {"results": [settled, hold]}
            if "/accounts/acc-1/balance" in url:
                return {"results": [{"current": 100.0, "currency": "GBP"}]}
            if url.endswith("/data/v1/me"):
                return {"results": []}
            raise AssertionError(f"unexpected URL: {url}")

        with patch.object(plugin_module, "_request", side_effect=fake_request):
            result = plugin_module.plugin.sync({}, valid_context())

        synced = result["data"]["accounts"][0]
        # TrueLayer's `current` is used unchanged; the hold does not move it.
        self.assertEqual(synced["balance"], "100.00")
        transactions = {tx["external_id"]: tx for tx in synced["transactions"]}
        self.assertEqual(len(transactions), 2)
        pending = transactions["account:acc-1:hold-1"]
        self.assertEqual(pending["status"], "pending")
        self.assertEqual(pending["type"], "credit")
        self.assertEqual(pending["currency"], "XXX")

        posted = [tx for tx in transactions.values() if tx["status"] == "posted"]
        signed = sum(
            (Decimal(tx["amount"]) if tx["type"] == "credit" else -Decimal(tx["amount"]))
            for tx in posted
        )
        # Securo's derived opening balance is unchanged by the visible hold.
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
            "status": "pending",
        }

        def fake_request(url, **kwargs):
            if url.endswith("/data/v1/accounts"):
                return {"results": [account]}
            if url.endswith("/data/v1/cards"):
                return {"results": []}
            if "/transactions/pending" in url:
                return {"results": [], "status": "success"}
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
        self.assertEqual(transactions[0]["currency"], "XXX")
        # The -2 hold is not in `current`, and it no longer shifts the balance.
        self.assertEqual(result["data"]["accounts"][0]["balance"], "50.00")

    def test_pending_feed_is_imported_alongside_posted(self):
        today = plugin_module.dt.date.today().isoformat()
        account = {"account_id": "acc-1", "display_name": "Current", "currency": "GBP"}
        settled = {
            "transaction_id": "t-1",
            "timestamp": f"{today}T10:00:00Z",
            "amount": -5.0,
            "transaction_type": "DEBIT",
            "description": "COFFEE",
        }
        # TrueLayer's pending feed has no status field; the plugin marks it.
        hold = {
            "transaction_id": "hold-1",
            "timestamp": f"{today}T11:00:00Z",
            "amount": -20.0,
            "transaction_type": "DEBIT",
            "description": "PENDING SHOP",
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
                return {"results": [{"current": 100.0, "available": 80.0, "currency": "GBP"}]}
            if url.endswith("/data/v1/me"):
                return {"results": []}
            raise AssertionError(f"unexpected URL: {url}")

        with patch.object(plugin_module, "_request", side_effect=fake_request):
            result = plugin_module.plugin.sync({}, valid_context())

        synced = result["data"]["accounts"][0]
        by_id = {tx["external_id"]: tx for tx in synced["transactions"]}
        self.assertEqual(len(by_id), 2)
        self.assertEqual(by_id["account:acc-1:t-1"]["status"], "posted")
        self.assertEqual(by_id["account:acc-1:t-1"]["currency"], "GBP")
        self.assertEqual(by_id["account:acc-1:hold-1"]["status"], "pending")
        self.assertEqual(by_id["account:acc-1:hold-1"]["currency"], "XXX")
        # Spendable accounts report `available`; the hold stays visible but
        # balance-neutral.
        self.assertEqual(synced["balance"], "80.00")

    def test_pending_feed_marks_matching_dated_row_pending_once(self):
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
        self.assertEqual(transactions[0]["currency"], "XXX")
        self.assertEqual(result["data"]["accounts"][0]["balance"], "50.00")

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

    def test_settled_feed_with_empty_pending_feed(self):
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
                return {"results": [], "status": "success"}
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

    def test_card_pending_rows_are_visible_but_do_not_change_debt(self):
        today = plugin_module.dt.date.today().isoformat()
        card = {"account_id": "card-1", "display_name": "Card", "currency": "GBP"}

        def fake_request(url, **kwargs):
            if url.endswith("/data/v1/accounts"):
                return {"results": []}
            if url.endswith("/data/v1/cards"):
                return {"results": [card]}
            if "/transactions/pending" in url:
                return {"results": [], "status": "success"}
            if "/cards/card-1/transactions" in url:
                return {
                    "results": [
                        {
                            "transaction_id": "posted-buy",
                            "timestamp": f"{today}T09:00:00Z",
                            "amount": 30.0,
                            "description": "POSTED SHOP",
                            "status": "booked",
                        },
                        {
                            "transaction_id": "hold-buy",
                            "timestamp": f"{today}T10:00:00Z",
                            "amount": 20.0,
                            "description": "PENDING SHOP",
                            "status": "pending",
                        },
                        {
                            "transaction_id": "hold-refund",
                            "timestamp": f"{today}T11:00:00Z",
                            "amount": -5.0,
                            "description": "PENDING REFUND",
                            "status": "pending",
                        },
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
        self.assertEqual(synced["balance"], "50.00")
        by_id = {tx["external_id"]: tx for tx in synced["transactions"]}
        self.assertEqual(by_id["card:card-1:hold-buy"]["type"], "debit")
        self.assertEqual(by_id["card:card-1:hold-buy"]["status"], "pending")
        self.assertEqual(by_id["card:card-1:hold-buy"]["currency"], "XXX")
        self.assertEqual(by_id["card:card-1:hold-refund"]["type"], "credit")
        self.assertEqual(by_id["card:card-1:hold-refund"]["status"], "pending")
        self.assertEqual(by_id["card:card-1:hold-refund"]["currency"], "XXX")

        posted = [tx for tx in by_id.values() if tx["status"] == "posted"]
        signed = sum(
            (Decimal(tx["amount"]) if tx["type"] == "credit" else -Decimal(tx["amount"]))
            for tx in posted
        )
        # The remaining -20 is the debt from before this window; holds do not
        # move the provider's `current` figure or Securo's synthetic opening.
        self.assertEqual(-Decimal(synced["balance"]) - signed, Decimal("-20.00"))

    def test_checking_card_pending_purchase_is_balance_neutral(self):
        today = plugin_module.dt.date.today().isoformat()
        card = {"account_id": "card-1", "display_name": "Debit Card", "currency": "GBP"}
        hold = {
            "transaction_id": "hold-buy",
            "timestamp": f"{today}T10:00:00Z",
            "amount": 20.0,
            "description": "PENDING SHOP",
            "status": "pending",
        }

        def fake_request(url, **kwargs):
            if url.endswith("/data/v1/accounts"):
                return {"results": []}
            if url.endswith("/data/v1/cards"):
                return {"results": [card]}
            if "/transactions/pending" in url:
                return {"results": [], "status": "success"}
            if "/cards/card-1/transactions" in url:
                return {"results": [hold]}
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
        self.assertEqual(synced["balance"], "50.00")
        self.assertEqual(synced["transactions"][0]["type"], "debit")
        self.assertEqual(synced["transactions"][0]["status"], "pending")
        self.assertEqual(synced["transactions"][0]["currency"], "XXX")

    def test_missing_balance_ignores_pending_row_when_deriving_balance(self):
        today = plugin_module.dt.date.today().isoformat()
        account = {"account_id": "acc-1", "display_name": "Current", "currency": "GBP"}
        hold = {
            "transaction_id": "hold-1",
            "timestamp": f"{today}T11:00:00Z",
            "amount": 2.0,
            "transaction_type": "CREDIT",
            "description": "REFUND",
            "status": "pending",
        }

        def fake_request(url, **kwargs):
            if url.endswith("/data/v1/accounts"):
                return {"results": [account]}
            if url.endswith("/data/v1/cards"):
                return {"results": []}
            if "/transactions/pending" in url:
                return {"results": [], "status": "success"}
            if "/accounts/acc-1/transactions" in url:
                return {"results": [hold]}
            if "/accounts/acc-1/balance" in url:
                raise UpstreamError(404, "not found", "account_not_found")
            if url.endswith("/data/v1/me"):
                return {"results": []}
            raise AssertionError(f"unexpected URL: {url}")

        stderr = io.StringIO()
        with patch.object(plugin_module, "_request", side_effect=fake_request), patch.object(sys, "stderr", stderr):
            result = plugin_module.plugin.sync({}, valid_context())

        synced = result["data"]["accounts"][0]
        self.assertEqual(synced["balance"], "0.00")
        self.assertEqual(synced["transactions"][0]["status"], "pending")
        self.assertEqual(synced["transactions"][0]["currency"], "XXX")
        self.assertIn("source=transactions", stderr.getvalue())

    def test_missing_balance_ignores_pending_card_hold_when_deriving_balance(self):
        today = plugin_module.dt.date.today().isoformat()
        card = {"account_id": "card-1", "display_name": "Credit Card", "currency": "GBP"}
        hold = {
            "transaction_id": "hold-1",
            "timestamp": f"{today}T11:00:00Z",
            "amount": 2.0,
            "description": "PENDING SHOP",
            "status": "pending",
        }

        def fake_request(url, **kwargs):
            if url.endswith("/data/v1/accounts"):
                return {"results": []}
            if url.endswith("/data/v1/cards"):
                return {"results": [card]}
            if "/transactions/pending" in url:
                return {"results": [], "status": "success"}
            if "/cards/card-1/transactions" in url:
                return {"results": [hold]}
            if "/cards/card-1/balance" in url:
                raise UpstreamError(404, "not found", "account_not_found")
            if url.endswith("/data/v1/me"):
                return {"results": []}
            raise AssertionError(f"unexpected URL: {url}")

        stderr = io.StringIO()
        with patch.object(plugin_module, "_request", side_effect=fake_request), patch.object(sys, "stderr", stderr):
            result = plugin_module.plugin.sync({}, valid_context())

        synced = result["data"]["accounts"][0]
        self.assertEqual(synced["balance"], "0.00")
        self.assertEqual(synced["transactions"][0]["currency"], "XXX")
        self.assertIn("source=transactions", stderr.getvalue())

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


class TokenRecoveryTests(unittest.TestCase):
    """A valid stored token is reused; a rejected one must not force a reconnect."""

    def _context(self, *, expires_at="2000-01-01T00:00:00+00:00"):
        return context(
            config={"client_id": "app-123"},
            secrets={
                "client_secret": "secret-1",
                # The stored token is deliberately stale; the expiry says when
                # it must be refreshed.
                "access_token": "stale-access",
                "refresh_token": "refresh-1",
                "expires_at": expires_at,
            },
        )

    def test_valid_stored_access_token_is_reused_without_refresh(self):
        used = []

        def fake_request(url, **kwargs):
            if "/connect/token" in url:
                raise AssertionError("a valid stored token must not be refreshed")
            used.append(kwargs.get("token"))
            return {"results": [], "status": "success"}

        valid = self._context(expires_at="2099-01-01T00:00:00+00:00")
        with patch.object(plugin_module, "_request", side_effect=fake_request):
            result = plugin_module.plugin.sync({}, valid)

        self.assertEqual(used, ["stale-access"] * 3)
        self.assertNotIn("secrets", result)

    def test_refresh_needed_only_near_expiry(self):
        now = dt.datetime(2026, 1, 1, 12, 0, tzinfo=dt.UTC)
        self.assertFalse(
            plugin_module._needs_refresh((now + dt.timedelta(seconds=120)).isoformat(), now)
        )
        self.assertTrue(
            plugin_module._needs_refresh((now + dt.timedelta(seconds=30)).isoformat(), now)
        )
        self.assertTrue(plugin_module._needs_refresh(None, now))

    def test_expired_access_token_is_refreshed(self):
        used = []

        def fake_request(url, **kwargs):
            if "/connect/token" in url:
                return {"access_token": "minted-access", "expires_in": 3600}
            used.append(kwargs.get("token"))
            return {"results": [], "status": "success"}

        with patch.object(plugin_module, "_request", side_effect=fake_request):
            result = plugin_module.plugin.sync({}, self._context())

        self.assertEqual(used, ["minted-access"] * 3)
        self.assertEqual(result["secrets"]["access_token"], "minted-access")

    def test_rejected_minted_token_is_refreshed_and_retried(self):
        calls = []

        def fake_request(url, **kwargs):
            calls.append(url)
            if "/connect/token" in url:
                token = "minted-access" if sum("/connect/token" in u for u in calls) == 1 else "second-access"
                return {"access_token": token, "refresh_token": "fresh-refresh", "expires_in": 3600}
            if kwargs.get("token") != "second-access":
                raise UpstreamError(401, "access token expired", "access_token_expired")
            return {"results": [], "status": "success"}

        with patch.object(plugin_module, "_request", side_effect=fake_request):
            result = plugin_module.plugin.sync({}, self._context())

        self.assertEqual(result["secrets"]["access_token"], "second-access")
        self.assertEqual(result["secrets"]["refresh_token"], "fresh-refresh")
        self.assertEqual(sum("/connect/token" in url for url in calls), 2)
        self.assertIsNone(result["data"])

    def test_token_still_rejected_after_retry_is_retryable_not_needs_auth(self):
        def fake_request(url, **kwargs):
            if "/connect/token" in url:
                return {"access_token": "minted-access", "expires_in": 3600}
            raise UpstreamError(401, "access token expired", "access_token_expired")

        with patch.object(plugin_module, "_request", side_effect=fake_request):
            with self.assertRaises(UpstreamError) as raised:
                plugin_module.plugin.sync({}, self._context())
        self.assertEqual(raised.exception.status, 401)
        self.assertIn("retry", str(raised.exception))
        # The underlying TrueLayer reason is kept so the runner log is actionable.
        self.assertIn("access token expired", str(raised.exception))
        self.assertIn("/data/v1/accounts", str(raised.exception))

    def test_data_api_errors_array_is_parsed(self):
        payload = {
            "errors": [{"error": "invalid_token", "message": "Access token expired"}],
            "status": "failed",
        }
        self.assertEqual(plugin_module._error_code(payload), "invalid_token")
        self.assertIn("Access token expired", plugin_module._error_message(payload) or "")

    def test_psu_ip_header_is_sent_when_valid(self):
        seen = {}

        def fake_urlopen(request, timeout=None):
            seen.update({k.lower(): v for k, v in dict(request.header_items()).items()})
            raise UpstreamError(500, "stop here")

        with patch.object(plugin_module.urllib.request, "urlopen", side_effect=fake_urlopen):
            with self.assertRaises(UpstreamError):
                plugin_module._request("https://api.truelayer.com/data/v1/accounts", psu_ip="203.0.113.7")
        self.assertEqual(seen.get("x-psu-ip"), "203.0.113.7")

    def test_psu_ip_config_validation_and_precedence(self):
        params = {"psu_ip": "198.51.100.9"}
        ctx = context(config={"psu_ip": "203.0.113.7"})
        self.assertEqual(plugin_module._psu_ip(ctx, params), "198.51.100.9")
        self.assertIsNone(plugin_module._psu_ip(context(config={}), {}))
        self.assertIsNone(plugin_module._psu_ip(context(config={"psu_ip": "not-an-ip"}), {}))
        self.assertEqual(
            plugin_module._psu_ip(context(config={"psu_ip": " 203.0.113.7 "}), {}),
            "203.0.113.7",
        )
        securo_ctx = context(config={"psu_ip": "203.0.113.7"})
        securo_ctx.securo = {"psu_ip": "192.0.2.1"}
        self.assertEqual(plugin_module._psu_ip(securo_ctx, {}), "192.0.2.1")

    def test_sync_forwards_psu_ip_to_data_calls(self):
        seen = []

        def fake_request(url, **kwargs):
            if "/connect/token" in url:
                return {"access_token": "minted-access", "expires_in": 3600}
            seen.append(kwargs.get("psu_ip"))
            return {"results": [], "status": "success"}

        ctx = context(
            config={"client_id": "app-123", "psu_ip": "203.0.113.7"},
            secrets={"client_secret": "secret-1", "refresh_token": "refresh-1"},
        )
        with patch.object(plugin_module, "_request", side_effect=fake_request):
            plugin_module.plugin.sync({}, ctx)
        data_calls = [url for url in seen]
        self.assertTrue(data_calls)
        self.assertTrue(all(ip == "203.0.113.7" for ip in seen))

    def test_401_detail_and_correlation_id_are_kept(self):
        import urllib.error

        payload = {
            "error": "unauthorized",
            "error_description": "Unauthorized.",
            "error_details": {"reason": "consent_expired", "provider": "mock"},
        }
        body = json.dumps(payload).encode()
        headers = {"X-TL-Correlation-Id": "corr-123"}
        exc = urllib.error.HTTPError(
            "https://api.truelayer.com/data/v1/accounts/a/transactions",
            401,
            "Unauthorized",
            headers,
            io.BytesIO(body),
        )
        with patch.object(plugin_module.urllib.request, "urlopen", side_effect=exc):
            with self.assertRaises(UpstreamError) as raised:
                plugin_module._request("https://api.truelayer.com/data/v1/accounts/a/transactions")
        message = str(raised.exception.message)
        self.assertIn("unauthorized", message)
        self.assertIn("consent_expired", message)
        self.assertIn("corr-123", message)
        self.assertEqual(raised.exception.code, "unauthorized")

    def test_expired_consent_still_needs_auth(self):
        calls = []

        def fake_request(url, **kwargs):
            calls.append(url)
            if "/connect/token" in url:
                return {"access_token": "minted-access", "expires_in": 3600}
            raise UpstreamError(403, "consent expired", "consent_expired")

        with patch.object(plugin_module, "_request", side_effect=fake_request):
            with self.assertRaises(NeedsAuth) as raised:
                plugin_module.plugin.sync({}, self._context())
        self.assertIn("consent has expired", str(raised.exception))
        self.assertEqual(sum("/connect/token" in url for url in calls), 1)


class RandomGbIpTests(unittest.TestCase):
    def test_bundled_ranges_decode_to_valid_ipv4_networks(self):
        ranges = plugin_module._gb_isp_ranges()
        self.assertGreater(len(ranges), 1000)
        for start, size in ranges:
            self.assertTrue(0 <= start < 2**32)
            self.assertGreaterEqual(size, 256)
            self.assertLessEqual(start + size, 2**32)

    def test_random_ip_is_inside_a_bundled_range(self):
        ranges = plugin_module._gb_isp_ranges()
        for _ in range(200):
            address = int(ipaddress.IPv4Address(plugin_module.random_gb_isp_ip()))
            self.assertTrue(
                any(start <= address < start + size for start, size in ranges)
            )

    def test_random_ip_does_not_touch_the_network(self):
        with patch.object(plugin_module.urllib.request, "urlopen", side_effect=AssertionError("network")):
            for _ in range(10):
                ipaddress.IPv4Address(plugin_module.random_gb_isp_ip())


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
        self.assertEqual(integration["sync_minutes"], 60)
        # Securo 0.21.0 rejects unknown integration fields; `complete_feed`
        # was added after that release, so it must stay out of the manifest.
        self.assertNotIn("complete_feed", integration)
        fields = {field["key"] for field in integration["fields"]}
        self.assertTrue({"client_id", "client_secret", "balance_field", "psu_ip"} <= fields)
        hosts = {entry["host"] for entry in manifest["network"]}
        self.assertTrue(hosts <= plugin_module.HOSTS)


if __name__ == "__main__":
    unittest.main()
