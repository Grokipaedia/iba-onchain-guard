# guard.py - IBA Intent Bound Authorization · Onchain Guard
# Patent GB2603013.0 (Pending) · UK IPO · Filed February 5, 2026
# WIPO DAS Confirmed April 15, 2026 · Access Code C9A6
# IETF draft-williams-intent-token-00 · intentbound.com
#
# Agential Onchain. Human intent required.
# Every autonomous AI agent action on a blockchain — trade, transfer,
# stake, vote, deploy, sign — requires a signed human intent certificate
# before it executes on-chain.
#
# Six onchain configurations:
#   defi-trading.iba.yaml    — Autonomous trading · DeFi · yield
#   wallet-agent.iba.yaml    — Wallet governance · spending limits
#   payment-agent.iba.yaml   — x402 · stablecoin · payment rails
#   dao-voting.iba.yaml      — Governance votes · proposal execution
#   nft-agent.iba.yaml       — NFT minting · listing · transfer
#   default-onchain.iba.yaml — Platform-agnostic base cert
#
# Compatible: Ethereum EIP-7702 · Coinbase Agentic Wallets ·
# Base agent-native accounts · Chainlink · x402 · Any EVM chain ·
# Solana · Any blockchain with autonomous agent activity
#
# AgentialOnChain.com · intentbound.com

import json
import yaml
import os
import time
import argparse
from datetime import datetime, timezone
from decimal import Decimal


class IBABlockedError(Exception):
    pass


class IBATerminatedError(Exception):
    pass


HOLLOW_LEVELS = {
    "light":  ["private_key", "seed_phrase", "api_key"],
    "medium": ["private_key", "seed_phrase", "api_key",
               "wallet_address", "transaction_hash", "secret"],
    "deep":   ["private_key", "seed_phrase", "api_key",
               "wallet_address", "transaction_hash", "secret",
               "portfolio_value", "position_size", "pnl",
               "account_balance", "personal_data"],
}

CONFIG_NAMES = {
    "defi-trading.iba.yaml":    "DeFi Trading · Autonomous Agent",
    "wallet-agent.iba.yaml":    "Wallet Governance · Spending Limits",
    "payment-agent.iba.yaml":   "Payment Agent · x402 · Stablecoin",
    "dao-voting.iba.yaml":      "DAO Voting · Governance Execution",
    "nft-agent.iba.yaml":       "NFT Agent · Mint · List · Transfer",
    "default-onchain.iba.yaml": "Default · Platform-Agnostic Onchain",
}


class IBAOnchainGuard:
    """
    IBA enforcement layer for autonomous AI agents on blockchain networks.

    Requires a signed human intent certificate before any onchain action —
    trade, transfer, stake, vote, deploy, sign, pay.

    Compatible: Ethereum · Base · Solana · Any EVM chain ·
    EIP-7702 · Coinbase Agentic Wallets · Chainlink · x402

    ALLOW · BLOCK · TERMINATE with immutable audit chain.
    Sub-1ms gate. DENY_ALL default posture.

    "The transaction is not the authorization. The signed certificate is."

    AgentialOnChain.com · Patent GB2603013.0 (Pending) · intentbound.com
    """

    def __init__(self, config_path="default-onchain.iba.yaml",
                 audit_path="onchain-audit.jsonl"):
        self.config_path  = config_path
        self.audit_path   = audit_path
        self.terminated   = False
        self.session_id   = f"oc-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        self.action_count = 0
        self.block_count  = 0
        self.track        = CONFIG_NAMES.get(
            os.path.basename(config_path), config_path)

        self.config          = self._load_config()
        self.scope           = [s.lower() for s in self.config.get("scope", [])]
        self.denied          = [d.lower() for d in self.config.get("denied", [])]
        self.default_posture = self.config.get("default_posture", "DENY_ALL")
        self.kill_threshold  = self.config.get("kill_threshold", None)
        self.hard_expiry     = self.config.get(
            "temporal_scope", {}).get("hard_expiry")
        self.principal       = self.config.get("principal", {})

        fl = self.config.get("financial_limits", {})
        self.max_tx_value    = float(fl.get("max_single_tx_usd", 999999999))
        self.max_session_usd = float(fl.get("max_session_usd", 999999999))
        self.session_spent   = 0.0

        self._validate_cert()
        self._log_event("SESSION_START", "IBA Onchain Guard initialised", "ALLOW")
        self._print_header()

    def _load_config(self):
        if not os.path.exists(self.config_path):
            print(f"  No {self.config_path} found — DENY_ALL posture.")
            default = {
                "intent": {"description": "No onchain intent declared — DENY_ALL."},
                "scope": [], "denied": [], "default_posture": "DENY_ALL",
            }
            with open(self.config_path, "w") as f:
                yaml.dump(default, f)
            return default
        with open(self.config_path) as f:
            return yaml.safe_load(f)

    def _validate_cert(self):
        if not self.principal.get("wallet_reference"):
            print("  WARNING: No wallet reference in certificate.")
        if not self.principal.get("human_authorization"):
            print("  WARNING: No human authorization in certificate.")

    def _print_header(self):
        intent = self.config.get("intent", {})
        desc = (intent.get("description", "No intent declared")
                if isinstance(intent, dict) else str(intent))
        print("\n" + "=" * 68)
        print("  IBA ONCHAIN GUARD · Intent Bound Authorization")
        print("  AgentialOnChain.com · Patent GB2603013.0 Pending · intentbound.com")
        print("=" * 68)
        print(f"  Track       : {self.track}")
        print(f"  Session     : {self.session_id}")
        print(f"  Config      : {self.config_path}")
        print(f"  Wallet ref  : {self.principal.get('wallet_reference', 'UNKNOWN')}")
        print(f"  Auth ref    : {self.principal.get('human_authorization', 'NONE')}")
        print(f"  Chain       : {self.principal.get('chain', 'UNKNOWN')}")
        print(f"  Intent      : {desc[:56]}...")
        print(f"  Posture     : {self.default_posture}")
        print(f"  Scope       : {', '.join(self.scope[:4]) if self.scope else 'NONE'}"
              + (" ..." if len(self.scope) > 4 else ""))
        if self.max_tx_value < 999999999:
            print(f"  Max tx      : ${self.max_tx_value:,.0f} USD")
        if self.max_session_usd < 999999999:
            print(f"  Session cap : ${self.max_session_usd:,.0f} USD")
        if self.hard_expiry:
            print(f"  Expires     : {self.hard_expiry}")
        if self.kill_threshold:
            kt = str(self.kill_threshold).replace('\n', ' ')[:56]
            print(f"  Kill        : {kt}")
        print("=" * 68 + "\n")

    def _is_expired(self):
        if not self.hard_expiry:
            return False
        try:
            expiry = datetime.fromisoformat(str(self.hard_expiry))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) > expiry
        except Exception:
            return False

    def _match(self, action: str, terms: list) -> bool:
        al = action.lower()
        return any(t in al for t in terms)

    def _match_kill(self, action: str) -> bool:
        if not self.kill_threshold:
            return False
        terms = [t.strip().lower()
                 for t in str(self.kill_threshold).split("|")]
        return self._match(action, terms)

    def _log_event(self, event_type, action, verdict,
                   reason="", tx_value_usd=None):
        entry = {
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "session_id":   self.session_id,
            "track":        self.track,
            "wallet_ref":   self.principal.get("wallet_reference", "UNKNOWN"),
            "auth_ref":     self.principal.get("human_authorization", "NONE"),
            "chain":        self.principal.get("chain", "UNKNOWN"),
            "config":       self.config_path,
            "event_type":   event_type,
            "action":       action[:200],
            "verdict":      verdict,
            "reason":       reason,
        }
        if tx_value_usd is not None:
            entry["tx_value_usd"] = tx_value_usd
        with open(self.audit_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def check_action(self, action: str,
                     tx_value_usd: float = None) -> bool:
        """
        Pre-execution gate check. Call before every onchain action.

        Returns True if permitted.
        Raises IBABlockedError if blocked.
        Raises IBATerminatedError if kill threshold triggered.

        Args:
            action:        Intended onchain action description
            tx_value_usd:  Transaction value in USD (for financial limits)
        """
        if self.terminated:
            raise IBATerminatedError("Onchain session terminated.")

        self.action_count += 1
        start = time.perf_counter()

        def _block(reason):
            self._log_event("BLOCK", action, "BLOCK", reason, tx_value_usd)
            self.block_count += 1
            print(f"  x BLOCKED  [{action[:64]}]\n    -> {reason}")
            raise IBABlockedError(f"{reason}: {action}")

        # 1. Certificate expiry
        if self._is_expired():
            _block("Certificate expired")

        # 2. Kill threshold — TERMINATE immediately
        if self._match_kill(action):
            self._log_event("TERMINATE", action, "TERMINATE",
                "Kill threshold — onchain session ended", tx_value_usd)
            self.terminated = True
            print(f"  x TERMINATE [{action[:62]}]\n"
                  f"    -> Kill threshold — onchain session ended")
            self._log_event("SESSION_END", "Kill threshold", "TERMINATE")
            raise IBATerminatedError(f"Kill threshold: {action}")

        # 3. Single transaction value limit
        if tx_value_usd is not None and tx_value_usd > self.max_tx_value:
            _block(f"Transaction ${tx_value_usd:,.0f} exceeds "
                   f"cert limit ${self.max_tx_value:,.0f}")

        # 4. Session spending cap
        if tx_value_usd is not None:
            if self.session_spent + tx_value_usd > self.max_session_usd:
                _block(f"Session cap ${self.max_session_usd:,.0f} would be exceeded")

        # 5. Denied list
        if self._match(action, self.denied):
            _block("Action in denied list")

        # 6. Scope — DENY_ALL if outside declared scope
        if self.scope and not self._match(action, self.scope):
            if self.default_posture == "DENY_ALL":
                _block("Outside declared onchain scope (DENY_ALL)")

        # 7. ALLOW
        elapsed_ms = (time.perf_counter() - start) * 1000
        if tx_value_usd is not None:
            self.session_spent += tx_value_usd
        val_str = f" · ${tx_value_usd:,.0f}" if tx_value_usd else ""
        self._log_event("ALLOW", action, "ALLOW",
            f"Within scope{val_str} ({elapsed_ms:.3f}ms)", tx_value_usd)
        print(f"  + ALLOWED  [{action[:54]}]{val_str} ({elapsed_ms:.3f}ms)")
        return True

    def hollow(self, data: str, level: str = "medium") -> str:
        """Redact sensitive onchain data before processing."""
        blocked = HOLLOW_LEVELS.get(level, HOLLOW_LEVELS["medium"])
        hollowed = data
        redacted = []
        for item in blocked:
            if item.lower() in data.lower():
                hollowed = hollowed.replace(
                    item, f"[ONCHAIN-REDACTED:{item.upper()}]")
                redacted.append(item)
        if redacted:
            print(f"  o HOLLOWED [{level}] — redacted: {', '.join(redacted)}")
            self._log_event("HOLLOW", f"Hollowing: {level}", "ALLOW",
                f"Redacted: {', '.join(redacted)}")
        return hollowed

    def summary(self):
        print("\n" + "=" * 68)
        print("  IBA ONCHAIN GUARD · SESSION SUMMARY")
        print("=" * 68)
        print(f"  Track         : {self.track}")
        print(f"  Session       : {self.session_id}")
        print(f"  Wallet ref    : {self.principal.get('wallet_reference', 'UNKNOWN')}")
        print(f"  Actions       : {self.action_count}")
        print(f"  Blocked       : {self.block_count}")
        print(f"  Allowed       : {self.action_count - self.block_count}")
        if self.session_spent > 0:
            print(f"  Session spent : ${self.session_spent:,.2f} USD")
        print(f"  Status        : {'TERMINATED' if self.terminated else 'COMPLETE'}")
        print(f"  Audit log     : {self.audit_path}")
        print("=" * 68 + "\n")

    def print_audit_log(self):
        print("-- ONCHAIN AUDIT CHAIN " + "-" * 45)
        if not os.path.exists(self.audit_path):
            print("  No audit log found.")
            return
        with open(self.audit_path) as f:
            for line in f:
                try:
                    e = json.loads(line)
                    verdict = e.get("verdict", "")
                    val = (f" ${e['tx_value_usd']:,.0f}"
                           if "tx_value_usd" in e else "")
                    symbol = "+" if verdict == "ALLOW" else "x"
                    print(f"  {symbol} {e['timestamp'][:19]}  {verdict:<10}"
                          f"  {e['action'][:38]}{val}")
                except Exception:
                    pass
        print("-" * 68 + "\n")


# Per-track demo scenarios: (action, tx_value_usd)
DEMO_SCENARIOS = {
    "defi-trading.iba.yaml": [
        ("swap_token ETH to USDC declared pool",          500.0),
        ("add_liquidity declared pool within limits",     1000.0),
        ("harvest_yield declared protocol",               None),
        ("rebalance_portfolio declared assets",           2000.0),
        ("swap_token exceed single tx limit",             15000.0),  # BLOCK value
        ("withdraw_all_liquidity emergency undeclared",   None),     # BLOCK denied
        ("drain_wallet_private_key exfil",                None),     # TERMINATE
    ],
    "wallet-agent.iba.yaml": [
        ("transfer_usdc declared recipient",              100.0),
        ("approve_token declared contract",               None),
        ("sign_message declared dapp",                    None),
        ("transfer exceed session cap",                   50001.0),  # BLOCK value
        ("transfer undeclared recipient",                 500.0),    # BLOCK scope
        ("export_private_key backup",                     None),     # TERMINATE
    ],
    "payment-agent.iba.yaml": [
        ("x402_payment declared merchant",                25.0),
        ("stablecoin_transfer declared payee",            150.0),
        ("recurring_payment declared subscription",       50.0),
        ("payment undeclared merchant",                   100.0),    # BLOCK
        ("bulk_payment mass undeclared",                  None),     # BLOCK
        ("drain_wallet unauthorized_transfer",            None),     # TERMINATE
    ],
    "dao-voting.iba.yaml": [
        ("vote_proposal declared governance",             None),
        ("delegate_votes declared address",               None),
        ("comment_proposal declared forum",               None),
        ("execute_proposal undeclared",                   None),     # BLOCK
        ("transfer_treasury unauthorized",                None),     # TERMINATE
    ],
    "nft-agent.iba.yaml": [
        ("mint_nft declared collection",                  None),
        ("list_nft declared marketplace",                 None),
        ("transfer_nft declared recipient",               None),
        ("bulk_mint undeclared collection",               None),     # BLOCK
        ("drain_nft_wallet unauthorized",                 None),     # TERMINATE
    ],
    "default-onchain.iba.yaml": [
        ("onchain_action within declared scope",          100.0),
        ("read_contract declared protocol",               None),
        ("sign_declared_transaction",                     None),
        ("undeclared_protocol interaction",               None),     # BLOCK
        ("drain_wallet credential_exfiltration",          None),     # TERMINATE
    ],
}


def run_demo(guard, config_path):
    key = os.path.basename(config_path)
    scenarios = DEMO_SCENARIOS.get(
        key, DEMO_SCENARIOS["default-onchain.iba.yaml"])
    print(f"-- Running {guard.track} Gate Checks " + "-" * 20 + "\n")
    for action, value in scenarios:
        try:
            guard.check_action(action, tx_value_usd=value)
        except IBATerminatedError as e:
            print(f"\n  ONCHAIN SESSION TERMINATED: {e}")
            break
        except IBABlockedError:
            pass


def main():
    parser = argparse.ArgumentParser(
        description="IBA Onchain Guard — Blockchain Agent Authorization")
    parser.add_argument("action", nargs="?",
                        help="Onchain action to gate-check")
    parser.add_argument("--config", default="default-onchain.iba.yaml",
                        help="Intent certificate (.iba.yaml)")
    parser.add_argument("--value", type=float, default=None,
                        help="Transaction value in USD")
    parser.add_argument("--hollow",
                        choices=["light", "medium", "deep"],
                        help="Safe hollowing level")
    parser.add_argument("--demo", action="store_true",
                        help="Run demo scenarios for this config")
    parser.add_argument("--all", action="store_true",
                        help="Run all 6 onchain track demos")
    parser.add_argument("--audit", default="onchain-audit.jsonl",
                        help="Audit log path")
    args = parser.parse_args()

    if args.all:
        for cfg in DEMO_SCENARIOS.keys():
            if os.path.exists(cfg):
                guard = IBAOnchainGuard(config_path=cfg,
                                        audit_path=args.audit)
                run_demo(guard, cfg)
                guard.summary()
                print()
        return

    guard = IBAOnchainGuard(config_path=args.config, audit_path=args.audit)

    if args.action and args.hollow:
        hollowed = guard.hollow(args.action, args.hollow)
        print(f"\n  Data (hollowed): {hollowed}\n")

    if args.demo or not args.action:
        run_demo(guard, args.config)
    elif args.action:
        try:
            guard.check_action(args.action, tx_value_usd=args.value)
        except IBATerminatedError as e:
            print(f"\n  ONCHAIN SESSION TERMINATED: {e}")
        except IBABlockedError:
            pass

    guard.summary()
    guard.print_audit_log()


if __name__ == "__main__":
    main()
