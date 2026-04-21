# iba-onchain-guard

> **Agential onchain. Human intent required.**

---

## The Problem

AI agents on blockchain networks can trade, transfer, stake, vote, deploy, and pay — autonomously, at speed, across chains — without a human in the loop.

Without a signed intent certificate:

- A DeFi trading agent can drain a liquidity pool without authorization
- A wallet agent can transfer funds to undeclared recipients
- A payment agent can execute bulk payments beyond declared limits
- A DAO voting agent can execute treasury transfers without explicit consent
- An NFT agent can bulk-transfer a collection to an attacker's address
- A compromised agent can export private keys or seed phrases
- No cryptographic record proves what the human authorized versus what the agent executed

The blockchain verifies the outcome. IBA governs the intent before execution.

**The transaction is not the authorization. The signed certificate is.**

---

## The IBA Layer

```
┌─────────────────────────────────────────────────────┐
│           HUMAN PRINCIPAL                           │
│   Signs onchain.iba.yaml before agent session       │
│   Declares: permitted actions, protocols, limits,   │
│   financial caps, kill threshold, hard expiry       │
└───────────────────────┬─────────────────────────────┘
                        │  Signed Onchain Intent Certificate
                        │  · Wallet reference
                        │  · Permitted: swap · stake · pay · vote
                        │  · Declared protocols and recipients
                        │  · Financial limits: per-tx · session cap
                        │  · Kill: drain · key export · exploit
                        │  · DENY_ALL default posture
                        ▼
┌─────────────────────────────────────────────────────┐
│              IBA ONCHAIN GUARD                      │
│   Pre-execution gate. Validates certificate         │
│   before every onchain action executes.             │
│                                                     │
│   ALLOW · BLOCK · TERMINATE                         │
│   Sub-1ms · Immutable audit chain                   │
└───────────────────────┬─────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│         BLOCKCHAIN / AGENT RUNTIME                  │
│   Ethereum · Base · Solana · Any EVM chain          │
│   EIP-7702 · Coinbase Agentic Wallets               │
│   Chainlink · x402 · DeFi protocols                │
│   DAO governance · NFT markets · Payment rails     │
└─────────────────────────────────────────────────────┘
```

---

## Quick Start

```bash
git clone https://github.com/Grokipaedia/iba-onchain-guard.git
cd iba-onchain-guard
pip install -r requirements.txt

# DeFi trading agent demo
python guard.py --config defi-trading.iba.yaml --demo

# Payment agent demo
python guard.py --config payment-agent.iba.yaml --demo

# Run all 6 onchain track demos
python guard.py --all

# Gate-check a single action with USD value
python guard.py "swap_token ETH to USDC" --config defi-trading.iba.yaml --value 500

# Safe hollowing
python guard.py "wallet_address private_key portfolio" --hollow medium
```

---

## Six Onchain Configurations

| Config | Track | Primary Kill Threshold |
|--------|-------|----------------------|
| [`defi-trading.iba.yaml`](defi-trading.iba.yaml) | DeFi · Swap · Liquidity · Yield | Drain wallet / MEV exploit |
| [`wallet-agent.iba.yaml`](wallet-agent.iba.yaml) | Wallet · Transfer · Approve · Sign | Private key export |
| [`payment-agent.iba.yaml`](payment-agent.iba.yaml) | x402 · Stablecoin · Recurring | Bulk unauthorized payment |
| [`dao-voting.iba.yaml`](dao-voting.iba.yaml) | DAO · Vote · Delegate · Execute | Unauthorized treasury transfer |
| [`nft-agent.iba.yaml`](nft-agent.iba.yaml) | NFT · Mint · List · Transfer | Malicious operator approval |
| [`default-onchain.iba.yaml`](default-onchain.iba.yaml) | Platform-agnostic base | Account takeover |

---

## Gate Logic

```
Valid human intent certificate?            → PROCEED
Action within declared scope?              → PROCEED
Transaction within financial limits?       → PROCEED
Session cap not exceeded?                  → PROCEED
Action in denied list?                     → BLOCK
Outside declared scope (DENY_ALL)?         → BLOCK
Kill threshold triggered?                  → TERMINATE + LOG
Certificate expired?                       → BLOCK
No certificate present?                    → BLOCK
```

**No cert = No onchain action.**

---

## Authorization Events

| Action | Without IBA | With IBA |
|--------|-------------|---------|
| Swap declared tokens | Implicit — any amount | Explicit — declared pair · tx limit |
| Add liquidity | Implicit | Declared pool · session cap |
| Transfer funds | Implicit — any recipient | Declared recipients only |
| x402 payment | Implicit — any merchant | Declared merchants only |
| DAO vote | Implicit | Declared proposals only |
| Treasury execution | No boundary | Requires re-cert |
| Undeclared protocol | No boundary | FORBIDDEN — BLOCK |
| Private key export | No boundary | TERMINATE |
| Drain wallet | No boundary | TERMINATE |
| MEV exploit | No boundary | TERMINATE |

---

## Financial Limits — Cert-Enforced

```yaml
financial_limits:
  max_single_tx_usd: 10000      # Block any single tx above this
  max_session_usd: 50000        # Block when session total exceeded
  slippage_tolerance_pct: 1.0   # DeFi slippage limit
  declared_protocols:           # Only these protocols allowed
    - uniswap_v3
    - aave_v3
    - compound_v3
```

The cert declares the financial boundary — not the agent's runtime logic. The gate enforces it before the transaction reaches the chain.

---

## EIP-7702 + IBA

Ethereum's EIP-7702 grants temporary, restricted permission to an agent for a single transaction. IBA is the authorization layer upstream of EIP-7702 — the signed cert that declares what the EIP-7702 session is permitted to do before the session opens.

```
Human signs .iba.yaml        → IBA cert issued
IBA gate validates cert      → EIP-7702 session opens
Agent executes transaction   → Audit log entry written
EIP-7702 permission expires  → Session ends cleanly
```

IBA and EIP-7702 are complementary. IBA governs intent. EIP-7702 enforces execution scope at the protocol level.

---

## x402 Payment Authorization

x402 is Coinbase's payment protocol for AI agents. Every x402 payment requires:
1. A declared merchant in the cert scope
2. Payment within the per-transaction and daily limits
3. Gate check before the HTTP 402 response is processed

```yaml
# payment-agent.iba.yaml
scope:
  - x402_payment_declared_merchant
financial_limits:
  max_single_payment_usd: 1000
  max_daily_usd: 10000
```

An agent that receives an x402 402 response from an undeclared merchant — BLOCK. The payment does not execute.

---

## Regulatory Alignment

**EU AI Act** — Autonomous financial agents are high-risk. IBA enforces human oversight architecturally.

**FATF Travel Rule** — Virtual asset transfers require originator and beneficiary information. IBA cert is the authorization record.

**EU Funds Transfer Regulation** — Stablecoin payments require identity verification. IBA principal field carries the authorization reference.

**MiCA** — EU crypto-asset regulation covering autonomous trading agents. IBA provides the audit trail MiCA requires.

**IBA priority date: February 5, 2026.** Predates all known onchain AI agent authorization framework deployments.

---

## Related Repos

| Repo | Track |
|------|-------|
| [iba-governor](https://github.com/Grokipaedia/iba-governor) | Core gate · any agent |
| [iba-social-guard](https://github.com/Grokipaedia/iba-social-guard) | Social · 6 platform configs |
| [iba-digital-worker-guard](https://github.com/Grokipaedia/iba-digital-worker-guard) | 19 AI models · parallel routing |
| [iba-grok-desktop-guard](https://github.com/Grokipaedia/iba-grok-desktop-guard) | Grok Build + Computer |
| [iba-neural-guard](https://github.com/Grokipaedia/iba-neural-guard) | BCI · 6 Neuralink clinical tracks |

---

## Live Demo

**governinglayer.com/governor-html/**

Edit the cert. Run any onchain action. ALLOW · BLOCK · TERMINATE.

**AgentialOnChain.com**

The hub for IBA onchain agent governance.

---

## Patent & Standards Record

```
Patent:   GB2603013.0 (Pending) · UK IPO · Filed February 10, 2026
WIPO DAS: Confirmed April 15, 2026 · Access Code C9A6
PCT:      150+ countries · Protected until August 2028
IETF:     draft-williams-intent-token-00 · CONFIRMED LIVE
          datatracker.ietf.org/doc/draft-williams-intent-token/
NIST:     13 filings · NIST-2025-0035
NCCoE:    10 filings · AI Agent Identity & Authorization
```

---

## Acquisition Enquiries

IBA Intent Bound Authorization is available for acquisition.

**Jeffrey Williams**
IBA@intentbound.com
IntentBound.com · AgentialOnChain.com
Patent GB2603013.0 Pending · WIPO DAS C9A6 · IETF draft-williams-intent-token-00
