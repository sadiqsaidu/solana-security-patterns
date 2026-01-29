# Solana Security Patterns: An Educational Repository

> ⚠️ **WARNING: This repository contains intentionally vulnerable code for educational purposes only. DO NOT use any vulnerable patterns in production.**

## 🎯 Purpose

This repository teaches Anchor developers how Solana programs actually get exploited — not just how to write "correct" code. By studying real attack patterns side-by-side with their fixes, you'll develop the security intuition needed to build robust programs.

**This is NOT production code.** Some instructions are deliberately insecure to demonstrate common attack patterns found in real-world Solana exploits.

## 🧠 Why Anchor Abstractions Are Not Enough

Many developers assume that using Anchor automatically makes their programs secure. This is dangerously wrong.

Anchor provides helpful guardrails, but it **does not**:

- ✗ Automatically validate that accounts belong to the right owner
- ✗ Prevent you from trusting user-supplied account data
- ✗ Stop arithmetic overflows/underflows (without explicit checks)
- ✗ Validate CPI target programs automatically
- ✗ Ensure PDA seeds are collision-resistant
- ✗ Enforce business logic constraints

**Every exploit in this repository uses valid Anchor code.** The bugs come from incorrect assumptions, missing constraints, and incomplete validation — not from Anchor failures.

## 📚 Real-World Context

The vulnerability patterns demonstrated here are derived from actual Solana exploits, including:

| Incident | Loss | Pattern |
|----------|------|---------|
| **Wormhole Bridge** (Feb 2022) | $326M | Missing signature/account validation |
| **Cashio** (Mar 2022) | $52.8M | Missing collateral validation, infinite mint |
| **Mango Markets** (Oct 2022) | $116M | Oracle manipulation, unchecked state |
| **Crema Finance** (Jul 2022) | $8.8M | Fake tick account, owner verification bypass |
| **Slope Wallet** (Aug 2022) | $8M | Insecure key management |
| **Raydium** (Dec 2022) | $4.4M | Compromised authority, unsafe admin functions |

These patterns repeat across the ecosystem. Understanding them is essential for any serious Solana developer.

## 🗂️ Repository Structure

```
solana-security-patterns/
│
├── README.md                              # This file
├── Anchor.toml                            # Anchor workspace configuration
│
├── programs/
│   ├── 01_missing_account_validation/     # Vault exploit via unauthorized accounts
│   │   ├── src/lib.rs
│   │   ├── tests/exploit.ts
│   │   └── README.md
│   │
│   ├── 02_missing_authority_check/        # Config hijack via missing signer
│   │   ├── src/lib.rs
│   │   ├── tests/exploit.ts
│   │   └── README.md
│   │
│   ├── 03_incorrect_pda_derivation/       # PDA collision/hijack attacks
│   │   ├── src/lib.rs
│   │   ├── tests/exploit.ts
│   │   └── README.md
│   │
│   ├── 04_unsafe_cpi_token_transfer/      # Token theft via unchecked CPI
│   │   ├── src/lib.rs
│   │   ├── tests/exploit.ts
│   │   └── README.md
│   │
│   └── 05_integer_overflow_state_bug/     # Balance manipulation via arithmetic bugs
│       ├── src/lib.rs
│       ├── tests/exploit.ts
│       └── README.md
│
└── tests/                                 # Shared test utilities
    └── utils.ts
```

## 🚀 Getting Started

### Prerequisites

- [Rust](https://rustup.rs/) (latest stable)
- [Solana CLI](https://docs.solana.com/cli/install-solana-cli-tools) (v1.17+)
- [Anchor](https://www.anchor-lang.com/docs/installation) (v0.29+)
- [Node.js](https://nodejs.org/) (v18+)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/solana-security-patterns.git
cd solana-security-patterns

# Install dependencies
yarn install

# Build all programs
anchor build

# Run all exploit tests
anchor test
```

### Running Individual Examples

```bash
# Navigate to a specific example
cd programs/01_missing_account_validation

# Run that example's tests
anchor test --skip-local-validator
```

## 📖 How to Navigate the Examples

Each vulnerability folder contains:

1. **`src/lib.rs`** — The Anchor program with two instructions:
   - `vulnerable_*` — Intentionally insecure (exploitable)
   - `secure_*` — Properly fixed version

2. **`tests/exploit.ts`** — Demonstrates:
   - The exploit succeeding against the vulnerable instruction
   - The exploit failing against the secure instruction

3. **`README.md`** — Explains:
   - What the vulnerability is
   - How attackers exploit it
   - Real-world incidents with this pattern
   - How the fix prevents the attack

## 🔐 Vulnerability Patterns Covered

| # | Pattern | Attack Vector | Real-World Example |
|---|---------|---------------|-------------------|
| 01 | Missing Account Validation | Attacker supplies unauthorized account | Wormhole, Cashio |
| 02 | Missing Authority Check | Unauthorized user mutates state | Solend, Audius |
| 03 | Incorrect PDA Derivation | PDA hijack/collision | Crema Finance |
| 04 | Unsafe CPI Token Transfer | Token account owner not validated | Multiple DeFi exploits |
| 05 | Unsafe Arithmetic | Overflow/underflow manipulation | Nirvana Finance |

## 🎓 Learning Path

**Recommended order:**

1. **Start with Example 01** — Understand why "passing any account" is dangerous
2. **Move to Example 02** — Learn the difference between accounts and signers
3. **Study Example 03** — Understand PDA security assumptions
4. **Examine Example 04** — See why CPI requires careful validation
5. **Finish with Example 05** — Appreciate arithmetic edge cases

After each example:
- Read the code comments carefully
- Run the exploit tests
- Try modifying the attack
- Read the README for context

## 🛡️ Security Checklist

After studying this repository, always ask yourself:

- [ ] **Account Ownership**: Is this account owned by the expected program?
- [ ] **Signer Verification**: Is the right account signing this transaction?
- [ ] **PDA Seeds**: Are my PDA seeds unique and non-colliding?
- [ ] **CPI Targets**: Am I calling the program I think I'm calling?
- [ ] **Arithmetic Safety**: Am I using checked/saturating math?
- [ ] **Data Validation**: Do I trust any user-supplied data?
- [ ] **Authority Transfer**: Can critical authorities be updated safely?
- [ ] **Account Closure**: Are closed accounts properly invalidated?

## 📚 Further Reading

- [Solana Security Best Practices](https://docs.solana.com/developing/programming-model/security)
- [Anchor Book - Security](https://www.anchor-lang.com/docs/security)
- [Neodyme Blog - Solana Security](https://blog.neodyme.io/)
- [Sealevel Attacks Repository](https://github.com/coral-xyz/sealevel-attacks)
- [Soteria - Static Analysis for Solana](https://www.soteria.dev/)

## ⚖️ License

MIT License - Educational use encouraged.

## 🤝 Contributing

Contributions welcome! Please ensure any new vulnerability examples:
- Reference real-world exploit patterns
- Include working exploit tests
- Provide clear educational documentation

---

**Remember: Security is not a feature — it's a discipline. Study these patterns, internalize them, and build safer programs.**
