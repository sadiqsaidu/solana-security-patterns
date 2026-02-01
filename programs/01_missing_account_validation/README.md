# 01 - Missing Account Validation

## Overview

This module demonstrates one of the most critical and recurring vulnerabilities in Solana programs: **Missing Account Validation**. When programs accept accounts without verifying ownership, type discriminators, or PDA derivation, attackers can substitute malicious data to hijack program logic.

---

## The Vulnerability

### Why This Matters

On Solana, the **caller controls which accounts are passed** to a program. Unlike traditional systems where data comes from trusted internal sources, Solana programs receive all inputs externally. This design grants attackers significant control over the data a program operates on.

A program must independently verify:

| Check | Purpose |
|-------|---------|
| **Owner** | Confirms the account is owned by the expected program |
| **Discriminator** | Ensures the account data is the expected type |
| **PDA Derivation** | Validates the account was derived with correct seeds |
| **Data Integrity** | Verifies stored values match expected relationships |

Without these checks, an attacker can craft fake accounts with arbitrary data and trick the program into trusting them.

---

## Program Architecture

This demo implements a simple SOL vault with four instructions:

| Instruction | Description |
|-------------|-------------|
| `initialize_vault` | Creates a per-user `Vault` account storing metadata and a `vault_pda` holding SOL |
| `deposit` | Transfers SOL from the owner into the `vault_pda` |
| `withdraw_insecure` | **Vulnerable** - Withdraws SOL without proper account validation |
| `withdraw_secure` | **Secure** - Withdraws SOL with full Anchor validation |

---

## Vulnerability Analysis

### The Insecure Pattern

The `withdraw_insecure` instruction accepts raw `AccountInfo` types and deserializes without validation:

```rust
#[derive(Accounts)]
pub struct WithdrawInsecure<'info> {
    // VULNERABLE: AccountInfo skips all Anchor safety checks
    /// CHECK: Unsafe. Any account data can be passed here.
    #[account(mut)] 
    pub vault: AccountInfo<'info>,
    
    // VULNERABLE: No seeds check to verify PDA derivation
    /// CHECK: Unsafe. No relationship to vault is enforced.
    #[account(mut)]
    pub vault_pda: AccountInfo<'info>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

The instruction then performs unchecked deserialization:

```rust
// Manually deserialize without checking account ownership
let vault_data = &mut ctx.accounts.vault.try_borrow_data()?;
let vault = Vault::try_deserialize_unchecked(&mut &vault_data[..])?;
```

### What Goes Wrong

| Missing Check | Consequence |
|---------------|-------------|
| No owner verification | Account may belong to a different program or the attacker |
| No discriminator check | Data might not represent a `Vault` at all |
| No PDA seeds validation | `vault_pda` can be any account, including a victim's PDA |
| Unchecked deserialization | Attacker-crafted bytes are trusted as valid state |

---

## Exploit Mechanism

### Attack Prerequisites
1. A victim has deposited SOL into their legitimate `vault_pda`
2. The attacker knows the victim's public key (to locate their PDA)

### Attack Steps

```
Step 1: Locate Target
---------------------------------------------------------------
Attacker finds a victim's vault_pda with deposited SOL

Step 2: Craft Fake Vault
---------------------------------------------------------------
Attacker creates an account with fabricated Vault data:
  - owner = attacker's pubkey (passes authority check)
  - balance = any amount (passes balance check)  
  - bump = calculated to derive victim's vault_pda

Step 3: Call withdraw_insecure
---------------------------------------------------------------
Attacker invokes the instruction with:
  - vault = fake vault account
  - vault_pda = victim's real PDA (with actual SOL)
  - authority = attacker (matches fake vault.owner)

Step 4: Exploit Succeeds
---------------------------------------------------------------
Program trusts fake data -> derives valid PDA signer
-> transfers victim's SOL to attacker
```

### Why This Works

The program uses data from the unverified fake vault to derive PDA signer seeds:

```rust
let seeds = &[
    b"vault_pda",
    vault.owner.as_ref(),  // Attacker's pubkey from fake vault
    &[vault.bump],          // Bump calculated to match victim's PDA
];
```

If the attacker correctly calculates the bump that derives the victim's `vault_pda`, the CPI transfer succeeds.

---

## Secure Implementation

The `withdraw_secure` instruction uses Anchor's built-in validation:

```rust
#[derive(Accounts)]
pub struct WithdrawSecure<'info> {
    // SECURE: Account wrapper validates Owner and Discriminator
    #[account(
        mut,
        seeds = [b"vault", owner.key().as_ref()],
        bump = vault.bump,
        has_one = owner @ VaultError::Unauthorized
    )]
    pub vault: Account<'info, Vault>,
    
    // SECURE: Seeds constraint validates PDA derivation
    #[account(
        mut,
        seeds = [b"vault_pda", owner.key().as_ref()],
        bump
    )]
    pub vault_pda: SystemAccount<'info>,
    
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

### Security Layers

| Constraint | Protection |
|------------|------------|
| `Account<'info, Vault>` | Verifies program ownership + 8-byte discriminator |
| `seeds = [...]` | Ensures PDA is derived from expected seeds |
| `bump = vault.bump` | Confirms stored bump matches derivation |
| `has_one = owner` | Enforces `vault.owner == owner.key()` |

---

## Real-World Exploits

Account validation failures have caused significant losses across the Solana ecosystem:

### 2021

| Incident | Loss | Description |
|----------|------|-------------|
| **Solend Auth Bypass (Aug 2021)** | $16K (mitigated) | Attacker bypassed admin checks by creating a new lending market and passing it as an account they controlled. This enabled unauthorized updates to reserve configurations, lowering liquidation thresholds and inflating bonuses. The flaw was in the `UpdateReserveConfig` function's insecure authentication check. |

### 2022

| Incident | Loss | Description |
|----------|------|-------------|
| **Wormhole Bridge (Feb 2022)** | $326M (reimbursed) | A signature verification flaw allowed attackers to forge Guardian signatures by bypassing account validation. The program failed to verify the authenticity of the signature account, enabling unauthorized minting of 120,000 wETH. |
| **Cashio (Mar 2022)** | $52.8M | Missing validation of the `mint` field in the `saber_swap.arrow` account allowed attackers to pass fake collateral accounts with worthless tokens. The program trusted the unverified account data, enabling an "infinite mint glitch" of CASH tokens. |
| **Crema Finance (Jul 2022)** | $8.8M | Attackers created a fake tick account that bypassed owner verification in the CLMM protocol. The program's failure to validate account ownership allowed manipulation of fee data, draining liquidity pools via flash loans. |
| **Audius (Jul 2022)** | $6.1M | The governance program accepted malicious proposals without proper validation. Attackers exploited missing checks to reconfigure treasury permissions and drain funds. |

### 2023

| Incident | Loss | Description |
|----------|------|-------------|
| **Synthetify DAO (Oct 2023)** | $230K | Attackers exploited an inactive DAO by submitting governance proposals that bypassed validation. The token-based voting system lacked proper scrutiny mechanisms, allowing a malicious proposal to transfer treasury funds. |

### 2025

| Incident | Loss | Description |
|----------|------|-------------|
| **Loopscale (Apr 2025)** | $5.8M (recovered) | Oracle manipulation in the pricing mechanism for RateX PT collateral allowed attackers to inflate token values. The program failed to validate the integrity of price feed accounts, enabling undercollateralized loans. |

### Pattern Analysis

These exploits share common characteristics:

1. **Trusting Caller-Provided Accounts** - Programs assumed passed accounts were legitimate
2. **Missing Owner Checks** - Accounts weren't verified as program-owned
3. **No Discriminator Validation** - Data type wasn't confirmed before deserialization
4. **Insufficient Relationship Checks** - Connections between accounts weren't enforced

---

## Security Checklist

When building Solana programs, verify each account:

- [ ] Use `Account<'info, T>` instead of `AccountInfo` for program-owned data
- [ ] Apply `seeds` + `bump` constraints for all PDA accounts
- [ ] Use `has_one` or explicit key comparisons for account relationships
- [ ] Prefer `Program<'info, T>` for CPI target programs
- [ ] Avoid `try_deserialize_unchecked` on untrusted accounts
- [ ] Validate all fields that affect program logic (authority, mint, etc.)

---

## Further Reading

- [Anchor Book: Account Constraints](https://www.anchor-lang.com/docs/account-constraints)
- [Solana Cookbook: PDAs](https://solanacookbook.com/core-concepts/pdas.html)
- [Neodyme: Account Confusion](https://blog.neodyme.io/posts/solana_common_pitfalls)
- [Helius: A Hitchhiker's Guide to Solana Program Security](https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
