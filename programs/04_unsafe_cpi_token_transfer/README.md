# 04 - Unsafe CPI Token Transfer

## Overview

This module demonstrates a critical vulnerability in Solana programs: **Unsafe CPI Token Transfer**. When programs perform Cross-Program Invocations (CPIs) to transfer tokens without validating that the destination account belongs to the intended recipient, attackers can redirect funds to their own accounts.

---

## The Vulnerability

### Why This Matters

CPIs allow programs to call other programs, including the SPL Token program for transfers. If a program blindly accepts any account as the transfer destination without verifying ownership, attackers can substitute their own token account and steal funds meant for legitimate recipients.

| Account Type | What It Provides | Security Level |
|--------------|------------------|----------------|
| `AccountInfo` | Raw account data, no validation | None - accepts any account |
| `Account<TokenAccount>` | Validated token account structure | Partial - structure only |
| `Account<TokenAccount>` + constraint | Validated structure + owner check | Secure - verified recipient |

The critical distinction: **Accepting an account is NOT the same as validating it.**

---

## Program Architecture

This demo implements a payment system with a stored recipient:

| Instruction | Validation | Description |
|-------------|------------|-------------|
| `initialize` | N/A | Creates state PDA with authority and recipient |
| `vulnerable_transfer` | None | **Vulnerable** - Transfers to any passed account |
| `secure_transfer` | `to.owner == state.recipient` | **Secure** - Verifies destination owner |

---

## Vulnerability Analysis

### The Flaw

The `vulnerable_transfer` instruction accepts any account as the destination without verifying it belongs to the intended recipient:

```rust
#[derive(Accounts)]
pub struct VulnerableTransfer<'info> {
    #[account(seeds = [b"state"], bump)]
    pub state: Account<'info, State>,

    /// CHECK: Unsafe. We don't check if this is a valid token account or who owns it.
    #[account(mut)]
    pub from: AccountInfo<'info>,
    
    /// CHECK: Unsafe. This allows the attacker to pass their OWN account here.
    #[account(mut)]
    pub to: AccountInfo<'info>,
    
    pub authority: Signer<'info>,
    pub token_program: AccountInfo<'info>,
}

pub fn vulnerable_transfer(ctx: Context<VulnerableTransfer>, amount: u64) -> Result<()> {
    let cpi_accounts = Transfer {
        from: ctx.accounts.from.to_account_info(),
        to: ctx.accounts.to.to_account_info(), // <--- NO CHECK: Is this really the recipient?
        authority: ctx.accounts.authority.to_account_info(),
    };
    
    let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
    token::transfer(cpi_ctx, amount)?;
    
    Ok(())
}
```

### What Goes Wrong

| Issue | Consequence |
|-------|-------------|
| `AccountInfo` for token accounts | No structure or ownership validation |
| No owner verification | Attacker substitutes their own account |
| State has recipient but unused | Intended recipient is ignored |
| `AccountInfo` for token program | Could be a fake program |

---

## Exploit Mechanism

### Attack: Fund Redirection

```
Step 1: Setup
---------------------------------------------------------------
Protocol initializes state with:
  - state.recipient = Alice (legitimate recipient)
  - state.authority = Protocol

Step 2: Identify Target
---------------------------------------------------------------
Attacker observes a pending transfer of 1000 tokens to Alice

Step 3: Craft Malicious Transaction
---------------------------------------------------------------
Attacker calls vulnerable_transfer with:
  - from = source token account (valid)
  - to = ATTACKER's token account (not Alice's!)
  - amount = 1000

Step 4: Exploit Succeeds
---------------------------------------------------------------
  - No validation that 'to' belongs to state.recipient
  - Tokens go to attacker instead of Alice
  - Alice receives nothing
```

### Attacker Advantages

| Advantage | Description |
|-----------|-------------|
| Simple substitution | Just pass a different account |
| No special permissions | Anyone can call the instruction |
| Undetectable on-chain | Transfer looks legitimate |
| Repeatable | Can intercept every transfer |

---

## Secure Implementation

The `secure_transfer` instruction validates that the destination account belongs to the intended recipient:

```rust
#[derive(Accounts)]
pub struct SecureTransfer<'info> {
    #[account(seeds = [b"state"], bump)]
    pub state: Account<'info, State>,

    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    
    // SECURE: Anchor checks that this account is owned by the legitimate recipient
    #[account(
        mut,
        constraint = to.owner == state.recipient // <---  THE FIX
    )]
    pub to: Account<'info, TokenAccount>,
    
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
}
```

### Security Layers

| Protection | Benefit |
|------------|---------|
| `Account<TokenAccount>` | Validates SPL Token account structure |
| `constraint = to.owner == state.recipient` | Verifies destination owner matches intended recipient |
| `Program<Token>` | Ensures real SPL Token program is called |

---

## Real-World Exploits

Unsafe CPI patterns and unvalidated token accounts have enabled significant exploits across the Solana ecosystem:

### 2022

| Incident | Loss | Description |
|----------|------|-------------|
| **Cashio (Mar 2022)** | $52.8M | Attacker passed fake collateral accounts in CPI calls. The program validated account existence but not ownership, allowing minting with worthless collateral. |
| **Crema Finance (Jul 2022)** | $8.8M | Attacker created fake tick accounts and used flash loans to manipulate fee data. CPI calls trusted the passed accounts without proper owner verification. |
| **Raydium (Dec 2022)** | $4.4M | Compromised admin key allowed attacker to call `withdrawPNL` function. The exploit used CPIs with manipulated fee parameters to drain liquidity pools. |

### 2023

| Incident | Loss | Description |
|----------|------|-------------|
| **Cypher Protocol (Aug 2023)** | $1.04M | Attackers exploited the protocol during a hacker house event, draining funds through improperly validated CPI interactions. |

### Pattern Analysis

These exploits share common characteristics:

1. **Unvalidated Accounts** - Programs accepted accounts without verifying ownership
2. **Missing Constraints** - No checks that passed accounts matched stored state
3. **Trusted CPI Calls** - Programs assumed CPI targets would validate accounts
4. **AccountInfo Misuse** - Raw account types bypassed Anchor's validation

---

## CPI Security Patterns

### Vulnerable Patterns

| Pattern | Risk | Example |
|---------|------|---------|
| Raw `AccountInfo` | No validation | `pub to: AccountInfo<'info>` |
| Missing owner check | Wrong recipient | No constraint on `to.owner` |
| Untyped token program | Fake program | `pub token_program: AccountInfo` |

### Secure Patterns

| Use Case | Recommended Approach |
|----------|----------------------|
| Token account destination | `Account<TokenAccount>` + owner constraint |
| Token account source | `Account<TokenAccount>` + authority check |
| Token program | `Program<'info, Token>` |
| Associated token account | Use `associated_token` constraint |

---

## Security Checklist

When implementing CPI token transfers:

- [ ] Use `Account<TokenAccount>` instead of `AccountInfo` for token accounts
- [ ] Add constraints verifying token account owners match expected parties
- [ ] Use `Program<Token>` instead of `AccountInfo` for token program
- [ ] Verify mint consistency across all token accounts
- [ ] Cross-reference passed accounts with stored state
- [ ] Never trust user-provided accounts without validation

---

## The AccountInfo vs Account<TokenAccount> Distinction

```rust
// DANGEROUS: Accepts any account, no validation
pub to: AccountInfo<'info>,

// SAFE: Validates structure and allows owner constraint
#[account(
    mut,
    constraint = to.owner == state.recipient
)]
pub to: Account<'info, TokenAccount>,
```

**Remember:**
- `AccountInfo` = "Here's an account" (no validation)
- `Account<TokenAccount>` = "Here's a valid SPL token account"
- `Account<TokenAccount>` + constraint = "Here's a valid token account owned by the expected party"

---

## Further Reading

- [Anchor Book: CPIs](https://www.anchor-lang.com/docs/cross-program-invocations)
- [SPL Token Program](https://spl.solana.com/token)
- [Neodyme: Solana Security Pitfalls](https://blog.neodyme.io/posts/solana_common_pitfalls)
- [Helius: A Hitchhiker's Guide to Solana Program Security](https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
