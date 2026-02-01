# 02 - Missing Authority Check

## Overview

This module demonstrates a critical vulnerability in Solana programs: **Missing Authority/Signer Check**. When programs verify that an account's public key matches an expected value but fail to confirm that the account actually **signed** the transaction, attackers can impersonate authorized users without their consent.

---

## The Vulnerability

### Why This Matters

On Solana, anyone can pass any public key as an account to a program. The `Signer` type is the only mechanism that proves an account owner authorized the transaction. Without it, a pubkey check is merely identity verification, not authorization.

| Check Type | What It Proves | Security Level |
|------------|----------------|----------------|
| Pubkey equality | "This is account X" | None - anyone can pass any pubkey |
| `Signer` constraint | "Account X authorized this" | Secure - requires private key |

The critical distinction: **Pubkey equality is NOT authorization.**

---

## Program Architecture

This demo implements a protocol configuration system with three instructions:

| Instruction | Description |
|-------------|-------------|
| `initialize` | Creates the config PDA with an initial admin and fee |
| `vulnerable_update_fee` | **Vulnerable** - Checks pubkey but not signature |
| `vulnerable_transfer_admin` | **Vulnerable** - No authorization check at all |
| `secure_update_fee` | **Secure** - Uses `Signer` + `has_one` constraints |

---

## Vulnerability Analysis

### Vulnerability 1: Pubkey Check Without Signature

The `vulnerable_update_fee` instruction checks if the passed account matches the stored admin, but doesn't verify the admin signed:

```rust
#[derive(Accounts)]
pub struct VulnerableUpdateFee<'info> {
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,

    /// CHECK: Unsafe. This allows passing the admin's address without their signature.
    pub admin_account: AccountInfo<'info>,
}

pub fn vulnerable_update_fee(ctx: Context<VulnerableUpdateFee>, new_fee_bps: u16) -> Result<()> {
    let config = &mut ctx.accounts.config;

    // This passes if you send the admin's Public Key, even if they didn't sign!
    require!(
        config.admin == ctx.accounts.admin_account.key(),
        ConfigError::Unauthorized
    );

    config.fee_bps = new_fee_bps;
    Ok(())
}
```

### What Goes Wrong

| Issue | Consequence |
|-------|-------------|
| `AccountInfo` instead of `Signer` | No signature verification |
| Pubkey equality check only | Attacker can pass admin's pubkey without consent |
| Admin never signs | Unauthorized fee changes accepted |

### Vulnerability 2: No Authorization At All

The `vulnerable_transfer_admin` instruction has zero authorization checks:

```rust
#[derive(Accounts)]
pub struct VulnerableTransferAdmin<'info> {
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub caller: Signer<'info>,
}

pub fn vulnerable_transfer_admin(ctx: Context<VulnerableTransferAdmin>, new_admin: Pubkey) -> Result<()> {
    let config = &mut ctx.accounts.config;
    config.admin = new_admin;  // Anyone can become admin!
    Ok(())
}
```

---

## Exploit Mechanism

### Attack 1: Fee Manipulation

```
Step 1: Identify Target
---------------------------------------------------------------
Attacker reads the config account to find the admin pubkey

Step 2: Craft Malicious Transaction
---------------------------------------------------------------
Attacker calls vulnerable_update_fee with:
  - admin_account = legitimate admin's pubkey (not signing)
  - new_fee_bps = 999 (9.99% - malicious fee)

Step 3: Exploit Succeeds
---------------------------------------------------------------
Pubkey check passes -> Fee changed without admin consent
```

### Attack 2: Complete Takeover

```
Step 1: Call vulnerable_transfer_admin
---------------------------------------------------------------
Attacker calls with:
  - caller = attacker (signing)
  - new_admin = attacker's pubkey

Step 2: Exploit Succeeds
---------------------------------------------------------------
No authorization check -> Attacker is now admin
-> Complete protocol control
```

---

## Secure Implementation

The `secure_update_fee` instruction uses proper Anchor constraints:

```rust
#[derive(Accounts)]
pub struct SecureUpdateFee<'info> {
    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump,
        has_one = admin @ ConfigError::Unauthorized
    )]
    pub config: Account<'info, Config>,

    pub admin: Signer<'info>,  // Must sign the transaction
}
```

### Security Layers

| Constraint | Protection |
|------------|------------|
| `Signer<'info>` | Requires the admin's private key to sign |
| `has_one = admin` | Verifies `config.admin == admin.key()` |
| Combined | Only the stored admin who signs can update |

---

## Real-World Exploits

Missing authority checks have enabled significant exploits across the Solana ecosystem:

### 2021

| Incident | Loss | Description |
|----------|------|-------------|
| **Solend Auth Bypass (Aug 2021)** | $16K (mitigated) | Attacker exploited an insecure authentication check in Solend's `UpdateReserveConfig` function. By creating a new lending market and passing it as an account they controlled, the attacker bypassed admin checks and modified reserve configurations for USDC, SOL, ETH, and BTC. This allowed lowering liquidation thresholds and inflating liquidation bonuses. |

### 2022

| Incident | Loss | Description |
|----------|------|-------------|
| **Audius Governance (Jul 2022)** | $6.1M | Attackers submitted and executed malicious governance proposals without proper authorization. The governance program failed to properly validate proposal submission authority, allowing attackers to reconfigure treasury permissions and drain 18.5 million AUDIO tokens. |

### 2023

| Incident | Loss | Description |
|----------|------|-------------|
| **Synthetify DAO (Oct 2023)** | $230K | Attackers exploited an inactive DAO by creating and voting on malicious governance proposals. They submitted 10 proposals (9 harmless, 1 malicious) and used their own tokens to meet voting quorum, transferring treasury funds without proper authority verification. |

### 2024

| Incident | Loss | Description |
|----------|------|-------------|
| **Saga DAO (Jan 2024)** | $60K | The DAO's multisig wallet required only 1 of 12 confirmations, allowing an attacker to drain approximately $60,000 in SOL from the treasury. The low confirmation threshold meant a single compromised or malicious signer could authorize transactions. |
| **Pump.fun (May 2024)** | $1.9M (mitigated) | A former employee exploited their privileged withdrawal authority access to execute a flash loan attack. The program failed to revoke authority after the employee left, demonstrating the need for proper access control lifecycle management. |

### Pattern Analysis

These exploits share common characteristics:

1. **Pubkey Checks Without Signatures** - Programs verified identity but not authorization
2. **Missing Access Control** - No verification that callers had permission
3. **Weak Governance Thresholds** - Low quorum or confirmation requirements
4. **Stale Authority** - Failure to revoke access when no longer needed

---

## Security Checklist

When implementing authority checks:

- [ ] Use `Signer<'info>` for all accounts that authorize actions
- [ ] Combine `has_one` with `Signer` for stored authority verification
- [ ] Never use `AccountInfo` for authorization - only for read-only data
- [ ] Implement two-step processes for critical authority transfers
- [ ] Set appropriate thresholds for multisig operations
- [ ] Revoke access immediately when authority should be removed

---

## The Signer vs AccountInfo Distinction

```rust
// DANGEROUS: Anyone can pass any pubkey
pub some_account: AccountInfo<'info>,

// SAFE: Only the owner of this pubkey can pass it (they must sign)
pub some_account: Signer<'info>,
```

**Remember:**
- `AccountInfo` = "Here's a pubkey" (no authorization)
- `Signer` = "I own this pubkey and I authorize this action"

---

## Further Reading

- [Anchor Book: Signers](https://www.anchor-lang.com/docs/the-accounts-struct)
- [Solana Docs: Transactions and Signatures](https://docs.solana.com/developing/programming-model/transactions)
- [Neodyme: Missing Signer Checks](https://blog.neodyme.io/posts/solana_common_pitfalls)
- [Helius: A Hitchhiker's Guide to Solana Program Security](https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
