# 02 - Missing Authority / Signer Check

## Vulnerability Name
**Missing Authority Check / Signer Verification Bypass**

## Summary

This vulnerability occurs when a program checks that an account's pubkey matches an expected value, but fails to verify that the account actually **signed** the transaction. An attacker can pass anyone's pubkey as an account without their consent, bypassing authorization checks.

## Vulnerable Behavior

### Vulnerability 1: Pubkey Check Without Signature

The `vulnerable_update_fee` instruction checks the admin's pubkey but not their signature:

```rust
// ❌ VULNERABLE: Checks pubkey equality, not signature
require!(
    config.admin == ctx.accounts.new_admin.key(),
    ConfigError::Unauthorized
);

// new_admin is AccountInfo, not Signer!
pub new_admin: AccountInfo<'info>,
```

**Attack Flow:**
1. Attacker identifies the stored admin pubkey
2. Attacker calls `vulnerable_update_fee` with:
   - `new_admin` = legitimate admin's pubkey (not signing)
   - `caller` = attacker's pubkey (is signing)
3. The pubkey check passes, but admin never authorized it!
4. Attacker changes fees to any value

### Vulnerability 2: No Authority Check At All

The `vulnerable_transfer_admin` instruction has zero authorization:

```rust
// ❌ CATASTROPHIC: No checks whatsoever
pub fn vulnerable_transfer_admin(ctx: Context<...>, new_admin: Pubkey) -> Result<()> {
    config.admin = new_admin;  // Anyone can become admin!
}
```

**Attack Flow:**
1. Attacker calls `vulnerable_transfer_admin(attacker_pubkey)`
2. Attacker is now the admin
3. Attacker has complete control of the protocol

## Real-World Context

### Solend Auth Bypass Attempt (August 2021)
> "An attacker exploited an insecure authentication check in Solend's `UpdateReserveConfig` function. The attacker bypassed admin checks by creating a new lending market and passing it as an account they owned, enabling unauthorized updates to reserve configurations."

The attacker manipulated account inputs to bypass authority checks, nearly stealing $2M. The pattern is identical to our `vulnerable_update_fee` - checking account data without verifying signatures.

### Audius Governance Exploit ($6.1M - July 2022)
> "A vulnerability in Audius' governance program allowed an attacker to submit and execute malicious proposals, bypassing proper validation. The attacker reconfigured treasury permissions, transferring 18.5 million AUDIO tokens."

Governance systems without proper signer verification allow attackers to submit malicious proposals and execute unauthorized actions.

### Synthetify DAO Exploit ($230K - October 2023)
> "An attacker exploited Synthetify's inactive DAO by creating and voting on malicious governance proposals... using their own tokens to meet the voting quorum unnoticed."

When DAOs don't properly verify authority and signatures, attackers can take control through carefully crafted transactions.

## Fix Explanation

### Fix 1: Use `Signer` Type

```rust
// ✅ SECURE: admin must be a Signer
pub admin: Signer<'info>,
```

The `Signer` type in Anchor automatically verifies that the account signed the transaction. Combined with `has_one`:

```rust
#[account(
    has_one = admin @ ConfigError::Unauthorized
)]
pub config: Account<'info, Config>,

// This verifies:
// 1. admin signed the transaction (Signer type)
// 2. config.admin == admin.key() (has_one constraint)
```

### Fix 2: Two-Step Authority Transfer

For critical authority changes, use a two-step process:

```rust
pub fn secure_nominate_admin(ctx: Context<...>, new_admin: Pubkey) -> Result<()> {
    // Current admin nominates (must sign)
    config.pending_admin = Some(new_admin);
}

pub fn secure_accept_admin(ctx: Context<...>) -> Result<()> {
    // New admin accepts (must sign)
    require!(config.pending_admin == Some(ctx.accounts.new_admin.key()));
    config.admin = ctx.accounts.new_admin.key();
    config.pending_admin = None;
}
```

**Benefits:**
- Prevents accidental transfers to wrong addresses
- Requires explicit consent from new admin
- Cannot be completed in a single transaction
- Provides time for detection and intervention

### Why These Fixes Work

| Attack Vector | Vulnerable | Secure |
|--------------|------------|--------|
| Pass admin pubkey without signature | ❌ Accepted | ✅ Rejected (Signer) |
| Attacker signs as different account | ❌ Accepted | ✅ Rejected (has_one) |
| Direct admin takeover | ❌ Accepted | ✅ Rejected (two-step) |
| Social engineering single-tx transfer | ❌ Possible | ✅ Prevented (acceptance required) |

## Key Takeaway

> **Pubkey equality is NOT authorization.**
> 
> The fundamental rule: **Always use `Signer` for any account that authorizes an action.**
> 
> A pubkey check only verifies identity, not consent. Anyone can pass anyone else's pubkey as an account - only signature verification proves the owner authorized the transaction.

### Security Checklist for Authority

- [ ] Use `Signer<'info>` for all accounts that authorize actions
- [ ] Combine `has_one` with `Signer` for stored authority verification
- [ ] Implement two-step processes for critical authority transfers
- [ ] Never trust `AccountInfo` for authorization - only for read-only data
- [ ] Log authority changes for auditability

## The Signer vs AccountInfo Distinction

```rust
// ❌ DANGEROUS: Anyone can pass any pubkey
pub some_account: AccountInfo<'info>,

// ✅ SAFE: Only the owner of this pubkey can pass it
pub some_account: Signer<'info>,
```

**Remember:**
- `AccountInfo` = "Here's a pubkey" (no authorization)
- `Signer` = "I own this pubkey and I authorize this action"

## Running the Exploit Test

```bash
cd programs/02_missing_authority_check
anchor test
```

The test demonstrates:
1. Attacker changing fees without admin signature (exploit succeeds)
2. Attacker becoming admin without authorization (exploit succeeds)
3. Both attacks failing against secure versions
4. Two-step admin transfer working correctly

## Further Reading

- [Anchor Book: Signers](https://www.anchor-lang.com/docs/the-accounts-struct#signer)
- [Solana Docs: Transactions and Signatures](https://docs.solana.com/developing/programming-model/transactions)
- [Neodyme: Missing Signer Checks](https://blog.neodyme.io/posts/solana_common_pitfalls)
