# 01 - Missing Account Validation

## Vulnerability Name
**Missing Account Validation / Unverified Account Ownership**

## Summary

This vulnerability occurs when a program accepts accounts without verifying that they:
1. Are owned by the expected program
2. Contain the expected data structure (discriminator)
3. Were derived from expected seeds (for PDAs)

An attacker can exploit this by passing fake accounts with arbitrary data, causing the program to operate on malicious data while affecting legitimate accounts.

## Vulnerable Behavior

The `vulnerable_withdraw` instruction uses `AccountInfo` instead of Anchor's `Account<'info, Vault>` type:

```rust
// ❌ VULNERABLE: Accepts ANY account
pub vault: AccountInfo<'info>,
```

This means:
- **No ownership check**: The account could be owned by any program
- **No discriminator check**: The data structure is not verified
- **No PDA derivation check**: The account could be attacker-created

The instruction then manually deserializes data and trusts whatever it finds:

```rust
// ❌ Trusts user-supplied data blindly
let vault = &ctx.accounts.vault;
require!(vault.owner == ctx.accounts.withdrawer.key(), ...);
```

### Attack Flow

1. **Attacker identifies target**: Victim's vault_pda contains 1 SOL
2. **Attacker creates fake vault**: Account with `owner = attacker_pubkey`, `balance = 100 SOL`
3. **Attacker calls vulnerable_withdraw** with:
   - `vault` = fake vault (passes owner/balance checks)
   - `vault_pda` = victim's real vault_pda (contains real SOL)
4. **Result**: Checks pass on fake data, but real SOL is transferred to attacker

## Real-World Context

This vulnerability pattern appeared in several major Solana exploits:

### Wormhole Bridge ($326M - February 2022)
> "A signature verification flaw in Wormhole's Solana-side program allowed an attacker to forge a valid signature, bypassing Guardian validation."

The attacker passed fake accounts that bypassed validation, similar to how our exploit passes a fake vault account.

### Cashio ($52.8M - March 2022)
> "A vulnerability in Cashio's program collateral validation allowed an attacker to mint 2 billion CASH tokens using fake accounts with worthless collateral. The flaw was due to a missing validation of the mint field."

The Cashio exploit is almost identical to our demonstration—the attacker created fake collateral accounts that the program trusted without proper verification.

### Crema Finance ($8.8M - July 2022)
> "A vulnerability in Crema Finance's CLMM allowed an attacker to create a fake tick account, bypassing owner verification."

Again, fake accounts bypassing validation led to massive fund theft.

## Fix Explanation

The `secure_withdraw` instruction uses multiple layers of validation:

### 1. Account Type Verification
```rust
// ✅ Account<'info, Vault> automatically verifies:
//    - Account is owned by this program
//    - Account has correct discriminator
pub vault: Account<'info, Vault>,
```

### 2. PDA Seed Derivation
```rust
// ✅ Verifies the vault was derived from expected seeds
#[account(
    seeds = [b"vault", owner.key().as_ref()],
    bump = vault.bump,
)]
```

### 3. Relationship Validation
```rust
// ✅ Verifies vault.owner matches the provided owner account
has_one = owner @ VaultError::UnauthorizedWithdrawal
```

### 4. Corresponding PDA Verification
```rust
// ✅ Verifies vault_pda corresponds to the same owner
#[account(
    seeds = [b"vault_pda", owner.key().as_ref()],
    bump
)]
pub vault_pda: SystemAccount<'info>,
```

### Why This Works

| Attack Vector | Vulnerable | Secure |
|--------------|------------|--------|
| Fake account with arbitrary data | ❌ Accepted | ✅ Rejected (ownership) |
| Account owned by wrong program | ❌ Accepted | ✅ Rejected (discriminator) |
| Mismatched vault/vault_pda | ❌ Accepted | ✅ Rejected (seeds) |
| Wrong owner | ❌ Accepted | ✅ Rejected (has_one) |

## Key Takeaway

> **Never use `AccountInfo` for accounts containing program-specific data.**
> 
> Always use `Account<'info, T>` which automatically verifies:
> - The account is owned by your program
> - The account has the correct discriminator
> - The account data deserializes correctly
> 
> Combine with `seeds`, `bump`, and `has_one` constraints for complete validation.

### Security Checklist for Account Validation

- [ ] Use `Account<'info, T>` instead of `AccountInfo` for program accounts
- [ ] Add `seeds` constraint for all PDAs
- [ ] Use `has_one` to verify account relationships
- [ ] Validate that derived addresses (vault_pda) correspond to metadata accounts (vault)
- [ ] Never trust user-supplied account data without verification

## Running the Exploit Test

```bash
cd programs/01_missing_account_validation
anchor test
```

The test demonstrates:
1. Setting up a victim's vault with 1 SOL
2. The vulnerability in `vulnerable_withdraw` (accepts fake accounts)
3. The security of `secure_withdraw` (rejects all attack vectors)

## Further Reading

- [Anchor Book: Account Constraints](https://www.anchor-lang.com/docs/account-constraints)
- [Solana Cookbook: PDAs](https://solanacookbook.com/core-concepts/pdas.html)
- [Neodyme: Account Confusion](https://blog.neodyme.io/posts/solana_common_pitfalls)
