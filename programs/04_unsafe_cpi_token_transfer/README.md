# 04 - Unsafe CPI Token Transfer

## Vulnerability Name
**Unsafe Cross-Program Invocation (CPI) / Unvalidated Token Accounts**

## Summary

Cross-Program Invocations (CPIs) allow programs to call other programs. When performing token transfers via CPI, failing to validate:
1. Token account ownership
2. Token program identity
3. Mint consistency

...allows attackers to redirect funds to their own accounts or execute malicious code.

## Vulnerable Behavior

### Vulnerability 1: Unvalidated Token Account Owner

```rust
// ❌ VULNERABLE: AccountInfo accepts any account
pub recipient_token_account: AccountInfo<'info>,

// No verification that owner matches expected recipient!
token::transfer(ctx, amount)?;
```

**Attack (Fund Redirection):**
1. Splitter is configured: recipient = Alice
2. Attacker calls vulnerable_split_payment
3. Attacker passes their OWN token account as recipient_token_account
4. Funds meant for Alice go to Attacker

### Vulnerability 2: Unvalidated Token Program

```rust
// ❌ VULNERABLE: Could be any program
pub token_program: AccountInfo<'info>,
```

**Attack (Malicious Program Execution):**
1. Attacker deploys a fake "token program"
2. Passes it as token_program parameter
3. Fake program executes malicious logic
4. Could drain funds, manipulate state, etc.

### Vulnerability 3: Arbitrary CPI

```rust
// ❌ CATASTROPHIC: Call any program the user specifies
pub target_program: AccountInfo<'info>,

invoke(&instruction_to_target_program, &accounts)?;
```

This allows complete arbitrary code execution through your program.

## Real-World Context

### Wormhole Bridge ($326M - February 2022)
> "A signature verification flaw... allowed an attacker to forge a valid signature, bypassing Guardian validation."

While primarily a signature issue, the attack involved CPIs with spoofed accounts. The program trusted CPI data without proper verification.

### Crema Finance ($8.8M - July 2022)
> "A vulnerability in Crema Finance's CLMM allowed an attacker to create a fake tick account, bypassing owner verification. Using flash loans from Solend, the attacker manipulated transaction fee data."

The attack exploited CPI interactions where fake accounts were passed, similar to our demonstration where an attacker's token account replaces the legitimate recipient.

### Raydium ($4.4M - December 2022)
> "A Trojan horse attack compromised the private key of Raydium's Pool Owner account... The attacker used the `withdrawPNL` function to inflate and withdraw fees."

While a key compromise, the exploit involved CPIs that trusted account data without sufficient validation, allowing the attacker to drain funds.

## Fix Explanation

### Fix 1: Use Token Account Types

```rust
// ✅ SECURE: Account<TokenAccount> verifies:
// - Account is owned by SPL Token program
// - Account data is valid TokenAccount structure
pub recipient_token_account: Account<'info, TokenAccount>,
```

### Fix 2: Verify Token Account Owners

```rust
#[account(
    mut,
    // ✅ Verify the token account owner matches expected recipient
    constraint = recipient_token_account.owner == splitter.recipient 
        @ SplitterError::InvalidRecipient,
)]
pub recipient_token_account: Account<'info, TokenAccount>,
```

### Fix 3: Enforce Mint Consistency

```rust
#[account(
    mut,
    // ✅ Verify all accounts use the same token mint
    constraint = recipient_token_account.mint == source_token_account.mint 
        @ SplitterError::MintMismatch,
)]
pub recipient_token_account: Account<'info, TokenAccount>,
```

### Fix 4: Verify Token Program

```rust
// ✅ SECURE: Program<Token> verifies this is the real SPL Token program
pub token_program: Program<'info, Token>,
```

### Complete Secure Pattern

```rust
#[derive(Accounts)]
pub struct SecureSplitPayment<'info> {
    #[account(has_one = recipient)]
    pub splitter: Account<'info, Splitter>,
    
    // Source: owned by authority, same mint
    #[account(
        mut,
        constraint = source.owner == authority.key(),
        constraint = source.mint == recipient_ata.mint
    )]
    pub source: Account<'info, TokenAccount>,
    
    // Recipient: owned by splitter.recipient, same mint
    #[account(
        mut,
        constraint = recipient_ata.owner == splitter.recipient,
        constraint = recipient_ata.mint == source.mint
    )]
    pub recipient_ata: Account<'info, TokenAccount>,
    
    pub authority: Signer<'info>,
    
    // Verified token program
    pub token_program: Program<'info, Token>,
}
```

## Key Takeaway

> **CPIs are as dangerous as the accounts they operate on.**
> 
> Rule 1: **Never use `AccountInfo` for token accounts** - use `Account<TokenAccount>`
> 
> Rule 2: **Always verify token account owners** match expected parties
> 
> Rule 3: **Verify mint consistency** across all token accounts in a transaction
> 
> Rule 4: **Use `Program<Token>`** instead of `AccountInfo` for the token program
> 
> Rule 5: **Never allow arbitrary CPI targets** - hardcode or whitelist program IDs

### CPI Security Checklist

| Check | Vulnerable | Secure |
|-------|------------|--------|
| Token account type | `AccountInfo` | `Account<TokenAccount>` |
| Owner verification | None | `constraint = ata.owner == expected` |
| Mint verification | None | `constraint = a.mint == b.mint` |
| Token program | `AccountInfo` | `Program<Token>` |
| CPI target | User-provided | Hardcoded/Whitelisted |

## Attack Prevention Matrix

| Attack Vector | Prevention |
|--------------|------------|
| Redirect to attacker's account | Verify token account owner |
| Different token mint | Enforce mint consistency |
| Fake token program | Use `Program<Token>` |
| Arbitrary CPI execution | Hardcode program IDs |
| Spoofed account data | Use typed accounts |

## The AccountInfo vs Account<T> Distinction

```rust
// ❌ DANGEROUS: Accepts any account, no validation
pub some_token_account: AccountInfo<'info>,

// ✅ SAFE: Verifies SPL Token ownership and data structure
pub some_token_account: Account<'info, TokenAccount>,
```

With `Account<TokenAccount>`:
- Anchor verifies the account is owned by SPL Token program
- Anchor deserializes and validates TokenAccount structure
- You can add constraints on `owner`, `mint`, `amount`

## Running the Exploit Test

```bash
cd programs/04_unsafe_cpi_token_transfer
anchor test
```

The test demonstrates:
1. Attacker redirecting funds through vulnerable instruction
2. Mint mismatch attack blocked by secure version
3. Owner mismatch attack blocked by secure version
4. Legitimate payments succeeding with secure version

## Token Account Verification Patterns

### Pattern 1: Direct Owner Check
```rust
constraint = token_account.owner == expected_owner
```

### Pattern 2: Associated Token Account
```rust
#[account(
    associated_token::mint = mint,
    associated_token::authority = owner,
)]
pub ata: Account<'info, TokenAccount>,
```

### Pattern 3: PDA-Owned Token Account
```rust
#[account(
    token::mint = mint,
    token::authority = vault_pda,
)]
pub vault_tokens: Account<'info, TokenAccount>,
```

## Further Reading

- [Anchor Book: CPIs](https://www.anchor-lang.com/docs/cross-program-invocations)
- [SPL Token Program](https://spl.solana.com/token)
- [Neodyme: CPI Vulnerabilities](https://blog.neodyme.io/posts/solana_common_pitfalls)
