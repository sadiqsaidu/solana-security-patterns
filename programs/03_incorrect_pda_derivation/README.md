# 03 - Incorrect PDA Derivation

## Overview

This module demonstrates a critical vulnerability in Solana programs: **Incorrect PDA Derivation**. When Program Derived Addresses are derived from user-controlled strings (like usernames) instead of cryptographically unique identifiers (like public keys), attackers can frontrun legitimate users and claim their desired identities.

---

## The Vulnerability

### Why This Matters

PDAs are deterministically derived from seeds. If seeds are predictable and user-controlled, anyone can compute the same PDA address and claim it first. This creates a race condition where the first transaction wins, regardless of legitimacy.

| Seed Type | What It Produces | Security Level |
|-----------|------------------|----------------|
| User-controlled string | Global namespace collision | None - anyone can claim any name |
| User's public key | Unique per-user namespace | Secure - tied to signer identity |

The critical distinction: **User strings are NOT unique identifiers.**

---

## Program Architecture

This demo implements a user profile system with two instructions:

| Instruction | Seeds | Description |
|-------------|-------|-------------|
| `vulnerable_create_profile` | `[b"profile", username.as_bytes()]` | **Vulnerable** - Anyone can claim any username |
| `secure_create_profile` | `[b"profile_secure", authority.key().as_ref()]` | **Secure** - Each user has unique namespace |

---

## Vulnerability Analysis

### The Flaw

The `vulnerable_create_profile` instruction derives the PDA from a user-supplied username string:

```rust
#[derive(Accounts)]
#[instruction(username: String)]
pub struct VulnerableCreateProfile<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + 32 + 4 + 32 + 1, 
        // BAD SEEDS: Only uses the string. Anyone can claim "alice".
        seeds = [b"profile", username.as_bytes()],
        bump
    )]
    pub profile: Account<'info, Profile>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

pub fn vulnerable_create_profile(ctx: Context<VulnerableCreateProfile>, username: String) -> Result<()> {
    let profile = &mut ctx.accounts.profile;
    profile.authority = ctx.accounts.payer.key();
    profile.username = username;
    profile.bump = ctx.bumps.profile;
    Ok(())
}
```

### What Goes Wrong

| Issue | Consequence |
|-------|-------------|
| Username as seed | PDA address is predictable by anyone |
| No signer binding | PDA not tied to any specific user |
| First-come-first-served | Race condition determines ownership |
| Permanent lockout | Victim can never claim that username |

---

## Exploit Mechanism

### Attack: Username Squatting

```
Step 1: Identify Target
---------------------------------------------------------------
Attacker observes victim's desired username via:
  - Mempool monitoring
  - Social media announcements
  - Public forum discussions

Step 2: Derive PDA
---------------------------------------------------------------
Attacker computes: seeds = [b"profile", b"alice"]
  - Deterministic: same seeds = same address
  - Zero cost to predict

Step 3: Frontrun Transaction
---------------------------------------------------------------
Attacker calls vulnerable_create_profile("alice") with:
  - Higher priority fee to land before victim
  - Attacker becomes profile.authority

Step 4: Exploit Succeeds
---------------------------------------------------------------
  - Attacker owns the "alice" profile PDA
  - Victim's transaction fails (account already exists)
  - Victim permanently locked out
```

### Attacker Advantages

| Advantage | Description |
|-----------|-------------|
| Zero cost to predict | Seeds are public, derivation is deterministic |
| Scalable attack | Can squat on many popular names cheaply |
| Irreversible damage | Victim cannot recover the username |
| Extortion potential | Attacker can demand payment for transfer |

---

## Secure Implementation

The `secure_create_profile` instruction uses the signer's public key as the seed:

```rust
#[derive(Accounts)]
#[instruction(username: String)]
pub struct SecureCreateProfile<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 4 + 32 + 1,
        // GOOD SEEDS: Uses the signer's key. "alice" is just data.
        seeds = [b"profile_secure", authority.key().as_ref()],
        bump
    )]
    pub profile: Account<'info, Profile>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

### Security Layers

| Protection | Benefit |
|------------|---------|
| Authority key as seed | Each user has unique PDA namespace |
| `Signer<'info>` | Only the key owner can create their profile |
| Username as data | Display name stored, not used for derivation |
| No frontrunning | Attacker cannot predict victim's PDA |

---

## Real-World Exploits

Incorrect PDA derivation and account validation flaws have enabled significant exploits across the Solana ecosystem:

### 2021

| Incident | Loss | Description |
|----------|------|-------------|
| **Solend Auth Bypass (Aug 2021)** | $2M at risk | Attacker bypassed admin checks by creating a new lending market and passing it as an account they controlled. The program failed to verify the account was derived from expected seeds, allowing unauthorized reserve configuration changes. |

### 2022

| Incident | Loss | Description |
|----------|------|-------------|
| **Cashio (Mar 2022)** | $52.8M | Attacker passed fake collateral accounts that satisfied PDA structure requirements but contained worthless data. The program verified account existence but not proper derivation, enabling an infinite mint exploit. |
| **Crema Finance (Jul 2022)** | $8.8M | Attacker created fake tick account PDAs with manipulated fee data. The program trusted account existence without verifying derivation matched expected parameters, allowing excessive fee claims via flash loans. |

### Pattern Analysis

These exploits share common characteristics:

1. **Predictable Seeds** - PDAs derived from user-controlled or public data
2. **Missing Derivation Checks** - Programs trusted account existence over proper derivation
3. **No Authority Binding** - PDAs not tied to authorized signers
4. **Fake Account Injection** - Attackers created accounts that looked valid but contained malicious data

---

## Seed Design Patterns

### Vulnerable Patterns

| Pattern | Risk | Example |
|---------|------|---------|
| User string only | Squatting | `[b"profile", username]` |
| Resource name only | Collision | `[b"pool", pool_name]` |
| No unique identifier | Namespace conflict | `[b"config"]` |

### Secure Patterns

| Use Case | Recommended Seeds |
|----------|-------------------|
| User profile | `[b"profile", user.key()]` |
| User's named resource | `[b"vault", user.key(), name]` |
| Global singleton | `[b"config", program_id]` |
| Two-party escrow | `[b"escrow", party_a.key(), party_b.key(), id]` |

---

## Security Checklist

When implementing PDA derivation:

- [ ] Include signer's public key in seeds for user-specific accounts
- [ ] Store user-controlled strings as data, not as seeds
- [ ] Use unique identifiers in seeds for global resources
- [ ] Always use canonical bump via `ctx.bumps.*`
- [ ] Verify account content, not just existence
- [ ] Document seed structure for each PDA type

---

## The String vs Pubkey Distinction

```rust
// DANGEROUS: Anyone can claim any username
seeds = [b"profile", username.as_bytes()]

// SAFE: Each user has unique namespace
seeds = [b"profile_secure", authority.key().as_ref()]
```

**Remember:**
- User-controlled strings = **stored data** (display purposes)
- User public keys = **PDA seeds** (identity binding)

---

## Further Reading

- [Anchor Book: PDAs](https://www.anchor-lang.com/docs/pdas)
- [Solana Cookbook: PDAs](https://solanacookbook.com/core-concepts/pdas.html)
- [Neodyme: Solana Security Pitfalls](https://blog.neodyme.io/posts/solana_common_pitfalls)
- [Helius: A Hitchhiker's Guide to Solana Program Security](https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
