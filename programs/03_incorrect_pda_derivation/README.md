# 03 - Incorrect PDA Derivation

## Vulnerability Name
**Incorrect PDA Derivation / PDA Collision / PDA Squatting**

## Summary

Program Derived Addresses (PDAs) are deterministically derived from seeds. If seeds are not carefully chosen, attackers can:
1. **Squat** on PDAs before legitimate users
2. **Collide** PDAs across different contexts
3. **Spoof** PDAs by using non-canonical bumps

This allows unauthorized control over program accounts, potentially leading to fund theft or denial of service.

## Vulnerable Behavior

### Vulnerability 1: User-Controlled String as Seed

```rust
// ❌ VULNERABLE: PDA from user-supplied username
seeds = [b"profile", username.as_bytes()],
```

**Attack (Username Squatting):**
1. Victim wants username "alice"
2. Attacker observes this (mempool, social media, etc.)
3. Attacker frontruns: `create_profile("alice")`
4. Attacker now controls the PDA victim wanted
5. Victim cannot register "alice"

### Vulnerability 2: Missing Authority in Seeds

```rust
// ❌ VULNERABLE: No authority, just pool name
seeds = [b"pool", pool_name.as_bytes()],
```

**Attack (Namespace Collision):**
1. Protocol A creates "main-pool"
2. Protocol B (or attacker) cannot create their "main-pool"
3. First-come-first-served leads to squatting

### Vulnerability 3: Non-Canonical Bump

```rust
// ❌ VULNERABLE: User-provided bump stored
pub fn vulnerable_create_escrow(..., bump: u8) {
    escrow.bump = bump;  // Could be wrong!
}
```

**Attack (Duplicate PDAs):**
1. Valid PDAs exist for bumps 255, 254, 253, etc.
2. If program doesn't enforce canonical bump (255 first found)
3. Multiple "valid" PDAs could exist for same logical entity

## Real-World Context

### Crema Finance ($8.8M - July 2022)
> "A vulnerability in Crema Finance's CLMM allowed an attacker to create a fake tick account, bypassing owner verification. Using flash loans, the attacker manipulated transaction fee data."

The attacker created PDAs (tick accounts) that looked legitimate but contained malicious data. The program trusted the PDA's existence without verifying its derivation matched expected parameters.

### Wormhole Bridge ($326M - February 2022)
> "A signature verification flaw... allowed an attacker to forge a valid signature, bypassing Guardian validation."

While primarily a signature issue, the attack involved passing spoofed accounts that the program trusted based on their address rather than proper derivation verification.

### Cashio ($52.8M - March 2022)
> "The flaw was due to a missing validation of the mint field in the saber_swap.arrow account, enabling the attacker to bypass checks."

The attacker passed fake accounts that satisfied PDA existence checks but contained malicious collateral data, demonstrating how PDA trust without content verification leads to exploits.

## Fix Explanation

### Fix 1: Include Authority in Seeds

```rust
// ✅ SECURE: Each user has unique PDA namespace
seeds = [b"profile", authority.key().as_ref()],
```

**Benefits:**
- Each user can only create ONE profile
- No frontrunning possible (derived from their own pubkey)
- Username becomes data, not identity

### Fix 2: Complete Seed Set for Uniqueness

```rust
// ✅ SECURE: Authority + name = unique pool per authority
seeds = [b"pool", authority.key().as_ref(), pool_name.as_bytes()],
```

**Benefits:**
- Each authority has their own pool namespace
- "main-pool" for Authority A ≠ "main-pool" for Authority B
- No global squatting possible

### Fix 3: Use Canonical Bump from Anchor

```rust
// ✅ SECURE: Always use ctx.bumps for canonical bump
escrow.bump = ctx.bumps.escrow;
```

**Why Canonical Bump Matters:**
- `find_program_address` starts at 255 and decrements
- First valid bump found is "canonical" (highest)
- Consistent bump = consistent PDA derivation
- Anchor's `bump` constraint enforces this

### Seed Design Checklist

| Seed Type | Vulnerable | Secure |
|-----------|------------|--------|
| User strings | `[username]` | `[authority.key()]` |
| Named resources | `[name]` | `[authority.key(), name]` |
| Multi-party | `[party_a]` | `[party_a, party_b, unique_id]` |
| Bump | User-provided | `ctx.bumps.*` |

## Key Takeaway

> **PDA seeds are the security boundary.**
> 
> Rule 1: **Always include authority pubkey** in seeds for user-specific accounts
> 
> Rule 2: **User-controlled strings are dangerous** - use them as data, not seeds
> 
> Rule 3: **Always use canonical bump** from `ctx.bumps.*`
> 
> Rule 4: **Verify PDA content**, not just existence - a valid address doesn't mean valid data

### Seed Formula

For most use cases:
```
seeds = [
    b"<account_type>",      // Type discriminator
    authority.key().as_ref(), // Owner/authority
    &unique_id.to_le_bytes()  // Instance identifier
]
```

Example:
```rust
// User's vault #5
seeds = [b"vault", user.key().as_ref(), &5u64.to_le_bytes()]

// Escrow between Alice and Bob
seeds = [b"escrow", alice.key().as_ref(), bob.key().as_ref(), &escrow_id.to_le_bytes()]
```

## Attack Prevention Matrix

| Attack | Prevention |
|--------|------------|
| Username squatting | Use pubkey as seed, username as data |
| Namespace collision | Include authority in all seeds |
| PDA frontrunning | Derive from signer's pubkey |
| Bump manipulation | Always use `ctx.bumps.*` |
| Cross-program collision | Use program-specific prefixes |

## Running the Exploit Test

```bash
cd programs/03_incorrect_pda_derivation
anchor test
```

The test demonstrates:
1. Username squatting attack
2. Pool name collision
3. Non-canonical bump issues
4. Secure alternatives for each pattern

## Further Reading

- [Anchor Book: PDAs](https://www.anchor-lang.com/docs/pdas)
- [Solana Cookbook: PDAs](https://solanacookbook.com/core-concepts/pdas.html)
- [Neodyme: Bump Seed Canonicalization](https://blog.neodyme.io/posts/solana_common_pitfalls)
