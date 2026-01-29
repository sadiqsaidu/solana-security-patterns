# 05 - Integer Overflow / State Bug

## Vulnerability Name
**Unsafe Arithmetic / Integer Overflow / Underflow / Precision Loss**

## Summary

Solana programs often perform arithmetic operations on token balances, rewards, and other critical values. Without proper safeguards:
1. **Overflow**: Addition/multiplication wraps to small values
2. **Underflow**: Subtraction wraps to huge values
3. **Precision Loss**: Division before multiplication loses accuracy
4. **State Corruption**: Updates before validation cause inconsistencies

These bugs allow attackers to manipulate balances, drain funds, or corrupt protocol state.

## Vulnerable Behavior

### Vulnerability 1: Unchecked Addition (Overflow)

```rust
// ❌ VULNERABLE: Can overflow
pool.total_staked = pool.total_staked + amount;
```

**Attack (Overflow to Zero):**
```
total_staked = u64::MAX - 50  (18,446,744,073,709,551,565)
amount = 100
result = 49  (wrapped around!)
```

### Vulnerability 2: Unchecked Subtraction (Underflow)

```rust
// ❌ VULNERABLE: Can underflow
stake.amount = stake.amount - amount;
```

**Attack (Underflow to Maximum):**
```
stake.amount = 100
amount = 200
result = 18,446,744,073,709,551,516  (u64::MAX - 99)
```

The attacker now has quintillions of tokens "staked"!

### Vulnerability 3: Division Before Multiplication (Precision Loss)

```rust
// ❌ VULNERABLE: Loses precision
let reward_per_share = (reward_rate / total_staked) * time_elapsed;
```

**Attack (Precision Exploitation):**
```
reward_rate = 5
total_staked = 3
time_elapsed = 1000

Vulnerable: (5 / 3) * 1000 = 1 * 1000 = 1000
Secure:     (5 * 1000) / 3 = 5000 / 3 = 1666

Difference: 666 tokens lost or exploitable!
```

### Vulnerability 4: State Update Before Validation

```rust
// ❌ VULNERABLE: State corrupted if validation fails
stake.amount = stake.amount * multiplier;  // Updated first
require!(stake.amount <= MAX);  // Check after - too late!
```

## Real-World Context

### Nirvana Finance ($3.5M - July 2022)
> "Attacker exploited a pricing mechanism vulnerability... using a flash loan of approximately $10 million. By purchasing ANA tokens and manipulating the bonding curve, Ahmed minted tokens at an inflated rate."

The attack exploited how the pricing formula calculated token values, similar to our precision loss vulnerability. Flash loans amplified the impact.

### Cashio ($52.8M - March 2022)
> "A vulnerability in Cashio's program collateral validation allowed an attacker to mint 2 billion CASH tokens... exploiting an 'infinite mint glitch.'"

While primarily an account validation issue, the "infinite mint" involved arithmetic assumptions being violated, allowing unbounded token creation.

### Mango Markets ($116M - October 2022)
> "The attacker manipulated Mango Markets' price oracle by inflating the MNGO token price... borrowing $116 million against the inflated collateral."

Oracle price manipulation affected balance calculations throughout the protocol, demonstrating how arithmetic dependencies on external data can be exploited.

## Fix Explanation

### Fix 1: Use Checked Arithmetic

```rust
// ✅ SECURE: Returns None on overflow
pool.total_staked = pool.total_staked
    .checked_add(amount)
    .ok_or(PoolError::ArithmeticOverflow)?;

// ✅ SECURE: Returns None on underflow  
stake.amount = stake.amount
    .checked_sub(amount)
    .ok_or(PoolError::ArithmeticUnderflow)?;
```

### Fix 2: Validate Before Operations

```rust
// ✅ SECURE: Check balance first
require!(stake.amount >= amount, PoolError::InsufficientBalance);

// Only then perform the subtraction
stake.amount = stake.amount
    .checked_sub(amount)
    .ok_or(PoolError::ArithmeticUnderflow)?;
```

### Fix 3: Multiply Before Divide (Preserve Precision)

```rust
// ✅ SECURE: Multiply first to preserve precision
let pending = reward_rate
    .checked_mul(time)?
    .checked_mul(staked_amount)?
    .checked_div(total_staked)?;
```

### Fix 4: Use Wider Types for Intermediates

```rust
// ✅ SECURE: u128 prevents intermediate overflow
let rate = pool.reward_rate as u128;
let time = time_elapsed as u128;
let amount = stake.amount as u128;

let result = rate
    .checked_mul(time)?
    .checked_mul(amount)?
    .checked_div(total_staked as u128)?;

// Verify result fits in u64 before conversion
require!(result <= u64::MAX as u128);
let result_u64 = result as u64;
```

### Fix 5: Validate Before State Change

```rust
// ✅ SECURE: Calculate, validate, then update
let new_amount = stake.amount
    .checked_mul(multiplier)
    .ok_or(PoolError::ArithmeticOverflow)?;

// Validate BEFORE state change
require!(new_amount <= 1_000_000_000, PoolError::StakeTooLarge);

// Only update after all checks pass
stake.amount = new_amount;
```

## Key Takeaway

> **Arithmetic is not safe by default in Rust release builds.**
> 
> Rule 1: **Always use checked arithmetic** - `checked_add`, `checked_sub`, `checked_mul`, `checked_div`
> 
> Rule 2: **Multiply before divide** - Preserves precision in integer math
> 
> Rule 3: **Use u128 for intermediates** - Prevents overflow during calculation
> 
> Rule 4: **Validate before state changes** - Checks-Effects-Interactions pattern
> 
> Rule 5: **Handle edge cases explicitly** - Zero amounts, empty pools, etc.

### Arithmetic Method Reference

| Method | Behavior | Use Case |
|--------|----------|----------|
| `checked_add` | Returns `None` on overflow | Default choice |
| `checked_sub` | Returns `None` on underflow | Balance deductions |
| `checked_mul` | Returns `None` on overflow | Reward calculations |
| `checked_div` | Returns `None` on divide-by-zero | Rate calculations |
| `saturating_add` | Caps at MAX | Bounded counters |
| `saturating_sub` | Floors at 0 | Bounded decrements |
| `wrapping_*` | Wraps around | Intentional wrapping only |

## Precision Loss Prevention

### Bad Pattern (Divide First)
```rust
(a / b) * c  // Truncates before multiplication
```

### Good Pattern (Multiply First)
```rust
(a * c) / b  // Maximum precision retained
```

### Best Pattern (Scaled Integers)
```rust
// Use "basis points" (1/10000) or higher precision
const PRECISION: u128 = 1_000_000_000_000;  // 1e12

let scaled = (amount as u128)
    .checked_mul(rate as u128)?
    .checked_mul(PRECISION)?
    .checked_div(total as u128)?;

// Unscale when needed
let result = scaled.checked_div(PRECISION)?;
```

## State Update Pattern

```rust
// ✅ CORRECT: Checks → Effects → Interactions
pub fn secure_operation(ctx: Context<...>, amount: u64) -> Result<()> {
    // 1. CHECKS: All validation first
    require!(amount > 0, Error::ZeroAmount);
    require!(ctx.accounts.stake.amount >= amount, Error::InsufficientBalance);
    
    // 2. EFFECTS: Calculate new state
    let new_balance = ctx.accounts.stake.amount
        .checked_sub(amount)
        .ok_or(Error::Underflow)?;
    
    // More validation on calculated values
    require!(new_balance >= MIN_BALANCE, Error::BelowMinimum);
    
    // 3. UPDATE: Atomic state changes
    ctx.accounts.stake.amount = new_balance;
    ctx.accounts.pool.total_staked = ctx.accounts.pool.total_staked
        .checked_sub(amount)
        .ok_or(Error::Underflow)?;
    
    // 4. INTERACTIONS: External calls last (if any)
    Ok(())
}
```

## Running the Exploit Test

```bash
cd programs/05_integer_overflow_state_bug
anchor test
```

The test demonstrates:
1. Underflow attempt (blocked in debug mode, dangerous in release)
2. Overflow potential with large values
3. Precision loss in division-first calculations
4. Secure alternatives blocking all attacks

## Debug vs Release Builds

**Critical Note:** Rust's behavior differs between builds:

| Operation | Debug Mode | Release Mode |
|-----------|------------|--------------|
| Overflow | Panic (crash) | Silent wrap |
| Underflow | Panic (crash) | Silent wrap |

This is why **checked arithmetic is essential** - it catches these issues in release builds where they would otherwise silently corrupt your program state.

## Further Reading

- [Rust Book: Integer Overflow](https://doc.rust-lang.org/book/ch03-02-data-types.html#integer-overflow)
- [Anchor Book: Common Security Exploits](https://www.anchor-lang.com/docs/common-security-exploits)
- [Neodyme: Arithmetic Vulnerabilities](https://blog.neodyme.io/posts/solana_common_pitfalls)
