# 05 - Integer Overflow / Underflow

## Overview

This module demonstrates a critical vulnerability in Solana programs: **Integer Overflow and Underflow**. When programs use unchecked arithmetic operations, values can wrap around silently, causing balances to become unexpectedly huge (underflow) or reset to zero (overflow).

---

## The Vulnerability

### Why This Matters

Rust's default behavior for integer arithmetic differs between debug and release builds. In release mode (production), overflows wrap silently without any error. This means a user with 10 tokens who withdraws 20 could end up with quintillions of tokens.

| Build Mode | Overflow Behavior | Security Implication |
|------------|-------------------|----------------------|
| Debug | Panic (program crashes) | Safe - operation fails |
| Release | Silent wrap-around | Dangerous - corrupted state |

The critical distinction: **Release builds silently corrupt your data.**

---

## Program Architecture

This demo implements a simple balance tracking system:

| Instruction | Arithmetic | Description |
|-------------|------------|-------------|
| `initialize` | N/A | Creates state PDA with balance = 0 |
| `vulnerable_withdraw` | `wrapping_sub` | **Vulnerable** - Underflows to massive value |
| `vulnerable_deposit` | `wrapping_add` | **Vulnerable** - Overflows to zero |
| `secure_withdraw` | `checked_sub` | **Secure** - Returns error on underflow |
| `secure_deposit` | `checked_add` | **Secure** - Returns error on overflow |

---

## Vulnerability Analysis

### Underflow: The Flaw

The `vulnerable_withdraw` instruction uses wrapping subtraction:

```rust
pub fn vulnerable_withdraw(ctx: Context<UpdateState>, amount: u64) -> Result<()> {
    let state = &mut ctx.accounts.state;
    
    // This simulates 'unchecked' subtraction
    // 10 - 20 = 18,446,744,073,709,551,606 (u64::MAX - 9)
    state.balance = state.balance.wrapping_sub(amount);
    
    msg!("Vulnerable new balance: {}", state.balance);
    Ok(())
}
```

### Overflow: The Flaw

The `vulnerable_deposit` instruction uses wrapping addition:

```rust
pub fn vulnerable_deposit(ctx: Context<UpdateState>, amount: u64) -> Result<()> {
    let state = &mut ctx.accounts.state;

    // This simulates 'unchecked' addition
    // u64::MAX + 1 = 0
    state.balance = state.balance.wrapping_add(amount);
    
    msg!("Vulnerable new balance: {}", state.balance);
    Ok(())
}
```

### What Goes Wrong

| Issue | Consequence |
|-------|-------------|
| Underflow (10 - 20) | Balance becomes ~18 quintillion |
| Overflow (MAX + 1) | Balance becomes 0 |
| No validation | Operations always "succeed" |
| Silent corruption | No error raised |

---

## Exploit Mechanism

### Attack 1: Underflow to Infinite Balance

```
Step 1: Setup
---------------------------------------------------------------
User has state.balance = 10 tokens

Step 2: Exploit
---------------------------------------------------------------
Attacker calls vulnerable_withdraw(20)
  - Calculation: 10 - 20 = -10
  - u64 cannot be negative
  - Wraps to: u64::MAX - 9 = 18,446,744,073,709,551,606

Step 3: Result
---------------------------------------------------------------
Attacker now has 18 quintillion tokens
  - Can drain entire protocol
  - Balance appears legitimate on-chain
```

### Attack 2: Overflow to Zero Balance

```
Step 1: Setup
---------------------------------------------------------------
Pool has balance near u64::MAX

Step 2: Exploit
---------------------------------------------------------------
Attacker deposits enough to cause overflow
  - Calculation: u64::MAX + 1 = 0
  - Balance resets to zero

Step 3: Result
---------------------------------------------------------------
All tracked value disappears
  - Accounting completely broken
  - Protocol may become insolvent
```

### Attacker Advantages

| Advantage | Description |
|-----------|-------------|
| Silent failure | No transaction error |
| Massive gain | Underflow creates quintillions |
| Undetectable | Balance looks like valid u64 |
| Repeatable | Can exploit multiple accounts |

---

## Secure Implementation

The secure instructions use checked arithmetic that returns an error on overflow/underflow:

```rust
pub fn secure_withdraw(ctx: Context<UpdateState>, amount: u64) -> Result<()> {
    let state = &mut ctx.accounts.state;

    // Returns Error if calculation fails (underflow)
    state.balance = state.balance
        .checked_sub(amount)
        .ok_or(ErrorCode::ArithmeticError)?;

    msg!("Secure new balance: {}", state.balance);
    Ok(())
}

pub fn secure_deposit(ctx: Context<UpdateState>, amount: u64) -> Result<()> {
    let state = &mut ctx.accounts.state;

    // Returns Error if calculation fails (overflow)
    state.balance = state.balance
        .checked_add(amount)
        .ok_or(ErrorCode::ArithmeticError)?;
        
    msg!("Secure new balance: {}", state.balance);
    Ok(())
}
```

### Security Layers

| Protection | Benefit |
|------------|---------|
| `checked_sub` | Returns `None` on underflow |
| `checked_add` | Returns `None` on overflow |
| `ok_or(Error)` | Converts `None` to transaction failure |
| Transaction reverts | No state corruption |

---

## Real-World Exploits

Arithmetic vulnerabilities and related calculation exploits have enabled significant attacks across the Solana ecosystem:

### 2022

| Incident | Loss | Description |
|----------|------|-------------|
| **Cashio (Mar 2022)** | $52.8M | Exploited an "infinite mint glitch" where arithmetic assumptions in collateral validation were violated, allowing the attacker to mint 2 billion CASH tokens with worthless collateral. |
| **Nirvana Finance (Jul 2022)** | $3.5M | Attacker exploited a pricing mechanism vulnerability using flash loans. By manipulating the bonding curve calculation, tokens were minted at an inflated rate, draining stablecoins from the protocol. |
| **Mango Markets (Oct 2022)** | $116M | Oracle price manipulation caused balance calculations throughout the protocol to use inflated collateral values. The attacker borrowed $116M against artificially inflated MNGO token positions. |

### Pattern Analysis

These exploits share common characteristics:

1. **Unchecked Calculations** - Arithmetic operations without bounds checking
2. **Assumption Violations** - Code assumed values would stay within expected ranges
3. **Cascading Effects** - One bad calculation corrupted dependent calculations
4. **Economic Amplification** - Flash loans and leverage magnified the impact

---

## Arithmetic Method Reference

### Checked Methods (Recommended)

| Method | Behavior | Use Case |
|--------|----------|----------|
| `checked_add` | Returns `None` on overflow | Balance increases |
| `checked_sub` | Returns `None` on underflow | Balance decreases |
| `checked_mul` | Returns `None` on overflow | Reward calculations |
| `checked_div` | Returns `None` on divide-by-zero | Rate calculations |

### Other Methods

| Method | Behavior | Use Case |
|--------|----------|----------|
| `saturating_add` | Caps at MAX | Bounded counters |
| `saturating_sub` | Floors at 0 | Bounded decrements |
| `wrapping_add` | Wraps around | Hash functions only |
| `overflowing_add` | Returns (result, bool) | When you need to detect wrap |

---

## Security Checklist

When implementing arithmetic operations:

- [ ] Use `checked_*` methods for all balance operations
- [ ] Convert `None` results to explicit errors
- [ ] Validate inputs before performing calculations
- [ ] Use `u128` for intermediate calculations to prevent overflow
- [ ] Multiply before divide to preserve precision
- [ ] Test with edge cases: 0, 1, MAX-1, MAX

---

## The Wrapping vs Checked Distinction

```rust
// DANGEROUS: Silently wraps on overflow/underflow
state.balance = state.balance.wrapping_sub(amount);

// SAFE: Returns error on overflow/underflow
state.balance = state.balance
    .checked_sub(amount)
    .ok_or(ErrorCode::ArithmeticError)?;
```

**Remember:**
- `wrapping_*` = "Silently corrupt my data"
- `checked_*` = "Fail safely if math is invalid"

---

## Further Reading

- [Rust Book: Integer Overflow](https://doc.rust-lang.org/book/ch03-02-data-types.html#integer-overflow)
- [Anchor Book: Common Security Exploits](https://www.anchor-lang.com/docs/common-security-exploits)
- [Neodyme: Solana Security Pitfalls](https://blog.neodyme.io/posts/solana_common_pitfalls)
- [Helius: A Hitchhiker's Guide to Solana Program Security](https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
