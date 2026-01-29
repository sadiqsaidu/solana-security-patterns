use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

/// # Integer Overflow / Unsafe Arithmetic Vulnerability Demo
/// 
/// This program demonstrates how unchecked arithmetic operations can
/// lead to overflows, underflows, and state manipulation attacks.
/// 
/// ## Real-World Context
/// This pattern was exploited in:
/// - **Nirvana Finance** ($3.5M) - Pricing mechanism manipulation via flash loans
/// - **Cashio** ($52.8M) - Infinite mint glitch exploiting arithmetic assumptions
/// - **Mango Markets** ($116M) - Oracle manipulation affecting balance calculations
/// 
/// ## The Scenario
/// A staking pool where users deposit tokens and earn rewards. The vulnerability
/// allows attackers to manipulate balances through arithmetic bugs.

#[program]
pub mod integer_overflow_state_bug {
    use super::*;

    /// Initialize a staking pool
    pub fn initialize_pool(ctx: Context<InitializePool>, reward_rate: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.authority = ctx.accounts.authority.key();
        pool.total_staked = 0;
        pool.reward_rate = reward_rate;  // Rewards per second per token
        pool.last_update_time = Clock::get()?.unix_timestamp;
        pool.accumulated_reward_per_share = 0;
        pool.bump = ctx.bumps.pool;
        
        msg!("Pool initialized with reward rate: {} per second", reward_rate);
        Ok(())
    }

    /// Initialize a user stake account
    pub fn initialize_stake(ctx: Context<InitializeStake>) -> Result<()> {
        let stake = &mut ctx.accounts.stake;
        stake.owner = ctx.accounts.owner.key();
        stake.pool = ctx.accounts.pool.key();
        stake.amount = 0;
        stake.reward_debt = 0;
        stake.pending_rewards = 0;
        stake.bump = ctx.bumps.stake;
        
        msg!("Stake account initialized for: {}", stake.owner);
        Ok(())
    }

    // =========================================================================
    // ⚠️  VULNERABLE INSTRUCTIONS - DO NOT USE IN PRODUCTION
    // =========================================================================

    /// ## WHY THIS IS DANGEROUS - Vulnerability 1: Unchecked Addition
    /// 
    /// This instruction uses regular + operator instead of checked_add.
    /// If total_staked + amount > u64::MAX, it wraps around to a small number.
    /// 
    /// ## ATTACK VECTOR
    /// 1. Pool has total_staked = u64::MAX - 100
    /// 2. Attacker deposits 200
    /// 3. Result wraps: (u64::MAX - 100) + 200 = 99
    /// 4. Total staked now shows 99 instead of u64::MAX + 100
    /// 5. Rewards calculation is completely wrong
    /// 
    pub fn vulnerable_deposit(ctx: Context<VulnerableStake>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let stake = &mut ctx.accounts.stake;

        // ❌ VULNERABILITY: Unchecked addition - can overflow!
        // In debug mode, Rust panics on overflow
        // In release mode, it wraps around silently
        pool.total_staked = pool.total_staked + amount;  // ❌ Could wrap!
        stake.amount = stake.amount + amount;            // ❌ Could wrap!

        msg!("Deposited {} (VULNERABLE). Total staked: {}", amount, pool.total_staked);
        msg!("⚠️  No overflow protection!");
        Ok(())
    }

    /// ## WHY THIS IS DANGEROUS - Vulnerability 2: Unchecked Subtraction
    /// 
    /// This instruction uses regular - operator instead of checked_sub.
    /// If amount > stake.amount, it underflows to a huge number.
    /// 
    /// ## ATTACK VECTOR
    /// 1. User has stake.amount = 100
    /// 2. Attacker calls withdraw(200) 
    /// 3. Result underflows: 100 - 200 = u64::MAX - 99
    /// 4. Stake amount is now ~18 quintillion tokens!
    /// 5. Attacker can claim massive rewards
    /// 
    pub fn vulnerable_withdraw(ctx: Context<VulnerableStake>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let stake = &mut ctx.accounts.stake;

        // ❌ VULNERABILITY: No check that user has enough staked!
        // This could also underflow if poorly implemented
        
        // ❌ VULNERABILITY: Unchecked subtraction - can underflow!
        pool.total_staked = pool.total_staked - amount;  // ❌ Could underflow!
        stake.amount = stake.amount - amount;            // ❌ Could underflow!

        msg!("Withdrew {} (VULNERABLE). Remaining stake: {}", amount, stake.amount);
        msg!("⚠️  No underflow protection or balance check!");
        Ok(())
    }

    /// ## WHY THIS IS DANGEROUS - Vulnerability 3: Precision Loss in Division
    /// 
    /// Integer division truncates. If done in wrong order:
    /// (a / b) * c ≠ (a * c) / b
    /// 
    /// The first loses precision, potentially giving attackers free funds.
    /// 
    pub fn vulnerable_claim_rewards(ctx: Context<VulnerableStake>) -> Result<()> {
        let pool = &ctx.accounts.pool;
        let stake = &mut ctx.accounts.stake;

        let time_elapsed = Clock::get()?.unix_timestamp - pool.last_update_time;
        
        // ❌ VULNERABILITY: Division before multiplication loses precision
        // Example: (1000 / 3) * 2 = 333 * 2 = 666
        // Correct:  (1000 * 2) / 3 = 2000 / 3 = 666
        // This specific example gives same result, but consider:
        // (5 / 3) * 1000 = 1 * 1000 = 1000
        // (5 * 1000) / 3 = 5000 / 3 = 1666
        let reward_per_share = (pool.reward_rate / pool.total_staked.max(1)) * time_elapsed as u64;
        
        // ❌ VULNERABILITY: Unchecked multiplication - can overflow
        let pending = stake.amount * reward_per_share;  // ❌ Could overflow!
        
        stake.pending_rewards = stake.pending_rewards + pending;  // ❌ Could overflow!

        msg!("Calculated rewards: {} (VULNERABLE)", pending);
        msg!("⚠️  Precision loss and overflow possible!");
        Ok(())
    }

    /// ## WHY THIS IS DANGEROUS - Vulnerability 4: State Inconsistency
    /// 
    /// Updates state before validation, allowing partial state corruption.
    /// Combined with reentrancy or failed transactions, this can break invariants.
    /// 
    pub fn vulnerable_compound(ctx: Context<VulnerableStake>, multiplier: u64) -> Result<()> {
        let stake = &mut ctx.accounts.stake;
        
        // ❌ VULNERABILITY: State updated before validation
        // If later check fails, state is already corrupted
        let new_amount = stake.amount * multiplier;  // ❌ Could overflow
        stake.amount = new_amount;
        
        // Validation happens AFTER state change
        require!(stake.amount <= 1_000_000_000, PoolError::StakeTooLarge);

        msg!("Compounded stake to: {} (VULNERABLE)", stake.amount);
        Ok(())
    }

    // =========================================================================
    // ✅ SECURE INSTRUCTIONS - USE THESE PATTERNS
    // =========================================================================

    /// ## HOW THIS IS FIXED
    /// 
    /// 1. **checked_add/checked_sub**: Returns None on overflow/underflow
    /// 2. **Explicit validation**: Check balances before operations
    /// 3. **Proper error handling**: Fail transaction on arithmetic errors
    /// 
    pub fn secure_deposit(ctx: Context<SecureStake>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let stake = &mut ctx.accounts.stake;

        // ✅ SECURE: Use checked_add to detect overflow
        pool.total_staked = pool.total_staked
            .checked_add(amount)
            .ok_or(PoolError::ArithmeticOverflow)?;
        
        stake.amount = stake.amount
            .checked_add(amount)
            .ok_or(PoolError::ArithmeticOverflow)?;

        msg!("Deposited {} (SECURE). Total staked: {}", amount, pool.total_staked);
        Ok(())
    }

    /// ## HOW THIS IS FIXED
    /// 
    /// 1. **Balance validation first**: Ensure user has sufficient balance
    /// 2. **checked_sub**: Returns None on underflow
    /// 3. **Update pool after stake**: Maintain consistency
    /// 
    pub fn secure_withdraw(ctx: Context<SecureStake>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let stake = &mut ctx.accounts.stake;

        // ✅ SECURE: Validate balance first
        require!(stake.amount >= amount, PoolError::InsufficientBalance);

        // ✅ SECURE: Use checked_sub to detect underflow
        stake.amount = stake.amount
            .checked_sub(amount)
            .ok_or(PoolError::ArithmeticUnderflow)?;
        
        pool.total_staked = pool.total_staked
            .checked_sub(amount)
            .ok_or(PoolError::ArithmeticUnderflow)?;

        msg!("Withdrew {} (SECURE). Remaining stake: {}", amount, stake.amount);
        Ok(())
    }

    /// ## HOW THIS IS FIXED
    /// 
    /// 1. **Multiplication before division**: Preserves precision
    /// 2. **u128 intermediates**: Prevents overflow during calculation
    /// 3. **checked operations**: Fail safely on edge cases
    /// 
    pub fn secure_claim_rewards(ctx: Context<SecureStake>) -> Result<()> {
        let pool = &ctx.accounts.pool;
        let stake = &mut ctx.accounts.stake;

        let time_elapsed = Clock::get()?.unix_timestamp
            .checked_sub(pool.last_update_time)
            .ok_or(PoolError::ArithmeticUnderflow)?;

        // ✅ SECURE: Use u128 for intermediate calculations to prevent overflow
        let total_staked = pool.total_staked.max(1) as u128;
        let reward_rate = pool.reward_rate as u128;
        let time = time_elapsed as u128;
        let staked_amount = stake.amount as u128;

        // ✅ SECURE: Multiply before divide to preserve precision
        // Formula: (reward_rate * time * staked_amount) / total_staked
        let pending = reward_rate
            .checked_mul(time)
            .ok_or(PoolError::ArithmeticOverflow)?
            .checked_mul(staked_amount)
            .ok_or(PoolError::ArithmeticOverflow)?
            .checked_div(total_staked)
            .ok_or(PoolError::DivisionByZero)?;

        // ✅ SECURE: Check the result fits in u64 before conversion
        require!(pending <= u64::MAX as u128, PoolError::ArithmeticOverflow);
        let pending_u64 = pending as u64;

        stake.pending_rewards = stake.pending_rewards
            .checked_add(pending_u64)
            .ok_or(PoolError::ArithmeticOverflow)?;

        msg!("Calculated rewards: {} (SECURE)", pending_u64);
        Ok(())
    }

    /// ## HOW THIS IS FIXED
    /// 
    /// 1. **Validate before state change**: Check constraints first
    /// 2. **Checked arithmetic**: Detect overflow before applying
    /// 3. **Atomic updates**: All or nothing
    /// 
    pub fn secure_compound(ctx: Context<SecureStake>, multiplier: u64) -> Result<()> {
        let stake = &mut ctx.accounts.stake;
        
        // ✅ SECURE: Validate multiplier
        require!(multiplier > 0 && multiplier <= 10, PoolError::InvalidMultiplier);
        
        // ✅ SECURE: Calculate new amount with overflow check
        let new_amount = stake.amount
            .checked_mul(multiplier)
            .ok_or(PoolError::ArithmeticOverflow)?;
        
        // ✅ SECURE: Validate BEFORE state change
        require!(new_amount <= 1_000_000_000, PoolError::StakeTooLarge);
        
        // ✅ SECURE: State change only after all validations pass
        stake.amount = new_amount;

        msg!("Compounded stake to: {} (SECURE)", stake.amount);
        Ok(())
    }

    /// Utility: Update pool rewards (secure version)
    pub fn update_pool(ctx: Context<UpdatePool>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let current_time = Clock::get()?.unix_timestamp;
        
        if pool.total_staked == 0 {
            pool.last_update_time = current_time;
            return Ok(());
        }

        let time_elapsed = current_time
            .checked_sub(pool.last_update_time)
            .ok_or(PoolError::ArithmeticUnderflow)? as u128;

        // ✅ SECURE: u128 intermediates and checked math
        let reward = (pool.reward_rate as u128)
            .checked_mul(time_elapsed)
            .ok_or(PoolError::ArithmeticOverflow)?
            .checked_mul(1_000_000_000_000)  // Precision multiplier
            .ok_or(PoolError::ArithmeticOverflow)?
            .checked_div(pool.total_staked as u128)
            .ok_or(PoolError::DivisionByZero)?;

        pool.accumulated_reward_per_share = pool.accumulated_reward_per_share
            .checked_add(reward as u64)
            .ok_or(PoolError::ArithmeticOverflow)?;
        pool.last_update_time = current_time;

        Ok(())
    }
}

// =============================================================================
// ACCOUNT STRUCTURES
// =============================================================================

#[derive(Accounts)]
pub struct InitializePool<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Pool::INIT_SPACE,
        seeds = [b"pool", authority.key().as_ref()],
        bump
    )]
    pub pool: Account<'info, Pool>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeStake<'info> {
    #[account(
        seeds = [b"pool", pool.authority.as_ref()],
        bump = pool.bump
    )]
    pub pool: Account<'info, Pool>,
    
    #[account(
        init,
        payer = owner,
        space = 8 + Stake::INIT_SPACE,
        seeds = [b"stake", pool.key().as_ref(), owner.key().as_ref()],
        bump
    )]
    pub stake: Account<'info, Stake>,
    
    #[account(mut)]
    pub owner: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VulnerableStake<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    
    #[account(
        mut,
        has_one = owner
    )]
    pub stake: Account<'info, Stake>,
    
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct SecureStake<'info> {
    #[account(
        mut,
        seeds = [b"pool", pool.authority.as_ref()],
        bump = pool.bump
    )]
    pub pool: Account<'info, Pool>,
    
    #[account(
        mut,
        seeds = [b"stake", pool.key().as_ref(), owner.key().as_ref()],
        bump = stake.bump,
        has_one = owner,
        has_one = pool
    )]
    pub stake: Account<'info, Stake>,
    
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdatePool<'info> {
    #[account(
        mut,
        seeds = [b"pool", pool.authority.as_ref()],
        bump = pool.bump
    )]
    pub pool: Account<'info, Pool>,
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub authority: Pubkey,                    // 32 bytes
    pub total_staked: u64,                    // 8 bytes
    pub reward_rate: u64,                     // 8 bytes
    pub last_update_time: i64,                // 8 bytes
    pub accumulated_reward_per_share: u64,    // 8 bytes
    pub bump: u8,                             // 1 byte
}

#[account]
#[derive(InitSpace)]
pub struct Stake {
    pub owner: Pubkey,          // 32 bytes
    pub pool: Pubkey,           // 32 bytes
    pub amount: u64,            // 8 bytes
    pub reward_debt: u64,       // 8 bytes
    pub pending_rewards: u64,   // 8 bytes
    pub bump: u8,               // 1 byte
}

// =============================================================================
// ERRORS
// =============================================================================

#[error_code]
pub enum PoolError {
    #[msg("Arithmetic overflow detected")]
    ArithmeticOverflow,
    #[msg("Arithmetic underflow detected")]
    ArithmeticUnderflow,
    #[msg("Division by zero")]
    DivisionByZero,
    #[msg("Insufficient balance for withdrawal")]
    InsufficientBalance,
    #[msg("Stake amount exceeds maximum allowed")]
    StakeTooLarge,
    #[msg("Invalid multiplier - must be between 1 and 10")]
    InvalidMultiplier,
}
