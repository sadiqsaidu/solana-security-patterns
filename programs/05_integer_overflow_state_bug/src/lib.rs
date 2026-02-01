use anchor_lang::prelude::*;

declare_id!("3UFE7yLEjqFt2WDGHkWeUnfR2C3ttJUYad2ty3V2TEsa");

#[program]
pub mod integer_overflow_demo {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.authority = ctx.accounts.authority.key();
        state.balance = 0;
        Ok(())
    }

    // VULNERABLE: Simulates unchecked math (wrapping)
    // If balance is 10 and we withdraw 20, it wraps to huge number.
    pub fn vulnerable_withdraw(ctx: Context<UpdateState>, amount: u64) -> Result<()> {
        let state = &mut ctx.accounts.state;
        
        // This simulates 'unchecked' subtraction
        // 10 - 20 = 18,446,744,073,709,551,606 (u64::MAX - 9)
        state.balance = state.balance.wrapping_sub(amount);
        
        msg!("Vulnerable new balance: {}", state.balance);
        Ok(())
    }

    // VULNERABLE: Simulates unchecked addition
    // If balance is u64::MAX and we add 1, it wraps to 0.
    pub fn vulnerable_deposit(ctx: Context<UpdateState>, amount: u64) -> Result<()> {
        let state = &mut ctx.accounts.state;

        // This simulates 'unchecked' addition
        // u64::MAX + 1 = 0
        state.balance = state.balance.wrapping_add(amount);
        
        msg!("Vulnerable new balance: {}", state.balance);
        Ok(())
    }

    // SECURE: Uses checked arithmetic
    pub fn secure_withdraw(ctx: Context<UpdateState>, amount: u64) -> Result<()> {
        let state = &mut ctx.accounts.state;

        // Returns Error if calculation fails (underflow)
        state.balance = state.balance
            .checked_sub(amount)
            .ok_or(ErrorCode::ArithmeticError)?;

        msg!("Secure new balance: {}", state.balance);
        Ok(())
    }

    // SECURE: Uses checked arithmetic
    pub fn secure_deposit(ctx: Context<UpdateState>, amount: u64) -> Result<()> {
        let state = &mut ctx.accounts.state;

        // Returns Error if calculation fails (overflow)
        state.balance = state.balance
            .checked_add(amount)
            .ok_or(ErrorCode::ArithmeticError)?;
            
        msg!("Secure new balance: {}", state.balance);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 8, // Disc + Pubkey + u64
        seeds = [b"state", authority.key().as_ref()],
        bump
    )]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateState<'info> {
    #[account(
        mut,
        seeds = [b"state", authority.key().as_ref()],
        bump
    )]
    pub state: Account<'info, State>,
    pub authority: Signer<'info>,
}

#[account]
pub struct State {
    pub authority: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Arithmetic operation failed (overflow/underflow)")]
    ArithmeticError,
}
