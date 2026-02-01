use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("3UFE7yLEjqFt2WDGHkWeUnfR2C3ttJUYad2ty3V2TEsa");

#[program]
pub mod unsafe_cpi_token_transfer {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, recipient: Pubkey) -> Result<()> {
        ctx.accounts.state.recipient = recipient;
        ctx.accounts.state.authority = ctx.accounts.authority.key();
        Ok(())
    }

    // VULNERABLE: Blindly transfers to whatever 'to' account is passed
    pub fn vulnerable_transfer(ctx: Context<VulnerableTransfer>, amount: u64) -> Result<()> {
        // We are supposed to pay the 'recipient' stored in state.
        // But here, we just use whatever account the user passed in 'ctx.accounts.to'.
        
        let cpi_accounts = Transfer {
            from: ctx.accounts.from.to_account_info(),
            to: ctx.accounts.to.to_account_info(), // <--- NO CHECK: Is this really the recipient?
            authority: ctx.accounts.authority.to_account_info(),
        };
        
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx, amount)?;
        
        Ok(())
    }

    // SECURE: Verifies the 'to' account belongs to the intended recipient
    pub fn secure_transfer(ctx: Context<SecureTransfer>, amount: u64) -> Result<()> {
        let cpi_accounts = Transfer {
            from: ctx.accounts.from.to_account_info(),
            to: ctx.accounts.to.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
        };
        
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx, amount)?;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 32, // Disc + Authority + Recipient
        seeds = [b"state"],
        bump
    )]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VulnerableTransfer<'info> {
    #[account(seeds = [b"state"], bump)]
    pub state: Account<'info, State>,

    /// CHECK: Unsafe. We don't check if this is a valid token account or who owns it.
    #[account(mut)]
    pub from: AccountInfo<'info>,
    
    /// CHECK: Unsafe. This allows the attacker to pass their OWN account here.
    #[account(mut)]
    pub to: AccountInfo<'info>,
    
    pub authority: Signer<'info>,
    pub token_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct SecureTransfer<'info> {
    #[account(seeds = [b"state"], bump)]
    pub state: Account<'info, State>,

    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    
    // SECURE: Anchor checks that this account is owned by the legitimate recipient
    #[account(
        mut,
        constraint = to.owner == state.recipient // <---  THE FIX
    )]
    pub to: Account<'info, TokenAccount>,
    
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct State {
    pub authority: Pubkey,
    pub recipient: Pubkey,
}
