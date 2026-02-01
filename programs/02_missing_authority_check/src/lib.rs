use anchor_lang::prelude::*;

declare_id!("HmbTLCmaGvZhKnn1Zfa1JVnp7vkMV4DYVxPLWBVoN65L");

#[program]
pub mod protocol_config {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, initial_fee_bps: u16) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.admin = ctx.accounts.admin.key();
        config.pending_admin = None;
        config.fee_bps = initial_fee_bps;
        config.bump = ctx.bumps.config;
        Ok(())
    }

    // VULNERABLE: Missing Signer Check
    // We check if the account matches the admin address, but we DO NOT check if they signed.
    pub fn vulnerable_update_fee(
        ctx: Context<VulnerableUpdateFee>,
        new_fee_bps: u16,
    ) -> Result<()> {
        let config = &mut ctx.accounts.config;

        // This passes if you send the admin's Public Key, even if they didn't sign!
        require!(
            config.admin == ctx.accounts.admin_account.key(),
            ConfigError::Unauthorized
        );

        config.fee_bps = new_fee_bps;
        Ok(())
    }

    // VULNERABLE: No Checks at all
    pub fn vulnerable_transfer_admin(
        ctx: Context<VulnerableTransferAdmin>,
        new_admin: Pubkey,
    ) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.admin = new_admin;
        Ok(())
    }

    // SECURE: Signer Check + Ownership Check
    pub fn secure_update_fee(ctx: Context<SecureUpdateFee>, new_fee_bps: u16) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.fee_bps = new_fee_bps;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + 32 + 33 + 2 + 1,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VulnerableUpdateFee<'info> {
    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,

    /// CHECK: Unsafe. This allows passing the admin's address without their signature.
    pub admin_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct VulnerableTransferAdmin<'info> {
    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub caller: Signer<'info>,
}

#[derive(Accounts)]
pub struct SecureUpdateFee<'info> {
    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump,
        has_one = admin @ ConfigError::Unauthorized
    )]
    pub config: Account<'info, Config>,

    pub admin: Signer<'info>,
}

#[account]
pub struct Config {
    pub admin: Pubkey,
    pub pending_admin: Option<Pubkey>,
    pub fee_bps: u16,
    pub bump: u8,
}

#[error_code]
pub enum ConfigError {
    #[msg("Unauthorized access")]
    Unauthorized,
}
