use anchor_lang::prelude::*;

declare_id!("3UFE7yLEjqFt2WDGHkWeUnfR2C3ttJUYad2ty3V2TEsa");

#[program]
pub mod incorrect_pda_derivation {
    use super::*;

    // VULNERABLE: PDA depends ONLY on the username string
    pub fn vulnerable_create_profile(
        ctx: Context<VulnerableCreateProfile>,
        username: String,
    ) -> Result<()> {
        let profile = &mut ctx.accounts.profile;
        profile.authority = ctx.accounts.payer.key();
        profile.username = username;
        profile.bump = ctx.bumps.profile;
        Ok(())
    }

    // SECURE: PDA depends on the User's Public Key
    pub fn secure_create_profile(
        ctx: Context<SecureCreateProfile>,
        username: String,
    ) -> Result<()> {
        let profile = &mut ctx.accounts.profile;
        profile.authority = ctx.accounts.authority.key();
        profile.username = username;
        profile.bump = ctx.bumps.profile;
        Ok(())
    }
}

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

#[account]
pub struct Profile {
    pub authority: Pubkey,
    pub username: String,
    pub bump: u8,
}
