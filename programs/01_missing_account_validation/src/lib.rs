use anchor_lang::prelude::*;
use anchor_lang::system_program::{transfer, Transfer};

declare_id!("3UFE7yLEjqFt2WDGHkWeUnfR2C3ttJUYad2ty3V2TEsa");

#[program]
pub mod vault {
    use super::*;

    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.owner = ctx.accounts.owner.key();
        vault.balance = 0;
        vault.bump = ctx.bumps.vault;
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let cpi_accounts = Transfer {
            from: ctx.accounts.owner.to_account_info(),
            to: ctx.accounts.vault_pda.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            cpi_accounts
        );
        transfer(cpi_ctx, amount)?;

        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance.checked_add(amount).unwrap();
        
        Ok(())
    }

    // VULNERABLE: Missing Account Validation
    // 1. Accepts arbitrary `AccountInfo` (fake accounts).
    // 2. No check that `vault.owner` matches program ID.
    // 3. Unsafe deserialization ignores type discriminators.
    pub fn withdraw_insecure(ctx: Context<WithdrawInsecure>, amount: u64) -> Result<()> {
        // Manually deserialize without checking account ownership
        let vault_data = &mut ctx.accounts.vault.try_borrow_data()?;
        let vault = Vault::try_deserialize_unchecked(&mut &vault_data[..])?;

        require!(vault.owner == ctx.accounts.authority.key(), VaultError::Unauthorized);
        require!(vault.balance >= amount, VaultError::InsufficientFunds);

        // Signer seeds derived from the UNVERIFIED vault data
        let seeds = &[
            b"vault_pda",
            vault.owner.as_ref(),
            &[vault.bump], 
        ];
        let signer = &[&seeds[..]];

        let cpi_accounts = Transfer {
            from: ctx.accounts.vault_pda.to_account_info(),
            to: ctx.accounts.authority.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            cpi_accounts,
            signer
        );
        
        transfer(cpi_ctx, amount)?;

        Ok(())
    }

    // ✅ SECURE: Anchor Validation
    // 1. `Account<Vault>` verifies Program ID ownership and Type Discriminator.
    // 2. `seeds` constraint ensures PDA matches the vault.
    // 3. `has_one` constraint enforces authority matches vault owner.
    pub fn withdraw_secure(ctx: Context<WithdrawSecure>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        require!(vault.balance >= amount, VaultError::InsufficientFunds);
        vault.balance = vault.balance.checked_sub(amount).unwrap();

        let seeds = &[
            b"vault_pda",
            ctx.accounts.owner.key.as_ref(),
            &[ctx.bumps.vault_pda],
        ];
        let signer = &[&seeds[..]];

        let cpi_accounts = Transfer {
            from: ctx.accounts.vault_pda.to_account_info(),
            to: ctx.accounts.owner.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            cpi_accounts,
            signer
        );
        
        transfer(cpi_ctx, amount)?;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(
        init,
        payer = owner,
        space = 8 + Vault::INIT_SPACE,
        seeds = [b"vault", owner.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    #[account(
        seeds = [b"vault_pda", owner.key().as_ref()],
        bump
    )]
    pub vault_pda: SystemAccount<'info>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [b"vault", owner.key().as_ref()],
        bump = vault.bump,
        has_one = owner
    )]
    pub vault: Account<'info, Vault>,
    #[account(
        mut,
        seeds = [b"vault_pda", owner.key().as_ref()],
        bump
    )]
    pub vault_pda: SystemAccount<'info>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawInsecure<'info> {
    // ⚠️ VULNERABLE: AccountInfo skips all Anchor safety checks
    /// CHECK: Unsafe. Any account data can be passed here.
    #[account(mut)] 
    pub vault: AccountInfo<'info>,
    
    // ⚠️ VULNERABLE: No seeds check to verify PDA derivation
    /// CHECK: Unsafe. No relationship to vault is enforced.
    #[account(mut)]
    pub vault_pda: AccountInfo<'info>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawSecure<'info> {
    // ✅ SECURE: Account wrapper validates Owner and Discriminator
    #[account(
        mut,
        seeds = [b"vault", owner.key().as_ref()],
        bump = vault.bump,
        has_one = owner @ VaultError::Unauthorized
    )]
    pub vault: Account<'info, Vault>,
    
    // ✅ SECURE: Seeds constraint validates PDA derivation
    #[account(
        mut,
        seeds = [b"vault_pda", owner.key().as_ref()],
        bump
    )]
    pub vault_pda: SystemAccount<'info>,
    
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub owner: Pubkey,
    pub balance: u64,
    pub bump: u8,
}

#[error_code]
pub enum VaultError {
    #[msg("Unauthorized access")]
    Unauthorized,
    #[msg("Insufficient funds")]
    InsufficientFunds,
}
