use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

/// # Missing Account Validation Vulnerability Demo
/// 
/// This program demonstrates how failing to validate account ownership
/// and data can lead to catastrophic fund theft.
/// 
/// ## Real-World Context
/// This pattern was exploited in:
/// - **Wormhole Bridge** ($326M) - Signature verification bypass via unvalidated accounts
/// - **Cashio** ($52.8M) - Fake collateral accounts passed to mint function
/// - **Crema Finance** ($8.8M) - Fake tick accounts bypassed owner verification
/// 
/// ## The Scenario
/// A simple vault where users deposit SOL. Each user has their own vault account
/// that tracks their balance. The vulnerability allows attackers to withdraw
/// from ANY vault by passing a fake vault account they control.

#[program]
pub mod missing_account_validation {
    use super::*;

    /// Initialize a new vault for a user
    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.owner = ctx.accounts.owner.key();
        vault.balance = 0;
        vault.bump = ctx.bumps.vault;
        
        msg!("Vault initialized for owner: {}", vault.owner);
        Ok(())
    }

    /// Deposit SOL into the vault
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        // Transfer SOL from user to vault PDA
        let ix = anchor_lang::solana_program::system_instruction::transfer(
            &ctx.accounts.owner.key(),
            &ctx.accounts.vault_pda.key(),
            amount,
        );
        anchor_lang::solana_program::program::invoke(
            &ix,
            &[
                ctx.accounts.owner.to_account_info(),
                ctx.accounts.vault_pda.to_account_info(),
            ],
        )?;

        // Update vault balance
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance.checked_add(amount).unwrap();
        
        msg!("Deposited {} lamports. New balance: {}", amount, vault.balance);
        Ok(())
    }

    // =========================================================================
    // ⚠️  VULNERABLE INSTRUCTION - DO NOT USE IN PRODUCTION
    // =========================================================================
    /// 
    /// ## WHY THIS IS DANGEROUS
    /// 
    /// This instruction does NOT validate that:
    /// 1. The vault account is actually owned by this program
    /// 2. The vault account's `owner` field matches the withdrawer
    /// 3. The vault account was created through our initialize instruction
    /// 
    /// ## ATTACK VECTOR
    /// An attacker can:
    /// 1. Create their own account with arbitrary data
    /// 2. Set the `owner` field to their own pubkey
    /// 3. Set the `balance` field to a huge number
    /// 4. Pass this fake account as the "vault"
    /// 5. Drain any vault_pda they target
    /// 
    /// This mirrors the Cashio exploit where attackers passed fake collateral
    /// accounts that the program trusted without verification.
    /// 
    pub fn vulnerable_withdraw(ctx: Context<VulnerableWithdraw>, amount: u64) -> Result<()> {
        // ❌ VULNERABILITY: We deserialize vault data without checking:
        //    - Account owner (could be any program or system account)
        //    - Account discriminator (could be arbitrary data)
        //    - Account derivation (could be attacker-controlled)
        
        let vault = &ctx.accounts.vault;
        
        // ❌ VULNERABILITY: We trust the vault.owner field blindly
        // An attacker can create an account with owner = their pubkey
        // This check passes but the vault is completely fake!
        require!(
            vault.owner == ctx.accounts.withdrawer.key(),
            VaultError::UnauthorizedWithdrawal
        );

        // ❌ VULNERABILITY: We trust the vault.balance field
        // Attacker sets this to any value they want
        require!(
            vault.balance >= amount,
            VaultError::InsufficientFunds
        );

        // Transfer SOL from the REAL vault PDA to the attacker
        // The vault_pda might have funds from legitimate users!
        **ctx.accounts.vault_pda.try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.withdrawer.try_borrow_mut_lamports()? += amount;

        msg!("Withdrew {} lamports (VULNERABLE PATH)", amount);
        Ok(())
    }

    // =========================================================================
    // ✅ SECURE INSTRUCTION - USE THIS PATTERN
    // =========================================================================
    /// 
    /// ## HOW THIS IS FIXED
    /// 
    /// 1. **Account Owner Check**: Anchor's `Account<>` type automatically 
    ///    verifies the account is owned by this program via discriminator
    /// 
    /// 2. **PDA Derivation**: We use `seeds` and `bump` constraints to ensure
    ///    the vault was derived from expected seeds (owner's pubkey)
    /// 
    /// 3. **has_one Constraint**: Explicitly validates vault.owner == withdrawer
    ///    at the Anchor constraint level, not just in instruction logic
    /// 
    /// 4. **Relationship Validation**: vault_pda is derived from vault's owner,
    ///    ensuring the SOL account corresponds to the metadata account
    /// 
    pub fn secure_withdraw(ctx: Context<SecureWithdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        // ✅ At this point, Anchor has already verified:
        //    - vault is owned by this program (discriminator check)
        //    - vault.owner == withdrawer.key() (has_one constraint)
        //    - vault PDA derived from correct seeds (seeds constraint)
        //    - vault_pda derived from same owner (seeds constraint)

        require!(
            vault.balance >= amount,
            VaultError::InsufficientFunds
        );

        // Update state BEFORE transfer (checks-effects-interactions pattern)
        vault.balance = vault.balance.checked_sub(amount).unwrap();

        // Transfer SOL from vault PDA to withdrawer
        **ctx.accounts.vault_pda.try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.withdrawer.try_borrow_mut_lamports()? += amount;

        msg!("Withdrew {} lamports (SECURE PATH). Remaining: {}", amount, vault.balance);
        Ok(())
    }
}

// =============================================================================
// ACCOUNT STRUCTURES
// =============================================================================

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
    
    /// The PDA that will hold the actual SOL
    /// CHECK: This is a PDA owned by system program, used for SOL storage
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
    
    /// CHECK: PDA for SOL storage
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

// =============================================================================
// ⚠️  VULNERABLE ACCOUNT STRUCTURE
// =============================================================================

#[derive(Accounts)]
pub struct VulnerableWithdraw<'info> {
    // ❌ VULNERABILITY: Using AccountInfo instead of Account<'info, Vault>
    // This bypasses Anchor's automatic ownership and discriminator checks!
    // 
    // An attacker can pass ANY account here, even one they created themselves
    // with arbitrary data that "looks like" a Vault but isn't one.
    /// CHECK: DELIBERATELY UNSAFE - This accepts any account without validation
    #[account(mut)]
    pub vault: AccountInfo<'info>,
    
    // ❌ VULNERABILITY: No seeds constraint on vault_pda
    // We don't verify this PDA corresponds to the vault we're checking
    /// CHECK: DELIBERATELY UNSAFE - No derivation verification
    #[account(mut)]
    pub vault_pda: AccountInfo<'info>,
    
    #[account(mut)]
    pub withdrawer: Signer<'info>,
}

// Manual deserialization for the vulnerable path
impl<'info> VulnerableWithdraw<'info> {
    pub fn vault(&self) -> Result<Vault> {
        // ❌ VULNERABILITY: We manually deserialize without checking:
        //    - The account owner
        //    - The discriminator
        //    - The account derivation
        let data = self.vault.try_borrow_data()?;
        
        // Skip 8-byte discriminator (but we don't verify it!)
        if data.len() < 8 + 32 + 8 + 1 {
            return Err(VaultError::InvalidVaultData.into());
        }
        
        let owner = Pubkey::try_from(&data[8..40]).unwrap();
        let balance = u64::from_le_bytes(data[40..48].try_into().unwrap());
        let bump = data[48];
        
        Ok(Vault { owner, balance, bump })
    }
}

// =============================================================================
// ✅ SECURE ACCOUNT STRUCTURE
// =============================================================================

#[derive(Accounts)]
pub struct SecureWithdraw<'info> {
    // ✅ SECURE: Account<'info, Vault> automatically verifies:
    //    - Account is owned by this program
    //    - Account has correct discriminator
    //    - Account data deserializes correctly
    #[account(
        mut,
        seeds = [b"vault", owner.key().as_ref()],
        bump = vault.bump,
        // ✅ SECURE: has_one verifies vault.owner == withdrawer.key()
        has_one = owner @ VaultError::UnauthorizedWithdrawal
    )]
    pub vault: Account<'info, Vault>,
    
    // ✅ SECURE: Seeds constraint ensures this PDA corresponds to the vault owner
    /// CHECK: PDA verified through seeds
    #[account(
        mut,
        seeds = [b"vault_pda", owner.key().as_ref()],
        bump
    )]
    pub vault_pda: SystemAccount<'info>,
    
    /// The owner must match vault.owner (enforced by has_one above)
    /// CHECK: Validated via has_one constraint on vault
    pub owner: AccountInfo<'info>,
    
    #[account(mut)]
    pub withdrawer: Signer<'info>,
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

#[account]
#[derive(InitSpace)]
pub struct Vault {
    /// The owner who can withdraw from this vault
    pub owner: Pubkey,    // 32 bytes
    /// Current balance tracked by the vault
    pub balance: u64,     // 8 bytes
    /// PDA bump seed for derivation
    pub bump: u8,         // 1 byte
}

// =============================================================================
// ERRORS
// =============================================================================

#[error_code]
pub enum VaultError {
    #[msg("You are not authorized to withdraw from this vault")]
    UnauthorizedWithdrawal,
    #[msg("Insufficient funds in vault")]
    InsufficientFunds,
    #[msg("Invalid vault data format")]
    InvalidVaultData,
}
