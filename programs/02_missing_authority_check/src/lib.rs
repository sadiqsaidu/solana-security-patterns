use anchor_lang::prelude::*;

declare_id!("HmbTLCmaGvZhKnn1Zfa1JVnp7vkMV4DYVxPLWBVoN65L");

/// # Missing Authority / Signer Check Vulnerability Demo
/// 
/// This program demonstrates how failing to verify that an account
/// is a signer allows unauthorized users to perform privileged actions.
/// 
/// ## Real-World Context
/// This pattern was exploited in:
/// - **Solend** (Aug 2021) - Attacker bypassed admin checks in UpdateReserveConfig
/// - **Audius** ($6.1M) - Attacker submitted malicious governance proposals
/// - **Synthetify DAO** ($230K) - Attacker exploited inactive DAO governance
/// 
/// ## The Scenario
/// A protocol configuration system where an admin can update critical parameters
/// like fees, limits, and pause states. The vulnerability allows anyone to
/// become the admin or change configuration without authorization.

#[program]
pub mod missing_authority_check {
    use super::*;

    /// Initialize the protocol configuration
    /// Only called once at deployment
    pub fn initialize(ctx: Context<Initialize>, initial_fee_bps: u16) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.admin = ctx.accounts.admin.key();
        config.pending_admin = None;
        config.fee_bps = initial_fee_bps;
        config.max_deposit = 1_000_000_000_000; // 1000 SOL
        config.is_paused = false;
        config.bump = ctx.bumps.config;
        
        msg!("Protocol initialized with admin: {}", config.admin);
        msg!("Initial fee: {} bps", config.fee_bps);
        Ok(())
    }

    // =========================================================================
    // ⚠️  VULNERABLE INSTRUCTIONS - DO NOT USE IN PRODUCTION
    // =========================================================================

    /// ## WHY THIS IS DANGEROUS
    /// 
    /// This instruction checks that the `new_admin` field equals the admin stored
    /// in config, BUT it doesn't verify that `new_admin` is actually a SIGNER.
    /// 
    /// ## ATTACK VECTOR
    /// An attacker can:
    /// 1. Pass the legitimate admin's pubkey as the `new_admin` account
    /// 2. Pass themselves as the `caller` (who IS a signer)
    /// 3. The check `config.admin == new_admin.key()` passes
    /// 4. But the actual admin never signed this transaction!
    /// 
    /// This mirrors the Solend exploit where an attacker bypassed admin checks
    /// by manipulating the accounts passed to UpdateReserveConfig.
    /// 
    pub fn vulnerable_update_fee(ctx: Context<VulnerableUpdateConfig>, new_fee_bps: u16) -> Result<()> {
        let config = &mut ctx.accounts.config;
        
        // ❌ VULNERABILITY: We check that new_admin EQUALS the stored admin
        // But we never verify that new_admin actually SIGNED this transaction!
        // 
        // The attacker passes:
        // - new_admin = legitimate admin's pubkey (not signing)
        // - caller = attacker's pubkey (is signing, but we don't check authority)
        require!(
            config.admin == ctx.accounts.new_admin.key(),
            ConfigError::Unauthorized
        );

        // ❌ VULNERABILITY: Anyone can change the fee!
        // The admin never authorized this, but we proceed anyway
        let old_fee = config.fee_bps;
        config.fee_bps = new_fee_bps;
        
        msg!("Fee updated from {} to {} bps (VULNERABLE PATH)", old_fee, new_fee_bps);
        msg!("⚠️  Admin {} did NOT sign this transaction!", config.admin);
        Ok(())
    }

    /// Even worse: No authority check at all
    /// 
    /// ## WHY THIS IS CATASTROPHIC
    /// 
    /// This instruction lets ANYONE become the admin because:
    /// 1. No check that caller is current admin
    /// 2. No signer verification on any privileged account
    /// 3. Immediate authority transfer without confirmation
    /// 
    /// This mirrors the Audius exploit where attackers hijacked governance.
    /// 
    pub fn vulnerable_transfer_admin(
        ctx: Context<VulnerableTransferAdmin>,
        new_admin: Pubkey,
    ) -> Result<()> {
        let config = &mut ctx.accounts.config;
        
        // ❌ VULNERABILITY: No check that anyone has authority to do this!
        // ANY caller can become the admin
        let old_admin = config.admin;
        config.admin = new_admin;
        
        msg!("Admin transferred from {} to {} (VULNERABLE PATH)", old_admin, new_admin);
        msg!("🚨 CRITICAL: No authorization was verified!");
        Ok(())
    }

    // =========================================================================
    // ✅ SECURE INSTRUCTIONS - USE THESE PATTERNS
    // =========================================================================

    /// ## HOW THIS IS FIXED
    /// 
    /// 1. **Signer Constraint**: Admin account must have `Signer` type
    /// 2. **has_one Constraint**: Verifies config.admin == admin.key()
    /// 3. **Combined Verification**: Only the stored admin who signs can update
    /// 
    pub fn secure_update_fee(ctx: Context<SecureUpdateConfig>, new_fee_bps: u16) -> Result<()> {
        // ✅ At this point, Anchor has verified:
        //    - admin is a Signer (they authorized this transaction)
        //    - config.admin == admin.key() (they are the stored admin)
        
        let config = &mut ctx.accounts.config;
        
        // Additional business logic validation
        require!(new_fee_bps <= 1000, ConfigError::FeeTooHigh); // Max 10%
        
        let old_fee = config.fee_bps;
        config.fee_bps = new_fee_bps;
        
        msg!("Fee updated from {} to {} bps (SECURE PATH)", old_fee, new_fee_bps);
        msg!("✅ Authorized by admin: {}", ctx.accounts.admin.key());
        Ok(())
    }

    /// Secure two-step admin transfer
    /// 
    /// ## HOW THIS IS FIXED
    /// 
    /// Uses a two-step process to prevent accidental or malicious transfers:
    /// 1. Current admin nominates a pending_admin
    /// 2. Pending admin must explicitly accept
    /// 
    /// This prevents:
    /// - Accidental transfers to wrong addresses
    /// - Social engineering attacks
    /// - Single-transaction takeovers
    /// 
    pub fn secure_nominate_admin(ctx: Context<SecureNominateAdmin>, new_admin: Pubkey) -> Result<()> {
        // ✅ Anchor verified: admin is Signer AND config.admin == admin.key()
        
        let config = &mut ctx.accounts.config;
        config.pending_admin = Some(new_admin);
        
        msg!("New admin nominated: {}", new_admin);
        msg!("✅ Pending admin must call accept_admin to complete transfer");
        Ok(())
    }

    pub fn secure_accept_admin(ctx: Context<SecureAcceptAdmin>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        
        // ✅ Verify the pending_admin exists and matches the signer
        require!(
            config.pending_admin.is_some(),
            ConfigError::NoPendingAdmin
        );
        require!(
            config.pending_admin.unwrap() == ctx.accounts.new_admin.key(),
            ConfigError::NotPendingAdmin
        );
        
        let old_admin = config.admin;
        config.admin = ctx.accounts.new_admin.key();
        config.pending_admin = None;
        
        msg!("Admin transferred from {} to {} (SECURE PATH)", old_admin, config.admin);
        msg!("✅ Both old and new admin authorized this transfer");
        Ok(())
    }

    /// Secure pause function - only admin can pause
    pub fn secure_pause(ctx: Context<SecureUpdateConfig>, pause: bool) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.is_paused = pause;
        
        msg!("Protocol paused: {} (SECURE)", pause);
        Ok(())
    }
}

// =============================================================================
// ACCOUNT STRUCTURES
// =============================================================================

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + Config::INIT_SPACE,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, Config>,
    
    #[account(mut)]
    pub admin: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

// =============================================================================
// ⚠️  VULNERABLE ACCOUNT STRUCTURES
// =============================================================================

#[derive(Accounts)]
pub struct VulnerableUpdateConfig<'info> {
    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,
    
    // ❌ VULNERABILITY: This is NOT a Signer!
    // We check that this pubkey matches config.admin,
    // but the owner of this pubkey never signed the transaction.
    // 
    // Anyone can pass the admin's pubkey here without their consent.
    /// CHECK: DELIBERATELY UNSAFE - Missing Signer constraint
    pub new_admin: AccountInfo<'info>,
    
    // The actual signer - could be anyone
    #[account(mut)]
    pub caller: Signer<'info>,
}

#[derive(Accounts)]
pub struct VulnerableTransferAdmin<'info> {
    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,
    
    // ❌ VULNERABILITY: No authority check at all!
    // Anyone who calls this becomes admin
    #[account(mut)]
    pub caller: Signer<'info>,
}

// =============================================================================
// ✅ SECURE ACCOUNT STRUCTURES
// =============================================================================

#[derive(Accounts)]
pub struct SecureUpdateConfig<'info> {
    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump,
        // ✅ SECURE: Verifies config.admin == admin.key()
        has_one = admin @ ConfigError::Unauthorized
    )]
    pub config: Account<'info, Config>,
    
    // ✅ SECURE: Must be a Signer - they must authorize this transaction
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct SecureNominateAdmin<'info> {
    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump,
        has_one = admin @ ConfigError::Unauthorized
    )]
    pub config: Account<'info, Config>,
    
    // ✅ Current admin must sign to nominate new admin
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct SecureAcceptAdmin<'info> {
    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,
    
    // ✅ New admin must sign to accept the role
    pub new_admin: Signer<'info>,
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

#[account]
#[derive(InitSpace)]
pub struct Config {
    /// Current admin who can modify settings
    pub admin: Pubkey,           // 32 bytes
    /// Pending admin for two-step transfer
    pub pending_admin: Option<Pubkey>, // 1 + 32 bytes
    /// Protocol fee in basis points (100 = 1%)
    pub fee_bps: u16,            // 2 bytes
    /// Maximum deposit amount in lamports
    pub max_deposit: u64,        // 8 bytes
    /// Whether the protocol is paused
    pub is_paused: bool,         // 1 byte
    /// PDA bump
    pub bump: u8,                // 1 byte
}

// =============================================================================
// ERRORS
// =============================================================================

#[error_code]
pub enum ConfigError {
    #[msg("You are not authorized to perform this action")]
    Unauthorized,
    #[msg("Fee cannot exceed 1000 basis points (10%)")]
    FeeTooHigh,
    #[msg("No pending admin to accept")]
    NoPendingAdmin,
    #[msg("You are not the pending admin")]
    NotPendingAdmin,
}
