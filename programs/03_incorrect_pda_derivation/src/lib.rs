use anchor_lang::prelude::*;

declare_id!("BPFLoaderUpgradeab1e11111111111111111111111");

/// # Incorrect PDA Derivation Vulnerability Demo
/// 
/// This program demonstrates how improper PDA seed derivation can allow
/// attackers to hijack, collide, or spoof PDAs to gain unauthorized access.
/// 
/// ## Real-World Context
/// This pattern was exploited in:
/// - **Crema Finance** ($8.8M) - Fake tick accounts bypassed owner verification
/// - **Wormhole** ($326M) - Spoofed signature accounts via flawed derivation
/// - **Cashio** ($52.8M) - Fake collateral account derivation
/// 
/// ## The Scenario
/// A user profile system where each user has a unique profile PDA. The vulnerability
/// allows attackers to create profiles that collide with or impersonate other users.

#[program]
pub mod incorrect_pda_derivation {
    use super::*;

    // =========================================================================
    // ⚠️  VULNERABLE INSTRUCTIONS - DO NOT USE IN PRODUCTION
    // =========================================================================

    /// ## WHY THIS IS DANGEROUS - Vulnerability 1: User-controlled seed
    /// 
    /// This instruction allows users to specify an arbitrary "username" seed.
    /// The problem: usernames are not unique or verified.
    /// 
    /// ## ATTACK VECTOR
    /// 1. Attacker observes victim's username "alice"
    /// 2. Before victim initializes, attacker calls create_profile("alice")
    /// 3. Attacker now owns the PDA that victim would have used
    /// 4. When victim tries to interact, attacker controls their "profile"
    /// 
    /// This is a "frontrunning" or "PDA squatting" attack.
    /// 
    pub fn vulnerable_create_profile(
        ctx: Context<VulnerableCreateProfile>,
        username: String,
    ) -> Result<()> {
        let profile = &mut ctx.accounts.profile;
        
        // ❌ VULNERABILITY: We trust user-supplied username as seed
        // Anyone can squat on any username before the legitimate user
        profile.authority = ctx.accounts.payer.key();
        profile.username = username.clone();
        profile.reputation = 0;
        profile.created_at = Clock::get()?.unix_timestamp;
        
        msg!("Profile created for username: {} (VULNERABLE)", username);
        msg!("⚠️  Anyone could have frontrun this username!");
        Ok(())
    }

    /// ## WHY THIS IS DANGEROUS - Vulnerability 2: Missing uniqueness seed
    /// 
    /// This instruction derives PDA from ONLY the pool name, not including
    /// the authority. Multiple "authorities" can create pools with the same name.
    /// 
    /// ## ATTACK VECTOR
    /// 1. Legitimate protocol creates pool "main-liquidity"
    /// 2. Attacker creates malicious contract that also creates "main-liquidity"
    /// 3. Users might interact with wrong pool (same name, different authority)
    /// 
    pub fn vulnerable_create_pool(
        ctx: Context<VulnerableCreatePool>,
        pool_name: String,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        // ❌ VULNERABILITY: PDA derived only from pool_name
        // If two programs use the same derivation, PDAs can collide!
        pool.authority = ctx.accounts.authority.key();
        pool.pool_name = pool_name.clone();
        pool.total_deposits = 0;
        pool.is_active = true;
        
        msg!("Pool '{}' created (VULNERABLE)", pool_name);
        msg!("⚠️  PDA could collide with pools from other programs!");
        Ok(())
    }

    /// ## WHY THIS IS DANGEROUS - Vulnerability 3: Non-canonical bump
    /// 
    /// This instruction accepts a user-provided bump seed instead of
    /// using the canonical bump from find_program_address.
    /// 
    /// ## ATTACK VECTOR
    /// 1. Legitimate user creates escrow with canonical bump (e.g., 255)
    /// 2. Attacker creates escrow with non-canonical bump (e.g., 254)
    /// 3. Now TWO different PDAs exist for "same" escrow
    /// 4. Attacker can manipulate their version independently
    /// 
    pub fn vulnerable_create_escrow(
        ctx: Context<VulnerableCreateEscrow>,
        escrow_id: u64,
        bump: u8,  // ❌ User-provided bump
    ) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        
        // ❌ VULNERABILITY: We use user-provided bump, not canonical
        // Multiple PDAs can exist for the same logical escrow
        escrow.creator = ctx.accounts.creator.key();
        escrow.recipient = ctx.accounts.recipient.key();
        escrow.amount = 0;
        escrow.escrow_id = escrow_id;
        escrow.bump = bump;  // ❌ Storing non-canonical bump
        
        msg!("Escrow {} created with bump {} (VULNERABLE)", escrow_id, bump);
        msg!("⚠️  Non-canonical bump could lead to duplicate PDAs!");
        Ok(())
    }

    // =========================================================================
    // ✅ SECURE INSTRUCTIONS - USE THESE PATTERNS
    // =========================================================================

    /// ## HOW THIS IS FIXED
    /// 
    /// 1. **Authority-based derivation**: PDA includes user's pubkey as seed
    /// 2. **No user-controlled strings**: Username stored as data, not seed
    /// 3. **Canonical bump**: Anchor's `bump` constraint ensures canonical
    /// 
    pub fn secure_create_profile(ctx: Context<SecureCreateProfile>, username: String) -> Result<()> {
        let profile = &mut ctx.accounts.profile;
        
        // ✅ SECURE: PDA derived from authority.key(), not username
        // Each user can only have one profile, derived from their pubkey
        profile.authority = ctx.accounts.authority.key();
        profile.username = username;
        profile.reputation = 0;
        profile.created_at = Clock::get()?.unix_timestamp;
        profile.bump = ctx.bumps.profile;  // ✅ Canonical bump from Anchor
        
        msg!("Profile created for authority: {} (SECURE)", profile.authority);
        Ok(())
    }

    /// ## HOW THIS IS FIXED
    /// 
    /// 1. **Include authority in seeds**: Ensures each authority has unique namespace
    /// 2. **Program-specific prefix**: Adds uniqueness across programs
    /// 3. **Canonical bump**: Always use find_program_address result
    /// 
    pub fn secure_create_pool(
        ctx: Context<SecureCreatePool>,
        pool_name: String,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        // ✅ SECURE: PDA includes authority AND pool_name
        // Each authority has their own namespace of pool names
        pool.authority = ctx.accounts.authority.key();
        pool.pool_name = pool_name.clone();
        pool.total_deposits = 0;
        pool.is_active = true;
        pool.bump = ctx.bumps.pool;
        
        msg!("Pool '{}' created for authority {} (SECURE)", pool_name, pool.authority);
        Ok(())
    }

    /// ## HOW THIS IS FIXED
    /// 
    /// 1. **No user-provided bump**: Anchor derives canonical bump
    /// 2. **Complete seed set**: Creator + Recipient + ID = unique escrow
    /// 3. **Bump stored from derivation**: Can be verified later
    /// 
    pub fn secure_create_escrow(
        ctx: Context<SecureCreateEscrow>,
        escrow_id: u64,
    ) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        
        // ✅ SECURE: Canonical bump from Anchor's derivation
        escrow.creator = ctx.accounts.creator.key();
        escrow.recipient = ctx.accounts.recipient.key();
        escrow.amount = 0;
        escrow.escrow_id = escrow_id;
        escrow.bump = ctx.bumps.escrow;  // ✅ Canonical bump
        
        msg!("Escrow {} created with canonical bump {} (SECURE)", escrow_id, escrow.bump);
        Ok(())
    }

    /// Deposit to escrow - demonstrates secure PDA access
    pub fn secure_deposit_to_escrow(
        ctx: Context<SecureAccessEscrow>,
        amount: u64,
    ) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        
        // ✅ Anchor verified the PDA derivation matches stored data
        escrow.amount = escrow.amount.checked_add(amount).unwrap();
        
        msg!("Deposited {} to escrow. Total: {}", amount, escrow.amount);
        Ok(())
    }
}

// =============================================================================
// ⚠️  VULNERABLE ACCOUNT STRUCTURES
// =============================================================================

#[derive(Accounts)]
#[instruction(username: String)]
pub struct VulnerableCreateProfile<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + Profile::INIT_SPACE,
        // ❌ VULNERABILITY: PDA derived from user-controlled username
        // Anyone can squat on usernames before legitimate users
        seeds = [b"profile", username.as_bytes()],
        bump
    )]
    pub profile: Account<'info, Profile>,
    
    #[account(mut)]
    pub payer: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(pool_name: String)]
pub struct VulnerableCreatePool<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Pool::INIT_SPACE,
        // ❌ VULNERABILITY: PDA derived only from pool_name
        // No authority included, could collide across contexts
        seeds = [b"pool", pool_name.as_bytes()],
        bump
    )]
    pub pool: Account<'info, Pool>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(escrow_id: u64, bump: u8)]
pub struct VulnerableCreateEscrow<'info> {
    #[account(
        init,
        payer = creator,
        space = 8 + Escrow::INIT_SPACE,
        // ❌ VULNERABILITY: User-provided bump instead of canonical
        seeds = [
            b"escrow",
            creator.key().as_ref(),
            recipient.key().as_ref(),
            &escrow_id.to_le_bytes()
        ],
        bump  // This uses canonical, but we STORE the user-provided one
    )]
    pub escrow: Account<'info, Escrow>,
    
    #[account(mut)]
    pub creator: Signer<'info>,
    
    /// CHECK: Recipient is just a pubkey reference
    pub recipient: AccountInfo<'info>,
    
    pub system_program: Program<'info, System>,
}

// =============================================================================
// ✅ SECURE ACCOUNT STRUCTURES
// =============================================================================

#[derive(Accounts)]
#[instruction(username: String)]
pub struct SecureCreateProfile<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Profile::INIT_SPACE,
        // ✅ SECURE: PDA derived from authority's pubkey
        // Each user can only create ONE profile (their own)
        seeds = [b"profile", authority.key().as_ref()],
        bump
    )]
    pub profile: Account<'info, Profile>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(pool_name: String)]
pub struct SecureCreatePool<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Pool::INIT_SPACE,
        // ✅ SECURE: PDA includes authority + pool_name
        // Each authority has unique namespace for pools
        seeds = [b"pool", authority.key().as_ref(), pool_name.as_bytes()],
        bump
    )]
    pub pool: Account<'info, Pool>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(escrow_id: u64)]
pub struct SecureCreateEscrow<'info> {
    #[account(
        init,
        payer = creator,
        space = 8 + Escrow::INIT_SPACE,
        // ✅ SECURE: Complete seed set with canonical bump
        seeds = [
            b"escrow",
            creator.key().as_ref(),
            recipient.key().as_ref(),
            &escrow_id.to_le_bytes()
        ],
        bump
    )]
    pub escrow: Account<'info, Escrow>,
    
    #[account(mut)]
    pub creator: Signer<'info>,
    
    /// CHECK: Recipient pubkey for escrow
    pub recipient: AccountInfo<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SecureAccessEscrow<'info> {
    #[account(
        mut,
        // ✅ SECURE: Verify PDA derivation matches stored data
        seeds = [
            b"escrow",
            escrow.creator.as_ref(),
            escrow.recipient.as_ref(),
            &escrow.escrow_id.to_le_bytes()
        ],
        bump = escrow.bump,
        // ✅ Also verify the depositor is the creator
        has_one = creator
    )]
    pub escrow: Account<'info, Escrow>,
    
    pub creator: Signer<'info>,
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

#[account]
#[derive(InitSpace)]
pub struct Profile {
    pub authority: Pubkey,           // 32 bytes
    #[max_len(32)]
    pub username: String,            // 4 + 32 bytes
    pub reputation: u64,             // 8 bytes
    pub created_at: i64,             // 8 bytes
    pub bump: u8,                    // 1 byte
}

#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub authority: Pubkey,           // 32 bytes
    #[max_len(32)]
    pub pool_name: String,           // 4 + 32 bytes
    pub total_deposits: u64,         // 8 bytes
    pub is_active: bool,             // 1 byte
    pub bump: u8,                    // 1 byte
}

#[account]
#[derive(InitSpace)]
pub struct Escrow {
    pub creator: Pubkey,             // 32 bytes
    pub recipient: Pubkey,           // 32 bytes
    pub amount: u64,                 // 8 bytes
    pub escrow_id: u64,              // 8 bytes
    pub bump: u8,                    // 1 byte
}

// =============================================================================
// ERRORS
// =============================================================================

#[error_code]
pub enum PdaError {
    #[msg("Username already taken")]
    UsernameTaken,
    #[msg("Invalid PDA derivation")]
    InvalidPda,
    #[msg("Unauthorized access to escrow")]
    UnauthorizedEscrowAccess,
}
