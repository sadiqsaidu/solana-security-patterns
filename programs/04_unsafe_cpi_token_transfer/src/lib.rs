use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

/// # Unsafe CPI Token Transfer Vulnerability Demo
/// 
/// This program demonstrates how failing to validate token accounts
/// during Cross-Program Invocations (CPI) can lead to fund theft.
/// 
/// ## Real-World Context
/// This pattern was exploited in:
/// - **Wormhole** ($326M) - Signature verification bypass in CPI
/// - **Crema Finance** ($8.8M) - Fake accounts in flash loan CPIs
/// - **Raydium** ($4.4M) - Compromised admin triggered malicious CPIs
/// 
/// ## The Scenario
/// A payment splitter that receives tokens and distributes them to multiple
/// recipients. The vulnerability allows attackers to redirect funds by
/// passing malicious token accounts.

#[program]
pub mod unsafe_cpi_token_transfer {
    use super::*;

    /// Initialize a payment splitter
    pub fn initialize_splitter(
        ctx: Context<InitializeSplitter>,
        recipient_share_bps: u16,  // Basis points (100 = 1%)
    ) -> Result<()> {
        require!(recipient_share_bps <= 10000, SplitterError::InvalidShare);
        
        let splitter = &mut ctx.accounts.splitter;
        splitter.authority = ctx.accounts.authority.key();
        splitter.treasury = ctx.accounts.treasury.key();
        splitter.recipient = ctx.accounts.recipient.key();
        splitter.recipient_share_bps = recipient_share_bps;
        splitter.bump = ctx.bumps.splitter;
        
        msg!("Splitter initialized:");
        msg!("  Authority: {}", splitter.authority);
        msg!("  Treasury: {}", splitter.treasury);
        msg!("  Recipient: {} ({}%)", splitter.recipient, recipient_share_bps as f64 / 100.0);
        Ok(())
    }

    // =========================================================================
    // ⚠️  VULNERABLE INSTRUCTIONS - DO NOT USE IN PRODUCTION
    // =========================================================================

    /// ## WHY THIS IS DANGEROUS
    /// 
    /// This instruction performs a token transfer via CPI but doesn't validate:
    /// 1. The source token account owner
    /// 2. The destination token account matches the intended recipient
    /// 3. The token program being called is legitimate
    /// 
    /// ## ATTACK VECTOR
    /// An attacker can:
    /// 1. Pass their own token account as the "recipient_token_account"
    /// 2. Pass a fake token program that does something malicious
    /// 3. Redirect funds meant for the legitimate recipient
    /// 
    /// This mirrors Crema Finance where fake accounts were passed to CPIs.
    /// 
    pub fn vulnerable_split_payment(
        ctx: Context<VulnerableSplitPayment>,
        amount: u64,
    ) -> Result<()> {
        let splitter = &ctx.accounts.splitter;
        
        // Calculate recipient's share
        let recipient_amount = (amount as u128)
            .checked_mul(splitter.recipient_share_bps as u128)
            .unwrap()
            .checked_div(10000)
            .unwrap() as u64;
        let treasury_amount = amount.checked_sub(recipient_amount).unwrap();

        msg!("Splitting {} tokens:", amount);
        msg!("  Recipient share: {}", recipient_amount);
        msg!("  Treasury share: {}", treasury_amount);

        // ❌ VULNERABILITY 1: No verification that source_token_account owner matches authority
        // Attacker could pass any token account as source
        
        // ❌ VULNERABILITY 2: No verification that recipient_token_account.owner == splitter.recipient
        // Attacker passes their own account to receive funds!
        
        // ❌ VULNERABILITY 3: token_program could be a malicious program
        // We don't verify it's the real SPL Token program
        
        // Transfer to "recipient" (could be attacker's account!)
        let transfer_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.source_token_account.to_account_info(),
                to: ctx.accounts.recipient_token_account.to_account_info(),  // ❌ Unverified!
                authority: ctx.accounts.authority.to_account_info(),
            },
        );
        token::transfer(transfer_ctx, recipient_amount)?;
        
        msg!("⚠️  Transferred {} to unverified recipient account!", recipient_amount);

        // Transfer to treasury
        let treasury_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.source_token_account.to_account_info(),
                to: ctx.accounts.treasury_token_account.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            },
        );
        token::transfer(treasury_ctx, treasury_amount)?;

        msg!("Payment split complete (VULNERABLE PATH)");
        Ok(())
    }

    /// Even worse: Arbitrary CPI call
    /// 
    /// ## WHY THIS IS CATASTROPHIC
    /// 
    /// This instruction allows the caller to specify which program to call.
    /// A malicious caller could:
    /// 1. Pass a fake token program that ignores transfer rules
    /// 2. Pass a program that executes arbitrary code
    /// 3. Drain any funds the program has authority over
    /// 
    pub fn vulnerable_arbitrary_cpi(
        ctx: Context<VulnerableArbitraryCpi>,
        amount: u64,
    ) -> Result<()> {
        // ❌ CATASTROPHIC: We call whatever program the user passes!
        // This could be a malicious program that drains funds
        
        let ix = anchor_lang::solana_program::instruction::Instruction {
            program_id: ctx.accounts.target_program.key(),
            accounts: vec![
                anchor_lang::solana_program::instruction::AccountMeta::new(
                    ctx.accounts.from_account.key(),
                    false,
                ),
                anchor_lang::solana_program::instruction::AccountMeta::new(
                    ctx.accounts.to_account.key(),
                    false,
                ),
                anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                    ctx.accounts.authority.key(),
                    true,
                ),
            ],
            data: amount.to_le_bytes().to_vec(),
        };

        anchor_lang::solana_program::program::invoke(
            &ix,
            &[
                ctx.accounts.from_account.to_account_info(),
                ctx.accounts.to_account.to_account_info(),
                ctx.accounts.authority.to_account_info(),
            ],
        )?;

        msg!("🚨 Called arbitrary program: {}", ctx.accounts.target_program.key());
        msg!("   This could have been a malicious program!");
        Ok(())
    }

    // =========================================================================
    // ✅ SECURE INSTRUCTIONS - USE THESE PATTERNS
    // =========================================================================

    /// ## HOW THIS IS FIXED
    /// 
    /// 1. **Token Account Validation**: Use `token::TokenAccount` with constraints
    /// 2. **Owner Verification**: Verify token account owners match expected pubkeys
    /// 3. **Program Verification**: Use `Program<'info, Token>` for token program
    /// 4. **Mint Verification**: Ensure all accounts use the same token mint
    /// 
    pub fn secure_split_payment(
        ctx: Context<SecureSplitPayment>,
        amount: u64,
    ) -> Result<()> {
        let splitter = &ctx.accounts.splitter;
        
        // ✅ At this point, Anchor has verified:
        // - source_token_account.owner == authority (via constraint)
        // - recipient_token_account.owner == splitter.recipient (via constraint)
        // - treasury_token_account.owner == splitter.treasury (via constraint)
        // - All accounts use the same mint (via constraint)
        // - token_program is the real SPL Token program

        let recipient_amount = (amount as u128)
            .checked_mul(splitter.recipient_share_bps as u128)
            .unwrap()
            .checked_div(10000)
            .unwrap() as u64;
        let treasury_amount = amount.checked_sub(recipient_amount).unwrap();

        msg!("Securely splitting {} tokens:", amount);

        // Transfer to verified recipient
        let transfer_to_recipient = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.source_token_account.to_account_info(),
                to: ctx.accounts.recipient_token_account.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            },
        );
        token::transfer(transfer_to_recipient, recipient_amount)?;

        msg!("✅ Transferred {} to verified recipient: {}", recipient_amount, splitter.recipient);

        // Transfer to verified treasury
        let transfer_to_treasury = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.source_token_account.to_account_info(),
                to: ctx.accounts.treasury_token_account.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            },
        );
        token::transfer(transfer_to_treasury, treasury_amount)?;

        msg!("✅ Transferred {} to verified treasury: {}", treasury_amount, splitter.treasury);
        msg!("Payment split complete (SECURE PATH)");
        Ok(())
    }
}

// =============================================================================
// ACCOUNT STRUCTURES
// =============================================================================

#[derive(Accounts)]
pub struct InitializeSplitter<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Splitter::INIT_SPACE,
        seeds = [b"splitter", authority.key().as_ref()],
        bump
    )]
    pub splitter: Account<'info, Splitter>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    /// CHECK: Treasury wallet pubkey
    pub treasury: AccountInfo<'info>,
    
    /// CHECK: Recipient wallet pubkey  
    pub recipient: AccountInfo<'info>,
    
    pub system_program: Program<'info, System>,
}

// =============================================================================
// ⚠️  VULNERABLE ACCOUNT STRUCTURES
// =============================================================================

#[derive(Accounts)]
pub struct VulnerableSplitPayment<'info> {
    #[account(
        seeds = [b"splitter", authority.key().as_ref()],
        bump = splitter.bump
    )]
    pub splitter: Account<'info, Splitter>,
    
    // ❌ VULNERABILITY: Using AccountInfo instead of TokenAccount
    // We don't verify this is a valid token account or its owner
    /// CHECK: DELIBERATELY UNSAFE - No validation of token account
    #[account(mut)]
    pub source_token_account: AccountInfo<'info>,
    
    // ❌ VULNERABILITY: No verification that this belongs to splitter.recipient
    // Attacker passes their own token account here!
    /// CHECK: DELIBERATELY UNSAFE - No owner validation
    #[account(mut)]
    pub recipient_token_account: AccountInfo<'info>,
    
    // ❌ VULNERABILITY: No verification that this belongs to splitter.treasury
    /// CHECK: DELIBERATELY UNSAFE - No owner validation
    #[account(mut)]
    pub treasury_token_account: AccountInfo<'info>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    // ❌ VULNERABILITY: Using AccountInfo instead of Program<Token>
    // Could be a fake program that does something malicious
    /// CHECK: DELIBERATELY UNSAFE - No program verification
    pub token_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct VulnerableArbitraryCpi<'info> {
    // ❌ CATASTROPHIC: Accept any program to call
    /// CHECK: DELIBERATELY UNSAFE - Arbitrary program execution
    pub target_program: AccountInfo<'info>,
    
    /// CHECK: Source account for the CPI
    #[account(mut)]
    pub from_account: AccountInfo<'info>,
    
    /// CHECK: Destination account for the CPI
    #[account(mut)]
    pub to_account: AccountInfo<'info>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
}

// =============================================================================
// ✅ SECURE ACCOUNT STRUCTURES
// =============================================================================

#[derive(Accounts)]
pub struct SecureSplitPayment<'info> {
    #[account(
        seeds = [b"splitter", authority.key().as_ref()],
        bump = splitter.bump,
        has_one = authority,
        has_one = treasury,
        has_one = recipient
    )]
    pub splitter: Account<'info, Splitter>,
    
    // ✅ SECURE: Account<TokenAccount> verifies it's a valid token account
    // The constraint verifies the owner is the authority
    #[account(
        mut,
        constraint = source_token_account.owner == authority.key() @ SplitterError::InvalidSourceOwner,
        constraint = source_token_account.mint == recipient_token_account.mint @ SplitterError::MintMismatch
    )]
    pub source_token_account: Account<'info, TokenAccount>,
    
    // ✅ SECURE: Verify token account owner matches splitter.recipient
    #[account(
        mut,
        constraint = recipient_token_account.owner == splitter.recipient @ SplitterError::InvalidRecipient,
        constraint = recipient_token_account.mint == source_token_account.mint @ SplitterError::MintMismatch
    )]
    pub recipient_token_account: Account<'info, TokenAccount>,
    
    // ✅ SECURE: Verify token account owner matches splitter.treasury
    #[account(
        mut,
        constraint = treasury_token_account.owner == splitter.treasury @ SplitterError::InvalidTreasury,
        constraint = treasury_token_account.mint == source_token_account.mint @ SplitterError::MintMismatch
    )]
    pub treasury_token_account: Account<'info, TokenAccount>,
    
    // ✅ SECURE: authority must sign
    #[account(mut)]
    pub authority: Signer<'info>,
    
    /// CHECK: Verified via has_one on splitter
    pub treasury: AccountInfo<'info>,
    
    /// CHECK: Verified via has_one on splitter
    pub recipient: AccountInfo<'info>,
    
    // ✅ SECURE: Program<Token> verifies this is the real SPL Token program
    pub token_program: Program<'info, Token>,
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

#[account]
#[derive(InitSpace)]
pub struct Splitter {
    pub authority: Pubkey,           // 32 bytes
    pub treasury: Pubkey,            // 32 bytes
    pub recipient: Pubkey,           // 32 bytes
    pub recipient_share_bps: u16,    // 2 bytes
    pub bump: u8,                    // 1 byte
}

// =============================================================================
// ERRORS
// =============================================================================

#[error_code]
pub enum SplitterError {
    #[msg("Invalid share percentage - must be <= 10000 bps")]
    InvalidShare,
    #[msg("Source token account owner does not match authority")]
    InvalidSourceOwner,
    #[msg("Recipient token account owner does not match expected recipient")]
    InvalidRecipient,
    #[msg("Treasury token account owner does not match expected treasury")]
    InvalidTreasury,
    #[msg("Token mint mismatch between accounts")]
    MintMismatch,
    #[msg("Invalid token program")]
    InvalidTokenProgram,
}
