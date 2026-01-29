/**
 * Shared Test Utilities for Solana Security Patterns
 * 
 * Common helpers used across exploit tests
 */

import * as anchor from "@coral-xyz/anchor";
import { 
    Keypair, 
    PublicKey, 
    Connection,
    LAMPORTS_PER_SOL,
} from "@solana/web3.js";

/**
 * Airdrop SOL to an account and wait for confirmation
 */
export async function airdropSol(
    connection: Connection,
    publicKey: PublicKey,
    amount: number = 5 * LAMPORTS_PER_SOL
): Promise<void> {
    const signature = await connection.requestAirdrop(publicKey, amount);
    await connection.confirmTransaction(signature);
}

/**
 * Airdrop SOL to multiple accounts
 */
export async function airdropToMultiple(
    connection: Connection,
    publicKeys: PublicKey[],
    amount: number = 5 * LAMPORTS_PER_SOL
): Promise<void> {
    const promises = publicKeys.map(pk => airdropSol(connection, pk, amount));
    await Promise.all(promises);
}

/**
 * Create multiple keypairs
 */
export function createKeypairs(count: number): Keypair[] {
    return Array.from({ length: count }, () => Keypair.generate());
}

/**
 * Get balance in SOL
 */
export async function getBalanceInSol(
    connection: Connection,
    publicKey: PublicKey
): Promise<number> {
    const balance = await connection.getBalance(publicKey);
    return balance / LAMPORTS_PER_SOL;
}

/**
 * Wait for a specified number of seconds
 */
export function sleep(seconds: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, seconds * 1000));
}

/**
 * Format a public key for display (first 8 chars)
 */
export function shortPubkey(pubkey: PublicKey): string {
    return pubkey.toString().slice(0, 8) + "...";
}

/**
 * Log a section header
 */
export function logSection(title: string): void {
    console.log(`\n${"=".repeat(60)}`);
    console.log(`  ${title}`);
    console.log(`${"=".repeat(60)}\n`);
}

/**
 * Log an attack attempt
 */
export function logAttack(description: string): void {
    console.log(`\n🎯 ATTACK: ${description}`);
}

/**
 * Log a successful exploit
 */
export function logExploitSuccess(details: string): void {
    console.log(`\n🚨 EXPLOIT SUCCEEDED!`);
    console.log(`   ${details}`);
}

/**
 * Log a blocked attack
 */
export function logAttackBlocked(reason: string): void {
    console.log(`\n✅ Attack blocked: ${reason}`);
}

/**
 * Log a secure operation
 */
export function logSecure(description: string): void {
    console.log(`\n✅ SECURE: ${description}`);
}

/**
 * Derive a PDA with common seeds pattern
 */
export function derivePda(
    seeds: (string | Buffer | PublicKey)[],
    programId: PublicKey
): [PublicKey, number] {
    const seedBuffers = seeds.map(s => {
        if (typeof s === "string") return Buffer.from(s);
        if (s instanceof PublicKey) return s.toBuffer();
        return s;
    });
    return PublicKey.findProgramAddressSync(seedBuffers, programId);
}

/**
 * Assert that a promise rejects with a specific error message
 */
export async function assertRejects(
    promise: Promise<any>,
    errorContains: string,
    message?: string
): Promise<void> {
    try {
        await promise;
        throw new Error(message || `Expected promise to reject with "${errorContains}"`);
    } catch (error: any) {
        if (!error.toString().includes(errorContains)) {
            throw new Error(
                `Expected error containing "${errorContains}" but got: ${error.toString()}`
            );
        }
    }
}

/**
 * Format token amounts with decimals
 */
export function formatTokenAmount(amount: anchor.BN | number, decimals: number = 9): string {
    const num = typeof amount === "number" ? amount : amount.toNumber();
    return (num / Math.pow(10, decimals)).toFixed(decimals);
}

/**
 * Security comparison table
 */
export function printSecurityComparison(
    title: string,
    vulnerable: string[],
    secure: string[]
): void {
    console.log(`\n╔${"═".repeat(68)}╗`);
    console.log(`║  ${title.padEnd(66)}║`);
    console.log(`╠${"═".repeat(68)}╣`);
    console.log(`║  VULNERABLE:${" ".repeat(55)}║`);
    vulnerable.forEach(v => {
        console.log(`║    ❌ ${v.padEnd(61)}║`);
    });
    console.log(`║${" ".repeat(68)}║`);
    console.log(`║  SECURE:${" ".repeat(59)}║`);
    secure.forEach(s => {
        console.log(`║    ✅ ${s.padEnd(61)}║`);
    });
    console.log(`╚${"═".repeat(68)}╝`);
}
