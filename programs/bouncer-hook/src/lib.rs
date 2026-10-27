//! Bouncer on Solana: a Token-2022 transfer hook for Meteora Dynamic Bonding Curve launches.
//!
//! Meteora's DBC lets anyone launch a Token-2022 token whose transfers run a hook program; the pool authority
//! holds the hook and Meteora revokes it when the curve completes, so after graduation the token is plain and
//! migrates to a normal DAMM v2 pool. This hook enforces Bouncer's rules on such tokens:
//!
//! During the protection window (5 to 60 minutes, picked by the creator):
//!   * buys (base vault -> wallet) need a pass signed by Bouncer's server for that wallet, verified on-chain from
//!     an Ed25519 signature-verify instruction in the same transaction (bots and terminals don't have one), OR a
//!     signature from a trusted relayer: a consumer app that signs (and pays gas for) its own users' trades, such as
//!     FOMO. The relayer list lives in the Config account; the admin can change it until it's locked;
//!   * nobody but the creator can buy in the launch slot (no same-block bundles);
//!   * wallet-to-wallet transfers are blocked (no consolidating bundled wallets); sells to the pool stay open.
//!
//! Until graduation (while the hook is attached) no wallet may hold more than 1.5% of the supply.
//! Launches also reserve their ticker: the same ticker (case-insensitive, A-Z 0-9) can't launch again on Bouncer
//! within 24 hours. Only Bouncer's own DBC configs (an admin-set list) can arm the hook.
//!
//! Nothing here can move tokens or funds: a hook can only approve or reject a transfer Token-2022 is making.
use anchor_lang::prelude::*;
use anchor_lang::solana_program::{ed25519_program, pubkey, sysvar::instructions as ix_sysvar};
use anchor_spl::token_2022::spl_token_2022::{
    extension::{transfer_hook::TransferHook as HookExt, BaseStateWithExtensions, StateWithExtensions},
    state::Mint as MintState,
};
use anchor_spl::token_interface::{Mint, TokenAccount};
use spl_tlv_account_resolution::{account::ExtraAccountMeta, seeds::Seed, state::ExtraAccountMetaList};
use spl_transfer_hook_interface::instruction::ExecuteInstruction;

declare_id!("6hUrf1bng8fQb5Vijp765poBYVNJFTPJ514nfeYYSByR");

/// Meteora Dynamic Bonding Curve.
pub const DBC: Pubkey = pubkey!("dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN");
/// Bouncer's pass signer (the server signs passes after the human check).
pub const PASS_SIGNER: Pubkey = pubkey!("FfF1i75DMPhMnKzbx1jJXyNnMFDasCinoXHEJKAF9E5i");
/// Can set the trusted relayers (until locked) and the allowed launch configs; nothing else.
pub const ADMIN: Pubkey = pubkey!("4mDF7Rmmmb23PgfRdXToJLoRq8igxQcB5FeafHddVoyk");
pub const MAX_RELAYERS: usize = 8;
pub const MAX_CONFIGS: usize = 8;
/// The creator picks a window of 5 to 60 minutes.
pub const MIN_WINDOW: i64 = 5 * 60;
pub const MAX_WINDOW: i64 = 60 * 60;
/// Per-wallet cap while the hook is attached (until graduation): 1.5% of supply.
pub const CAP_BPS: u64 = 150;
/// A ticker can't launch again on Bouncer within this long of its last launch.
#[cfg(not(feature = "short-ticker-lock"))]
pub const TICKER_LOCK_SECS: i64 = 24 * 60 * 60;
#[cfg(feature = "short-ticker-lock")]
pub const TICKER_LOCK_SECS: i64 = 60; // local tests only
pub const MAX_TICKER_LEN: usize = 10;
/// Pass message: PASS_PREFIX || mint || wallet || expiry (i64, little-endian).
pub const PASS_PREFIX: &[u8] = b"bouncer-pass-v1:";

// DBC TransferHookPool layout: 8-byte discriminator, then PoolState with a 64-byte volatility tracker first.
const POOL_LEN: usize = 8 + 416;
const POOL_CONFIG: usize = 8 + 64;
const POOL_CREATOR: usize = POOL_CONFIG + 32;
const POOL_BASE_MINT: usize = POOL_CREATOR + 32;
const POOL_BASE_VAULT: usize = POOL_BASE_MINT + 32;

#[program]
pub mod bouncer_hook {
    use super::*;

    /// Arm the guard for a freshly created DBC transfer-hook pool and reserve its ticker. Called in the launch
    /// transaction, right after Meteora creates the pool (so `launch_slot` is the creation slot). Once per mint.
    pub fn initialize(ctx: Context<Initialize>, window_secs: i64, ticker: String) -> Result<()> {
        require!((MIN_WINDOW..=MAX_WINDOW).contains(&window_secs), BouncerError::InvalidWindow);

        // the mint must run this hook, and `ticker` must be its on-chain symbol, normalized
        {
            let data = ctx.accounts.mint.to_account_info().try_borrow_data()?.to_vec();
            let mint = StateWithExtensions::<MintState>::unpack(&data).map_err(|_| BouncerError::InvalidMint)?;
            let hook = mint.get_extension::<HookExt>().map_err(|_| BouncerError::InvalidMint)?;
            require!(Option::<Pubkey>::from(hook.program_id) == Some(crate::ID), BouncerError::InvalidMint);
            let symbol = metadata_symbol(&data).ok_or(BouncerError::InvalidMint)?;
            let normalized = normalize_ticker(&symbol).ok_or(BouncerError::InvalidTicker)?;
            require!(normalized == ticker, BouncerError::InvalidTicker);
        }

        // the pool must be Meteora's transfer-hook pool for this mint, on a Bouncer config
        let pool = &ctx.accounts.pool;
        require_keys_eq!(*pool.owner, DBC, BouncerError::InvalidPool);
        let p = pool.try_borrow_data()?;
        require!(p.len() >= POOL_LEN && p[..8] == transfer_hook_pool_discriminator(), BouncerError::InvalidPool);
        let key = |o: usize| Pubkey::new_from_array(p[o..o + 32].try_into().unwrap());
        require_keys_eq!(key(POOL_BASE_MINT), ctx.accounts.mint.key(), BouncerError::InvalidPool);
        require!(ctx.accounts.settings.allowed_configs.contains(&key(POOL_CONFIG)), BouncerError::ConfigNotAllowed);

        // one launch per ticker per 24 hours
        let clock = Clock::get()?;
        let t = &mut ctx.accounts.ticker_record;
        require!(
            t.launched_at == 0 || clock.unix_timestamp >= t.launched_at + TICKER_LOCK_SECS,
            BouncerError::TickerTaken
        );
        t.mint = ctx.accounts.mint.key();
        t.launched_at = clock.unix_timestamp;
        t.bump = ctx.bumps.ticker_record;

        let g = &mut ctx.accounts.guard;
        g.mint = ctx.accounts.mint.key();
        g.pool = pool.key();
        g.config = key(POOL_CONFIG);
        g.creator = key(POOL_CREATOR);
        g.base_vault = key(POOL_BASE_VAULT);
        g.launch_slot = clock.slot;
        g.window_end = clock.unix_timestamp + window_secs;
        g.cap = (ctx.accounts.mint.supply as u128 * CAP_BPS as u128 / 10_000) as u64;
        g.bump = ctx.bumps.guard;

        // Token-2022 passes these to every transfer: the guard (seeded by the mint), the instructions sysvar and
        // the relayer Config.
        let metas = [
            ExtraAccountMeta::new_with_seeds(
                &[Seed::Literal { bytes: b"guard".to_vec() }, Seed::AccountKey { index: 1 }],
                false,
                false,
            )?,
            ExtraAccountMeta::new_with_pubkey(&ix_sysvar::ID, false, false)?,
            ExtraAccountMeta::new_with_seeds(&[Seed::Literal { bytes: b"config".to_vec() }], false, false)?,
        ];
        ExtraAccountMetaList::init::<ExecuteInstruction>(&mut ctx.accounts.extra_account_meta_list.try_borrow_mut_data()?, &metas)?;
        emit!(GuardArmed { mint: g.mint, pool: g.pool, creator: g.creator, window_end: g.window_end, cap: g.cap, ticker });
        Ok(())
    }

    /// Replace the list of trusted relayers (admin only, until locked). Creates the accounts on first use.
    pub fn set_relayers(ctx: Context<SetRelayers>, relayers: Vec<Pubkey>) -> Result<()> {
        require!(relayers.len() <= MAX_RELAYERS, BouncerError::TooManyRelayers);
        require!(!ctx.accounts.settings.relayers_locked, BouncerError::RelayersLocked);
        ctx.accounts.settings.bump = ctx.bumps.settings;
        let c = &mut ctx.accounts.config;
        c.relayers = relayers;
        c.bump = ctx.bumps.config;
        emit!(RelayersSet { relayers: c.relayers.clone() });
        Ok(())
    }

    /// Freeze the relayer list forever (admin only, one way).
    pub fn lock_relayers(ctx: Context<AdminSettings>) -> Result<()> {
        ctx.accounts.settings.relayers_locked = true;
        ctx.accounts.settings.bump = ctx.bumps.settings;
        emit!(RelayersLocked {});
        Ok(())
    }

    /// Replace the list of DBC configs allowed to launch Bouncer tokens (admin only).
    pub fn set_configs(ctx: Context<AdminSettings>, configs: Vec<Pubkey>) -> Result<()> {
        require!(configs.len() <= MAX_CONFIGS, BouncerError::TooManyConfigs);
        let st = &mut ctx.accounts.settings;
        st.allowed_configs = configs;
        st.bump = ctx.bumps.settings;
        emit!(ConfigsSet { configs: st.allowed_configs.clone() });
        Ok(())
    }

    /// Token-2022 calls this on every transfer of a guarded mint (after balances are updated).
    #[interface(spl_transfer_hook_interface::execute)]
    pub fn transfer_hook(ctx: Context<TransferHook>, _amount: u64) -> Result<()> {
        let g = &ctx.accounts.guard;
        let clock = Clock::get()?;
        let source = ctx.accounts.source.key();
        let destination = ctx.accounts.destination.key();
        if destination == g.base_vault {
            return Ok(()); // sells back to the curve are always open
        }
        // the hook is only attached until graduation: until then no wallet may end up above the cap
        require!(ctx.accounts.destination.amount <= g.cap, BouncerError::WalletCap);
        if clock.unix_timestamp >= g.window_end {
            return Ok(()); // window over: open to everyone (within the cap)
        }
        require_keys_eq!(source, g.base_vault, BouncerError::TransfersLocked); // wallet-to-wallet: locked

        // a buy during the window
        let wallet = ctx.accounts.destination.owner;
        require!(clock.slot > g.launch_slot || wallet == g.creator, BouncerError::LaunchSlot);
        require!(
            has_pass(&ctx.accounts.instructions, &g.mint, &wallet, clock.unix_timestamp)?
                || relayer_signed(&ctx.accounts.instructions, &ctx.accounts.config)?,
            BouncerError::NoPass
        );
        Ok(())
    }
}

/// The symbol from a Token-2022 mint's TokenMetadata extension, read straight from its TLV data:
/// base mint padded to 165 bytes + account-type byte, then (type u16, length u16, value) entries.
/// TokenMetadata (type 19) = update authority (32) + mint (32) + name (u32 len + bytes) + symbol (u32 len + bytes) + ...
fn metadata_symbol(data: &[u8]) -> Option<String> {
    const TOKEN_METADATA: u16 = 19;
    let mut pos = 166;
    while pos + 4 <= data.len() {
        let kind = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let len = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let value = data.get(pos + 4..pos + 4 + len)?;
        if kind == 0 {
            return None;
        }
        if kind == TOKEN_METADATA {
            let field = |at: usize| -> Option<(&[u8], usize)> {
                let n = u32::from_le_bytes(value.get(at..at + 4)?.try_into().ok()?) as usize;
                Some((value.get(at + 4..at + 4 + n)?, at + 4 + n))
            };
            let (_name, next) = field(64)?;
            let (symbol, _) = field(next)?;
            return String::from_utf8(symbol.to_vec()).ok();
        }
        pos += 4 + len;
    }
    None
}

/// Uppercase A-Z and 0-9 only, 1 to 10 characters (so "pepe" and "PEPE" are one ticker and lookalikes are out).
fn normalize_ticker(symbol: &str) -> Option<String> {
    let s = symbol.trim();
    if s.is_empty() || s.len() > MAX_TICKER_LEN || !s.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    Some(s.to_ascii_uppercase())
}

/// Anchor account discriminator of DBC's TransferHookPool: sha256("account:TransferHookPool")[..8].
fn transfer_hook_pool_discriminator() -> [u8; 8] {
    let h = anchor_lang::solana_program::hash::hash(b"account:TransferHookPool").to_bytes();
    h[..8].try_into().unwrap()
}

/// True when a trusted relayer is a signer of any instruction in this transaction. The runtime only marks an
/// account as a signer when its signature is on the transaction, so this can't be faked without the relayer's key.
fn relayer_signed(ixs: &AccountInfo, config: &AccountInfo) -> Result<bool> {
    if config.owner != &crate::ID || config.data_is_empty() {
        return Ok(false); // no relayers configured
    }
    let cfg = Config::try_deserialize(&mut &config.try_borrow_data()?[..])?;
    if cfg.relayers.is_empty() {
        return Ok(false);
    }
    let mut i = 0usize;
    while let Ok(ix) = ix_sysvar::load_instruction_at_checked(i, ixs) {
        i += 1;
        if ix.accounts.iter().any(|a| a.is_signer && cfg.relayers.contains(&a.pubkey)) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// True when this transaction contains an Ed25519 signature check, by PASS_SIGNER, of a pass for (mint, wallet)
/// that hasn't expired. The signature, key and message must all live in that instruction's own data, so the
/// precompile verified exactly the bytes read here.
fn has_pass(ixs: &AccountInfo, mint: &Pubkey, wallet: &Pubkey, now: i64) -> Result<bool> {
    let mut i = 0usize;
    while let Ok(ix) = ix_sysvar::load_instruction_at_checked(i, ixs) {
        i += 1;
        if ix.program_id != ed25519_program::ID {
            continue;
        }
        let d = &ix.data;
        if d.len() < 2 {
            continue;
        }
        let count = d[0] as usize;
        for k in 0..count {
            let o = 2 + k * 14;
            if d.len() < o + 14 {
                break;
            }
            let rd = |x: usize| u16::from_le_bytes([d[o + x], d[o + x + 1]]) as usize;
            let (sig_ix, pk_off, pk_ix, msg_off, msg_len, msg_ix) = (rd(2), rd(4), rd(6), rd(8), rd(10), rd(12));
            if sig_ix != u16::MAX as usize || pk_ix != u16::MAX as usize || msg_ix != u16::MAX as usize {
                continue; // data must be inside this instruction
            }
            if d.len() < pk_off + 32 || d.len() < msg_off + msg_len {
                continue;
            }
            if d[pk_off..pk_off + 32] != PASS_SIGNER.to_bytes() {
                continue;
            }
            let msg = &d[msg_off..msg_off + msg_len];
            let n = PASS_PREFIX.len();
            if msg.len() != n + 72 || &msg[..n] != PASS_PREFIX {
                continue;
            }
            let expiry = i64::from_le_bytes(msg[n + 64..n + 72].try_into().unwrap());
            if msg[n..n + 32] == mint.to_bytes() && msg[n + 32..n + 64] == wallet.to_bytes() && expiry >= now {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[derive(Accounts)]
#[instruction(window_secs: i64, ticker: String)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: initialized here as the transfer hook's extra-account list
    #[account(
        init,
        payer = payer,
        space = ExtraAccountMetaList::size_of(3).unwrap(),
        seeds = [b"extra-account-metas", mint.key().as_ref()],
        bump
    )]
    pub extra_account_meta_list: UncheckedAccount<'info>,
    #[account(init, payer = payer, space = 8 + Guard::INIT_SPACE, seeds = [b"guard", mint.key().as_ref()], bump)]
    pub guard: Account<'info, Guard>,
    pub mint: InterfaceAccount<'info, Mint>,
    /// CHECK: Meteora DBC pool, checked by owner, discriminator, base mint and config
    pub pool: UncheckedAccount<'info>,
    #[account(seeds = [b"settings"], bump = settings.bump)]
    pub settings: Account<'info, Settings>,
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + TickerRecord::INIT_SPACE,
        seeds = [b"ticker", ticker.as_bytes()],
        bump
    )]
    pub ticker_record: Account<'info, TickerRecord>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct TransferHook<'info> {
    #[account(token::mint = mint)]
    pub source: InterfaceAccount<'info, TokenAccount>,
    pub mint: InterfaceAccount<'info, Mint>,
    #[account(token::mint = mint)]
    pub destination: InterfaceAccount<'info, TokenAccount>,
    /// CHECK: source owner / delegate, unused
    pub owner: UncheckedAccount<'info>,
    /// CHECK: the extra-account list PDA
    #[account(seeds = [b"extra-account-metas", mint.key().as_ref()], bump)]
    pub extra_account_meta_list: UncheckedAccount<'info>,
    #[account(seeds = [b"guard", mint.key().as_ref()], bump = guard.bump)]
    pub guard: Account<'info, Guard>,
    /// CHECK: instructions sysvar
    #[account(address = ix_sysvar::ID)]
    pub instructions: UncheckedAccount<'info>,
    /// CHECK: the relayer Config PDA; may not exist yet (then no relayers), so it's read by hand
    #[account(seeds = [b"config"], bump)]
    pub config: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct SetRelayers<'info> {
    #[account(mut, address = ADMIN)]
    pub admin: Signer<'info>,
    #[account(init_if_needed, payer = admin, space = 8 + Config::INIT_SPACE, seeds = [b"config"], bump)]
    pub config: Account<'info, Config>,
    #[account(init_if_needed, payer = admin, space = 8 + Settings::INIT_SPACE, seeds = [b"settings"], bump)]
    pub settings: Account<'info, Settings>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminSettings<'info> {
    #[account(mut, address = ADMIN)]
    pub admin: Signer<'info>,
    #[account(init_if_needed, payer = admin, space = 8 + Settings::INIT_SPACE, seeds = [b"settings"], bump)]
    pub settings: Account<'info, Settings>,
    pub system_program: Program<'info, System>,
}

/// Trusted relayers (kept as its own account: every guarded mint's transfers read it).
#[account]
#[derive(InitSpace)]
pub struct Config {
    #[max_len(8)]
    pub relayers: Vec<Pubkey>,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Settings {
    #[max_len(8)]
    pub allowed_configs: Vec<Pubkey>,
    pub relayers_locked: bool,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct TickerRecord {
    pub mint: Pubkey,
    pub launched_at: i64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Guard {
    pub mint: Pubkey,
    pub pool: Pubkey,
    pub config: Pubkey,
    pub creator: Pubkey,
    pub base_vault: Pubkey,
    pub launch_slot: u64,
    pub window_end: i64,
    pub cap: u64,
    pub bump: u8,
}

#[event]
pub struct GuardArmed {
    pub mint: Pubkey,
    pub pool: Pubkey,
    pub creator: Pubkey,
    pub window_end: i64,
    pub cap: u64,
    pub ticker: String,
}

#[event]
pub struct RelayersSet {
    pub relayers: Vec<Pubkey>,
}

#[event]
pub struct RelayersLocked {}

#[event]
pub struct ConfigsSet {
    pub configs: Vec<Pubkey>,
}

#[error_code]
pub enum BouncerError {
    #[msg("Protection window must be 5 to 60 minutes")]
    InvalidWindow,
    #[msg("Mint doesn't use the Bouncer hook")]
    InvalidMint,
    #[msg("Not a Meteora transfer-hook pool for this mint")]
    InvalidPool,
    #[msg("Transfers between wallets are locked during the protection window")]
    TransfersLocked,
    #[msg("Nobody but the creator can buy in the launch slot")]
    LaunchSlot,
    #[msg("No wallet can hold more than 1.5% of the supply before graduation")]
    WalletCap,
    #[msg("Buys during the protection window need a Bouncer pass (buy on the website)")]
    NoPass,
    #[msg("At most 8 trusted relayers")]
    TooManyRelayers,
    #[msg("The relayer list is locked forever")]
    RelayersLocked,
    #[msg("At most 8 allowed configs")]
    TooManyConfigs,
    #[msg("This launch config isn't a Bouncer config")]
    ConfigNotAllowed,
    #[msg("Tickers are 1-10 letters or digits, matching the token's symbol")]
    InvalidTicker,
    #[msg("This ticker launched on Bouncer less than 24 hours ago")]
    TickerTaken,
}
