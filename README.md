# Bouncer: Solana transfer hook

Anti-bundle and anti-snipe rules for token launches on [Meteora's Dynamic Bonding Curve](https://docs.meteora.ag/),
enforced on-chain by a Token-2022 transfer hook.

Program ID (mainnet): `6hUrf1bng8fQb5Vijp765poBYVNJFTPJ514nfeYYSByR`

## Rules

During the protection window (5 to 60 minutes, picked by the creator at launch):

- Buys need a pass signed by Bouncer's server for the buying wallet (issued after a human check on the website), or a
  signature from a trusted relayer (a consumer app that signs its users' trades, such as FOMO).
- Nobody but the creator can buy in the launch slot.
- Wallet-to-wallet transfers are blocked. Selling back to the curve is always allowed.

Until graduation (while the hook is attached), no wallet can hold more than 1.5% of the supply.

Each launch reserves its ticker: the same ticker (case-insensitive, letters and digits) can't launch again on Bouncer
within 24 hours.

When the curve completes, Meteora removes the hook and the token becomes a plain Token-2022 token in a DAMM v2 pool.

The hook can only approve or reject a transfer that Token-2022 is already making. It can't move, mint or freeze
tokens, and it holds no funds.

## Admin

The admin key can set the list of Meteora configs allowed to launch Bouncer tokens, and the list of trusted relayers
until it's locked with `lock_relayers` (one way). Nothing else.

## Build

Verifiable build (matches the deployed program):

```
solana-verify build --library-name bouncer_hook --base-image solanafoundation/solana-verifiable-build:4.3.0
```
