# How the risk score works

Rule table version: **3**. The version goes up by one whenever a rule,
cap, or floor changes, so a saved score always says which rules made it.

The score runs from 0 (no red flags found) to 100 (almost certainly dangerous).
It is rule-based. There is no machine learning and no hidden weighting.
Every point in a score comes from one finding, and each finding has a plain
reason and a data source.

## Steps

1. **Collect findings.** The tools check the address with Etherscan, GoPlus,
   DexScreener, public RPC nodes, and a small local list of known bad addresses.
   Each thing they notice becomes a *finding* with a stable ID, such as
   `token.honeypot`.
2. **Give points.** The table below gives each finding ID a number of points.
   Trust signals give negative points.
3. **Do not count twice.** Findings that describe the same problem share a
   *group*. Only the biggest finding in a group counts. For example, "source
   not verified" from GoPlus and from Etherscan count once.
4. **Cap owner powers.** Mint, blacklist, pause, upgrade, withdraw, trade
   limits, and single-wallet ownership all say the same thing: a central
   party controls the contract. Together they add at most 30 points
   (groups: blacklist, limits, mint, pause, single_owner, upgradeable, withdraw). A regulated stablecoin has many of these powers
   and is not a scam. Scam-specific signals such as honeypots, tax tricks, and
   hidden owners are not capped.
5. **Add up and clamp.** Points are added and kept between 0 and 100.
6. **Decisive floor.** Some findings are evidence of fraud or harm, not just
   the ability to cause it, such as a honeypot token or a sanctioned address.
   If one is present, the score is at least 75, however many trust
   signals there are.

## Levels

| Score | Level | Meaning |
|---|---|---|
| 75 to 100 | critical | Very likely dangerous. Do not interact. |
| 50 to 74 | high | Serious red flags. Avoid unless you fully understand the risks. |
| 20 to 49 | medium | Some warning signs. Look closely before interacting. |
| 0 to 19 | low | No major red flags in the data we could check. |

## Confidence

The score also has a confidence: **high** if every data source answered,
**medium** if up to half failed, **low** if more than half failed. Missing
data never lowers the score. It lowers the confidence instead, and the
report says what could not be checked. **A low score with low confidence
does not mean "safe".**

## Rule table

| Finding ID | Points | Group | Decisive |
|---|---:|---|:---:|
| `address.sanctioned` | +90 | sanctioned | yes |
| `address.known_sanctioned` | +90 | sanctioned | yes |
| `address.known_exploit` | +80 | known_bad | yes |
| `address.known_scam` | +80 | known_bad | yes |
| `address.stealing_attack` | +70 | known_bad | yes |
| `address.phishing_activities` | +70 | known_bad | yes |
| `address.cybercrime` | +50 | crime |  |
| `address.money_laundering` | +50 | crime |  |
| `address.financial_crime` | +50 | crime |  |
| `address.blackmail_activities` | +50 | crime |  |
| `address.darkweb_transactions` | +50 | crime |  |
| `address.malicious_contracts_created` | +50 |  |  |
| `address.honeypot_related_address` | +40 |  |  |
| `address.honeypot_related_token` | +0 |  |  |
| `address.usdc_blocklisted` | +80 | sanctioned | yes |
| `address.eurc_blocklisted` | +80 | sanctioned | yes |
| `address.official_contract` | -30 |  |  |
| `address.fake_token` | +40 |  |  |
| `address.known_mixer` | +40 | mixer |  |
| `address.mixer` | +30 | mixer |  |
| `address.malicious_mining_activities` | +25 |  |  |
| `address.fake_standard_interface` | +25 |  |  |
| `address.fake_kyc` | +20 |  |  |
| `address.blacklist_doubt` | +20 |  |  |
| `address.gas_abuse` | +20 |  |  |
| `address.reinit` | +15 |  |  |
| `wallet.funded_by_risky` | +30 |  |  |
| `wallet.risky_counterparty` | +25 | direct_link |  |
| `wallet.very_new` | +10 | wallet_age |  |
| `wallet.new` | +5 | wallet_age |  |
| `wallet.no_history` | +5 | wallet_age |  |
| `wallet.many_failed_txs` | +5 |  |  |
| `wallet.established` | -10 |  |  |
| `wallet.delegated_code` | +0 |  |  |
| `token.honeypot` | +60 | honeypot | yes |
| `token.airdrop_scam` | +60 |  | yes |
| `token.fake_token` | +60 |  | yes |
| `token.owner_can_change_balance` | +50 | balance_control |  |
| `token.extreme_sell_tax` | +45 | sell_tax | yes |
| `token.cannot_sell_all` | +35 | honeypot |  |
| `token.no_sells` | +35 | honeypot |  |
| `token.creator_made_honeypots` | +30 |  |  |
| `token.per_wallet_tax` | +30 | fees |  |
| `token.not_open_source` | +25 | unverified |  |
| `token.hidden_owner` | +25 |  |  |
| `token.can_take_back_ownership` | +25 |  |  |
| `token.selfdestruct` | +20 | selfdestruct |  |
| `token.no_liquidity` | +20 | liquidity |  |
| `token.mintable` | +15 | mint |  |
| `token.mintable_renounced` | +3 | mint |  |
| `token.tax_modifiable` | +15 | fees |  |
| `token.high_sell_tax` | +15 | sell_tax |  |
| `token.extreme_concentration` | +15 | concentration |  |
| `token.high_concentration` | +8 | concentration |  |
| `token.high_buy_tax` | +10 |  |  |
| `token.cannot_buy` | +10 |  |  |
| `token.insider_holds_large_share` | +10 |  |  |
| `token.low_liquidity` | +10 | liquidity |  |
| `token.liquidity_not_locked` | +10 |  |  |
| `token.very_new_pool` | +10 | age |  |
| `token.new_pool` | +4 | age |  |
| `token.proxy` | +10 | upgradeable |  |
| `token.transfer_pausable` | +10 | pause |  |
| `token.blacklist` | +10 | blacklist |  |
| `token.whitelist` | +3 |  |  |
| `token.trading_cooldown` | +3 |  |  |
| `token.anti_whale_modifiable` | +3 |  |  |
| `token.external_call` | +3 |  |  |
| `token.goplus_note` | +0 |  |  |
| `token.trusted` | -40 |  |  |
| `contract.unverified` | +25 | unverified |  |
| `contract.verified` | +0 |  |  |
| `contract.upgradeable_by_wallet` | +20 | upgradeable |  |
| `contract.upgradeable` | +8 | upgradeable |  |
| `contract.implementation_unverified` | +15 |  |  |
| `contract.selfdestruct` | +20 | selfdestruct |  |
| `contract.owner_is_single_wallet` | +8 | single_owner |  |
| `contract.very_new` | +10 | age |  |
| `contract.ownership_renounced` | -5 |  |  |
| `contract.owner_is_multisig` | -5 |  |  |
| `trace.direct.sanctioned` | +60 | direct_link |  |
| `trace.direct.exploit` | +45 | direct_link |  |
| `trace.direct.scam` | +40 | direct_link |  |
| `trace.direct.mixer` | +30 | direct_link |  |
| `trace.direct.flagged` | +30 | direct_link |  |
| `trace.direct.blocklisted` | +50 | direct_link |  |
| `trace.indirect.sanctioned` | +15 | indirect_link |  |
| `trace.indirect.exploit` | +10 | indirect_link |  |
| `trace.indirect.scam` | +10 | indirect_link |  |
| `trace.indirect.mixer` | +8 | indirect_link |  |
| `trace.indirect.flagged` | +8 | indirect_link |  |
| `trace.indirect.blocklisted` | +12 | indirect_link |  |

Findings without their own rule get points from their severity:
critical = 40, high = 15, medium = 8, low = 2, info = 0. Risky functions found in a contract (`contract.fn.*`) use these
severity points too. Their severity is lowered when the owner has renounced
control, because nobody can call owner-only functions any more.

## Extra checks on Arc

Arc is Circle's chain, and its native coin is USDC. Three things are
different there, and the tools handle each one:

- **Blocklists.** The USDC and EURC contracts on Arc keep a public
  blocklist. Every address checked is looked up in both
  (`address.usdc_blocklisted`, `address.eurc_blocklisted`). A blocked
  address cannot send or receive that coin, and a transfer to it fails
  and still costs the fee. These findings share the sanctions group, so a
  sanctioned and blocked address is not counted twice. Fund tracing also
  checks the addresses it finds (`trace.direct.blocklisted`,
  `trace.indirect.blocklisted`).
- **One USDC stream.** Every USDC move is logged once by a system address
  (EIP-7708) with 18 decimals. ERC-20 transfers are also logged a second
  time by the USDC contract with 6 decimals. The tools read only the
  system stream, so no move is missed or counted twice.
- **Two views of one balance.** The native balance (18 decimals) and the
  ERC-20 balance (6 decimals) are the same money. The tools always use the
  native value and never add the two.

## Limits of this method

- Points were chosen by hand from common scam patterns. They are a
  reasoned starting point, not a statistical model. The evaluation set in the
  repository measures how well they separate known scams from known safe
  addresses.
- The score only knows what its data sources know. A brand-new scam that no
  source has flagged yet can score low.
- Fund tracing looks at recent history only and follows the busiest paths.
