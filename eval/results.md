# Evaluation results

Generated 2026-09-30 with web3-risk-mcp 0.1.0 (live data). An address is flagged as risky when its score is 50 or more.

| Metric | Full scorer | Without local address list |
|---|---:|---:|
| ROC AUC (1.0 = perfect separation) | 0.951 | 0.894 |
| Accuracy | 0.882 | 0.824 |
| Precision (flagged items that are risky) | 0.786 | 0.75 |
| Recall (risky items that got flagged) | 0.917 | 0.75 |
| False alarms on safe items | 3 of 22 | 3 of 22 |
| Missed risky items | 1 of 12 | 3 of 12 |
| Mean score, risky / safe | 83.8 / 20.0 | 73 / 21.0 |

## Every item (full scorer)

| Label | Name | Chain | Score | Level | Confidence | Main reasons |
|---|---|---|---:|---|---|---|
| risky | Honeypot token (blacklist) | ethereum | 100 | critical | high | token.hidden_owner (+25), token.extreme_concentration (+15), token.high_sell_tax (+15), token.tax_modifiable (+15) |
| risky | Fake_Phishing7459364 | ethereum | 100 | critical | high | address.phishing_activities (+70), contract.unverified (+25), address.blacklist_doubt (+20) |
| risky | Ronin Bridge Exploiter | ethereum | 100 | critical | high | address.sanctioned (+90), address.stealing_attack (+70), trace.direct.exploit (+45), address.blacklist_doubt (+20) |
| risky | Bybit Exploiter 1 | ethereum | 100 | critical | high | address.known_exploit (+80), trace.direct.flagged (+30), address.blacklist_doubt (+20) |
| risky | Euler Finance Exploiter 2 | ethereum | 100 | critical | high | address.known_exploit (+80), wallet.risky_counterparty (+25) |
| risky | Wormhole Network Exploiter | ethereum | 100 | critical | high | address.known_exploit (+80), trace.direct.mixer (+30) |
| risky | Fake_Phishing6102 | ethereum | 90 | critical | high | address.stealing_attack (+70), address.blacklist_doubt (+20) |
| risky | Fake_Phishing184810 (address poisoning) | ethereum | 80 | critical | high | address.phishing_activities (+70), address.blacklist_doubt (+20), wallet.established (-10) |
| risky | Fake_Phishing608048 | ethereum | 80 | critical | high | address.phishing_activities (+70), address.blacklist_doubt (+20), wallet.established (-10) |
| risky | Tornado Cash 1 ETH pool (mixer) | ethereum | 63 | high | high | address.known_mixer (+40), contract.implementation_unverified (+15), contract.upgradeable (+8) |
| risky | Tornado Cash 10 ETH pool (mixer) | ethereum | 63 | high | high | address.known_mixer (+40), contract.implementation_unverified (+15), contract.upgradeable (+8) |
| risky | SQUID (Squid Game token, 2021 rug pull) | bsc | 30 | medium | medium | contract.upgradeable_by_wallet (+20), contract.implementation_unverified (+15), contract.ownership_renounced (-5) |
| safe | USDT | ethereum | 78 | critical | high | token.owner_can_change_balance (+50), token.trusted (-40), contract.fn.blacklist (+15), token.mintable (+15) |
| safe | USDC on Arbitrum | arbitrum | 74 | high | high | contract.upgradeable_by_wallet (+20), contract.fn.blacklist (+15), contract.fn.mint (+15), contract.fn.pause (+8) |
| safe | USDC on Polygon | polygon | 74 | high | high | contract.upgradeable_by_wallet (+20), contract.fn.blacklist (+15), contract.fn.mint (+15), contract.fn.pause (+8) |
| safe | WETH on Base | base | 48 | medium | medium | address.honeypot_related_address (+40), token.high_concentration (+8) |
| safe | stETH (Lido, upgradeable) | ethereum | 36 | medium | high | token.liquidity_not_locked (+10), token.proxy (+10), contract.fn.pause (+8), token.high_concentration (+8) |
| safe | USDC | ethereum | 34 | medium | high | token.trusted (-40), contract.upgradeable_by_wallet (+20), contract.fn.blacklist (+15), contract.fn.mint (+15) |
| safe | USDC on Base | base | 34 | medium | medium | token.trusted (-40), contract.upgradeable_by_wallet (+20), contract.fn.blacklist (+15), contract.fn.mint (+15) |
| safe | vitalik.eth | ethereum | 25 | medium | high | contract.unverified (+25) |
| safe | AAVE | ethereum | 20 | medium | high | token.liquidity_not_locked (+10), token.proxy (+10) |
| safe | Aave V3 Pool | ethereum | 16 | low | medium | contract.fn.withdraw (+8), contract.upgradeable (+8) |
| safe | DAI | ethereum | 0 | low | high | token.trusted (-40), token.mintable (+15) |
| safe | WETH | ethereum | 0 | low | high | token.trusted (-40), token.high_concentration (+8) |
| safe | UNI | ethereum | 0 | low | high | token.trusted (-40), token.insider_holds_large_share (+10), contract.fn.mint (+2) |
| safe | LINK | ethereum | 0 | low | high | token.trusted (-40) |
| safe | WBTC | ethereum | 0 | low | high | token.trusted (-40), token.mintable (+15), token.transfer_pausable (+10), token.high_concentration (+8) |
| safe | ARB | arbitrum | 0 | low | high | token.trusted (-40), contract.fn.mint (+15), token.proxy (+10) |
| safe | WPOL (wrapped POL) | polygon | 0 | low | high | token.trusted (-40) |
| safe | WBNB | bsc | 0 | low | medium | token.trusted (-40) |
| safe | USDT on BNB Chain | bsc | 0 | low | medium | token.trusted (-40), token.mintable (+15), contract.owner_is_single_wallet (+8) |
| safe | CAKE | bsc | 0 | low | medium | token.trusted (-40), token.mintable (+15) |
| safe | Uniswap V2 Router 2 | ethereum | 0 | low | medium | none |
| safe | Binance 14 (exchange hot wallet) | ethereum | 0 | low | high | wallet.established (-10) |
