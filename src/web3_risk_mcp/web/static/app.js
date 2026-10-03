// Arc Safe Send front end.
// It calls the server's read-only check, shows the result, and can ask the
// user's own browser wallet to send USDC. The server never sees a key.
"use strict";

(function () {
  const $ = (id) => document.getElementById(id);
  const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
  const LEVEL_NAMES = { low: "Low risk", medium: "Medium risk", high: "High risk", critical: "Critical risk" };
  const TYPE_NAMES = { wallet: "Wallet", token: "Token contract", contract: "Smart contract", unknown: "Unknown" };

  let config = null;   // from /api/config
  let current = null;  // the last check response
  let slowTimer = null;

  // ---- Helpers --------------------------------------------------------------

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs || {})) {
      if (key === "className") node.className = value;
      else node.setAttribute(key, value);
    }
    for (const child of children) {
      if (child === null || child === undefined) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function setStatus(node, text, kind) {
    node.textContent = text || "";
    node.classList.remove("error", "ok");
    if (kind) node.classList.add(kind);
  }

  function shortAddress(a) {
    return a.slice(0, 6) + "…" + a.slice(-4);
  }

  // USDC amounts are turned into whole units with BigInt, never floats, so no
  // rounding can change what is sent. Arc's native USDC has 18 decimals.
  // We accept at most 6 decimal places, the precision of USDC everywhere else.
  function parseUsdc(text) {
    const clean = String(text).trim();
    if (!/^\d{1,12}(\.\d{1,6})?$/.test(clean)) return null;
    const [whole, frac = ""] = clean.split(".");
    const value = BigInt(whole) * 10n ** 18n + BigInt((frac + "000000").slice(0, 6)) * 10n ** 12n;
    return value > 0n ? value : null;
  }

  function formatUsdc(units) {
    const whole = units / 10n ** 18n;
    const frac = ((units % 10n ** 18n) / 10n ** 12n).toString().padStart(6, "0").replace(/0+$/, "");
    return frac ? `${whole}.${frac}` : `${whole}`;
  }

  // ---- Setup ----------------------------------------------------------------

  async function loadConfig() {
    const response = await fetch("/api/config");
    config = await response.json();
    const select = $("chain");
    select.textContent = "";
    for (const chain of config.chains) {
      const option = el("option", { value: chain.key }, `${chain.name} (${chain.chain_id})`);
      if (chain.key === config.default_chain) option.selected = true;
      select.append(option);
    }
  }

  function readQuery() {
    const params = new URLSearchParams(window.location.search);
    const address = params.get("address");
    const chain = params.get("chain");
    if (chain && [...$("chain").options].some((o) => o.value === chain)) $("chain").value = chain;
    if (address) {
      $("address").value = address;
      return true;
    }
    return false;
  }

  // ---- Check ----------------------------------------------------------------

  async function runCheck() {
    const address = $("address").value.trim();
    const chain = $("chain").value;
    const status = $("status");
    if (!ADDRESS_RE.test(address)) {
      setStatus(status, "That does not look like an address. It should be 0x followed by 40 letters or numbers (0-9, a-f).", "error");
      $("address").focus();
      return;
    }
    $("result").hidden = true;
    current = null;
    $("check-button").disabled = true;
    setStatus(status, "Checking… this reads several data sources and usually takes 5 to 15 seconds.");
    clearTimeout(slowTimer);
    slowTimer = setTimeout(() => setStatus(status, "Still checking. The first check after a quiet period can take up to a minute while the free server wakes up."), 20000);

    try {
      const response = await fetch("/api/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address, chain }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        const wait = data.retry_after ? ` Try again in ${data.retry_after} seconds.` : "";
        setStatus(status, (data.error || `The check failed (HTTP ${response.status}).`) + wait, "error");
        return;
      }
      current = data;
      setStatus(status, "");
      render(data);
      const url = new URL(window.location.href);
      url.searchParams.set("address", data.result.address);
      url.searchParams.set("chain", data.result.chain);
      window.history.replaceState(null, "", url);
    } catch (err) {
      setStatus(status, "Could not reach the server. Check your connection and try again.", "error");
    } finally {
      clearTimeout(slowTimer);
      $("check-button").disabled = false;
    }
  }

  function render(data) {
    const r = data.result;
    const chain = config.chains.find((c) => c.key === r.chain) || { name: r.chain };
    const card = $("score-card");
    card.className = `card score-card band-${r.level}`;
    $("score").textContent = r.score;
    $("level").textContent = LEVEL_NAMES[r.level] || r.level;
    $("verdict").textContent = r.verdict;
    $("confidence").textContent = r.confidence;
    $("address-type").textContent = TYPE_NAMES[r.address_type] || r.address_type;
    $("chain-name").textContent = chain.name;
    $("checked-address").textContent = r.address;
    const link = $("explorer-link");
    link.href = data.explorer_url;
    link.textContent = `View on ${new URL(data.explorer_url).hostname}`;
    $("band-marker").style.left = `${Math.min(100, Math.max(0, r.score))}%`;
    $("rules-version").textContent = r.rules_version;

    renderReasons(r.contributions);
    renderList($("gaps"), r.data_gaps);
    $("gap-count").textContent = r.data_gaps.length;
    $("gaps-box").open = r.data_gaps.length > 0 && r.confidence !== "high";
    renderSources(r.sources);
    renderList($("notes"), r.notes);
    $("cache-note").textContent = `Checked ${new Date(data.checked_at).toLocaleString()}` +
      (data.cached ? " (saved result, reused to protect the free data limits)." : ".");

    renderPay(data);
    renderAttestation(data);
    $("result").hidden = false;
    $("score-card").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function renderReasons(contributions) {
    const list = $("reasons");
    list.textContent = "";
    $("reasons-empty").hidden = contributions.length > 0;
    for (const c of contributions) {
      const sign = c.points > 0 ? "plus" : c.points < 0 ? "minus" : "zero";
      const points = c.points > 0 ? `+${c.points}` : `${c.points}`;
      const rule = c.rule.charAt(0).toUpperCase() + c.rule.slice(1);
      const meta = `Source: ${c.source}. ${c.counted ? "" : "Not counted. "}${rule}.`;
      list.append(
        el("li", { className: `reason${c.counted ? "" : " not-counted"}` },
          el("span", { className: `points ${sign}`, "aria-label": `${points} points` }, points),
          el("div", {},
            el("p", { className: "reason-title" }, c.title),
            el("p", { className: "reason-detail" }, c.reason),
            el("p", { className: "reason-meta" }, meta))));
    }
  }

  function renderList(node, items) {
    node.textContent = "";
    for (const item of items) node.append(el("li", {}, item));
  }

  function renderSources(sources) {
    const node = $("sources");
    node.textContent = "";
    for (const s of sources) {
      const chip = el("span", { className: `chip ${s.ok ? "ok" : "fail"}`, title: s.error || "answered" },
        `${s.source}: ${s.ok ? "answered" : "failed"}`);
      node.append(el("li", {}, chip));
    }
  }

  // ---- Check, then pay ------------------------------------------------------

  function renderPay(data) {
    const section = $("pay");
    const isArc = data.result.chain === "arc";
    section.hidden = !isArc;
    if (!isArc) return;
    const advice = data.send_advice;
    const list = $("advice");
    list.textContent = "";
    for (const message of advice.messages) {
      const kind = !advice.can_send ? "stop" : advice.needs_confirmation ? "warn" : "";
      list.append(el("li", { className: kind }, message));
    }
    $("confirm-row").hidden = !(advice.can_send && advice.needs_confirmation);
    $("confirm-risk").checked = false;
    $("amount").value = "";
    $("send-button").disabled = !advice.can_send;
    $("amount").disabled = !advice.can_send;
    $("send-button").textContent = advice.can_send ? "Connect wallet and send" : "Sending is blocked";
    setStatus($("pay-status"), "");
  }

  function wallet() {
    if (!window.ethereum) {
      throw new Error("No browser wallet found. Install MetaMask, or another wallet that lets you add networks, then reload this page.");
    }
    return window.ethereum;
  }

  async function switchToArc(provider) {
    const arc = config.arc;
    const target = arc.chain_id_hex.toLowerCase();
    const now = String(await provider.request({ method: "eth_chainId" })).toLowerCase();
    if (now === target) return;
    try {
      await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: arc.chain_id_hex }] });
    } catch (err) {
      const code = err && (err.code ?? (err.data && err.data.originalError && err.data.originalError.code));
      if (code !== 4902) throw err;
      // The wallet does not know Arc yet, so we ask it to add the network.
      await provider.request({
        method: "wallet_addEthereumChain",
        params: [{
          chainId: arc.chain_id_hex,
          chainName: arc.name,
          nativeCurrency: { name: "USDC", symbol: arc.native_symbol, decimals: arc.native_decimals },
          rpcUrls: [arc.rpc_url],
          blockExplorerUrls: [arc.explorer_url],
        }],
      });
    }
    const after = String(await provider.request({ method: "eth_chainId" })).toLowerCase();
    if (after !== target) throw new Error("Your wallet is not on Arc. Switch to Arc and try again.");
  }

  async function waitForReceipt(provider, hash) {
    // Arc settles in under a second, so a short wait is enough.
    for (let i = 0; i < 30; i += 1) {
      const receipt = await provider.request({ method: "eth_getTransactionReceipt", params: [hash] });
      if (receipt) return receipt;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    return null;
  }

  function txLink(hash) {
    return el("a", { href: `${config.arc.explorer_url}/tx/${hash}`, target: "_blank", rel: "noopener noreferrer" }, shortAddress(hash));
  }

  async function sendPayment() {
    const status = $("pay-status");
    if (!current) return;
    const r = current.result;
    const advice = current.send_advice;
    if (!advice.can_send) return;
    const value = parseUsdc($("amount").value);
    if (value === null) {
      setStatus(status, "Enter an amount in USDC, for example 10 or 2.5 (up to 6 decimal places).", "error");
      $("amount").focus();
      return;
    }
    if (advice.needs_confirmation && !$("confirm-risk").checked) {
      setStatus(status, "Read the warnings, then tick the box to confirm before sending.", "error");
      $("confirm-risk").focus();
      return;
    }
    const button = $("send-button");
    button.disabled = true;
    try {
      const provider = wallet();
      setStatus(status, "Asking your wallet to connect…");
      const accounts = await provider.request({ method: "eth_requestAccounts" });
      const from = accounts && accounts[0];
      if (!from) throw new Error("No account was shared by the wallet.");
      await switchToArc(provider);
      const balance = BigInt(await provider.request({ method: "eth_getBalance", params: [from, "latest"] }));
      if (balance < value) {
        throw new Error(`Not enough USDC. This account has ${formatUsdc(balance)} USDC, and the fee is paid in USDC too.`);
      }
      setStatus(status, `Approve the payment of ${formatUsdc(value)} USDC to ${shortAddress(r.address)} in your wallet…`);
      // The payment goes to the exact address that was checked, never to what
      // is in the box now.
      const hash = await provider.request({
        method: "eth_sendTransaction",
        params: [{ from, to: r.address, value: "0x" + value.toString(16) }],
      });
      status.textContent = "";
      status.append("Sent. Waiting for Arc to confirm… ", txLink(hash));
      const receipt = await waitForReceipt(provider, hash);
      status.textContent = "";
      if (receipt && receipt.status === "0x1") {
        status.classList.add("ok");
        status.append(`Done: ${formatUsdc(value)} USDC sent and final on Arc. `, txLink(hash));
      } else if (receipt) {
        status.classList.add("error");
        status.append("The payment failed on Arc (the fee was still charged). ", txLink(hash));
      } else {
        status.append("Sent, but no confirmation yet. Check it on the explorer: ", txLink(hash));
      }
    } catch (err) {
      const rejected = err && err.code === 4001;
      setStatus(status, rejected ? "You cancelled the request in your wallet. Nothing was sent." : (err && err.message) || String(err), "error");
    } finally {
      button.disabled = !advice.can_send;
    }
  }

  // ---- Save the check on Arc (filled in when the contract is configured) ---

  function renderAttestation(data) {
    const section = $("attest");
    section.hidden = !(data.attestation && config.attestation_contract && data.result.chain === "arc");
    if (section.hidden) return;
    const a = data.attestation;
    const fields = $("attest-fields");
    fields.textContent = "";
    const rows = [
      ["Address checked", data.result.address],
      ["Score", `${data.result.score}/100`],
      ["Rule table version", String(data.result.rules_version)],
      ["Findings hash", a.findings_hash],
      ["Contract", config.attestation_contract],
    ];
    for (const [k, v] of rows) fields.append(el("div", {}, el("dt", {}, k), el("dd", {}, el("code", {}, v))));
    setStatus($("attest-status"), "");
    const history = $("attest-history");
    history.textContent = "";
    if (a.history && a.history.length) {
      const list = el("ul", { className: "history" });
      for (const h of a.history) {
        list.append(el("li", {}, `Score ${h.score}/100 (rules v${h.rules_version}) saved by ${shortAddress(h.attester)} on ${new Date(h.timestamp * 1000).toLocaleString()} `, txLink(h.tx_hash)));
      }
      history.append(el("p", { className: "muted small" }, "Earlier checks of this address saved on Arc:"), list);
    }
  }

  async function saveAttestation() {
    const status = $("attest-status");
    if (!current || !current.attestation) return;
    const button = $("attest-button");
    button.disabled = true;
    try {
      const provider = wallet();
      setStatus(status, "Asking your wallet to connect…");
      const accounts = await provider.request({ method: "eth_requestAccounts" });
      const from = accounts && accounts[0];
      if (!from) throw new Error("No account was shared by the wallet.");
      await switchToArc(provider);
      setStatus(status, "Approve the transaction in your wallet…");
      const hash = await provider.request({
        method: "eth_sendTransaction",
        params: [{ from, to: config.attestation_contract, data: current.attestation.calldata }],
      });
      const receipt = await waitForReceipt(provider, hash);
      status.textContent = "";
      if (receipt && receipt.status === "0x1") {
        status.classList.add("ok");
        status.append("Saved on Arc. ", txLink(hash));
      } else {
        status.append("Sent. Check the result on the explorer: ", txLink(hash));
      }
    } catch (err) {
      const rejected = err && err.code === 4001;
      setStatus(status, rejected ? "You cancelled the request in your wallet. Nothing was saved." : (err && err.message) || String(err), "error");
    } finally {
      button.disabled = false;
    }
  }

  // ---- Wire up --------------------------------------------------------------

  document.addEventListener("DOMContentLoaded", async () => {
    $("check-form").addEventListener("submit", (event) => {
      event.preventDefault();
      runCheck();
    });
    for (const button of document.querySelectorAll("[data-address]")) {
      button.addEventListener("click", () => {
        $("address").value = button.getAttribute("data-address");
        $("chain").value = "arc";
        runCheck();
      });
    }
    $("address").addEventListener("input", () => {
      // A payment must always go to the address that was checked.
      if (current && $("address").value.trim().toLowerCase() !== current.result.address) {
        $("result").hidden = true;
        current = null;
      }
    });
    $("send-button").addEventListener("click", sendPayment);
    $("attest-button").addEventListener("click", saveAttestation);
    try {
      await loadConfig();
    } catch (err) {
      setStatus($("status"), "Could not load settings from the server. Reload the page to try again.", "error");
      return;
    }
    if (readQuery()) runCheck();
  });

  // Exposed for tests only.
  window.__safeSend = { parseUsdc, formatUsdc };
})();
