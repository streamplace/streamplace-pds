// The sign-in bridge's pages: the form_post return, and Sign-In with Ethereum
// with a browser wallet (found by EIP-6963, else window.ethereum).
"use strict";
(function () {
  const body = document.body;
  if (body.dataset.autopost) {
    document.forms[0].submit();
    return;
  }
  if (body.dataset.method !== "siwe") return;

  const base = body.dataset.issuerPath;
  const request = body.dataset.request;
  const list = document.getElementById("wallets");
  const status = document.getElementById("status");
  const wallets = new Map(); // uuid -> { info, provider }
  let busy = false;

  function say(text, isError) {
    status.textContent = text;
    status.classList.toggle("error", !!isError);
  }

  function setDisabled(on) {
    for (const b of list.querySelectorAll("button")) b.disabled = on;
  }

  async function post(path, payload) {
    const r = await fetch(`${base}/${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(payload),
    });
    let j = {};
    try {
      j = await r.json();
    } catch (_) {}
    if (!r.ok) throw new Error(j.error || `The sign-in service answered ${r.status}.`);
    return j;
  }

  // personal_sign takes the message as hex-encoded UTF-8
  function utf8Hex(s) {
    return "0x" + Array.from(new TextEncoder().encode(s), (b) => b.toString(16).padStart(2, "0")).join("");
  }

  async function signIn(provider) {
    if (busy) return;
    busy = true;
    setDisabled(true);
    try {
      say("Waiting for your wallet…");
      const accounts = await provider.request({ method: "eth_requestAccounts" });
      if (!accounts || !accounts.length) throw new Error("Your wallet didn't share an account.");
      const address = accounts[0];
      const { message } = await post("challenge", { request, address });
      say("Sign the message in your wallet…");
      const signature = await provider.request({ method: "personal_sign", params: [utf8Hex(message), address] });
      say("Checking the signature…");
      const { next } = await post("verify", { request, message, signature });
      say("Signed in. Returning to the app…");
      location.assign(next);
    } catch (e) {
      busy = false;
      setDisabled(false);
      say(e && e.code === 4001 ? "You declined in your wallet." : (e && e.message) || String(e), true);
    }
  }

  function render() {
    list.replaceChildren();
    for (const { info, provider } of wallets.values()) {
      const b = document.createElement("button");
      b.type = "button";
      if (typeof info.icon === "string" && info.icon.startsWith("data:image/")) {
        const img = document.createElement("img");
        img.src = info.icon;
        img.alt = "";
        b.append(img);
      }
      b.append(document.createTextNode(`Continue with ${info.name}`));
      b.addEventListener("click", () => signIn(provider));
      list.append(b);
    }
  }

  window.addEventListener("eip6963:announceProvider", (e) => {
    const d = e.detail;
    if (!d || !d.info || !d.provider || !d.info.uuid) return;
    wallets.set(d.info.uuid, d);
    render();
  });
  window.dispatchEvent(new Event("eip6963:requestProvider"));

  // wallets that predate EIP-6963 only set window.ethereum
  setTimeout(() => {
    if (wallets.size) return;
    if (window.ethereum) {
      wallets.set("injected", { info: { name: "your browser wallet", uuid: "injected" }, provider: window.ethereum });
      render();
      return;
    }
    say(
      "No wallet found in this browser. Install a wallet extension such as MetaMask, or open this page in your wallet app's browser.",
      true,
    );
  }, 500);
})();
