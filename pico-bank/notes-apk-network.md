# APK network layer — com.example.picobank (CyLab 529 "Pico Bank")

## Bottom line
The app performs exactly **ONE** HTTP call: OTP verification (`POST /verify-otp`).
All login/OTP gate logic is **client-side static strings**; the server is only
contacted to validate the OTP and return `{success, flag, hint}`.

## Base URL — literal placeholder (NOT obfuscated)
- `OTP.smali:116` `const-string v0, "your server url"` (local `.local v0, "severUrl"`).
  There is **no real host/port anywhere in the APK** (checked all smali, res/values*,
  assets/, res/xml, AndroidManifest). No base64/split/concatenated secret URL.
- Author's published build ships the placeholder; real base must come from the
  website/instance (brief: `http://xebec.cylabacademy.net:39382`, port varies).
- Dev hint: `res/xml/network_security_config.xml` permits cleartext **only** to
  `10.0.2.2` (Android-emulator alias for host loopback) ⇒ during dev the base was
  `http://10.0.2.2:<port>`. All other cleartext HTTP is blocked by the config.

## URL assembly
- `OTP.smali:120-136` `StringBuilder` → `append(severUrl)` + `append("/verify-otp")`
  (`OTP.smali:128`). Simple base + path concat; no trailing-slash handling.

## Endpoint list
| Method | Path | Request | Auth |
|---|---|---|---|
| POST | `/verify-otp` | JSON `{"otp": "<4 digits>"}` | none |

- Method POST: `OTP.smali:227` `const/4 v3, 0x1` passed as JsonObjectRequest method;
  request built at `OTP.smali:217-235` (`JsonObjectRequest(method,url,body,listener,err)`).
- Request body: `OTP.smali:197` key `"otp"` (String), value = 4 EditText digits
  concatenated in `OTP$1.smali:54-128` (digit1..4 order).
- **No** auth headers, tokens, cookies, API keys, or extra params anywhere.

## Expected response JSON (parsed in `OTP$2.smali`)
- `success` (bool) — `OTP$2.smali:69-71`; if false → Toast "Invalid OTP".
- `flag` (string) — `OTP$2.smali:66,80-82`.
- `hint` (string) — `OTP$2.smali:64,86-88`.
- On success both are put as Intent extras `"flag"`/`"hint"` and MainActivity opens
  (`OTP$2.smali:92-110`). **MainActivity never reads them** — no `getIntent`/
  `getStringExtra`/`getExtras` exists in the app ⇒ flag is NOT rendered in the UI.
  It is only observable by capturing the raw HTTP response.
- Error listener `OTP$3.smali:onErrorResponse` is empty (silent failure).

## Related client-side secrets (context for other workers)
- Login creds **hardcoded client-side**, not sent to server:
  username `"johnson"` `Login$1.smali:76`, password `"tricky1990"` `Login$1.smali:84`.
- OTP expected value static: `res/values/strings.xml:158` `otp_value = 9673`;
  compared locally at `OTP.smali:144-150`. Passing this check does NOT involve the
  network (local `getString().equals(otp)`).
- Hardcoded UI hint Toast `MainActivity.smali:95`: "Have you analyzed the server's
  response when handling OTP requests?" → confirms flag is in the `/verify-otp` reply.
- `Transaction.smali` / `TransactionAdapter` are pure UI (no network); the odd
  binary-looking `$ 1xxxxxx` amounts in MainActivity are display-only.

## Ambiguous / not found
- Real base URL: absent from APK (placeholder). Must be taken from the live instance.
- App declares INTERNET + `debuggable=true`, but no other endpoints (login, txs,
  notifications) touch the network — those screens are hardcoded local data.
- Port is dynamic (changes on restart) → use brief's current `host:port`.
