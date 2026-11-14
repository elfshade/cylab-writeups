# 529 Pico Bank — APK login/credential/flag/OTP logic (worker: apk-logic)

Decoded tree: `/home/thang/cylab-re/529/dec` (smali_classes3 = app code).

## Username & password (hardcoded plaintext comparison)
`smali_classes3/com/example/picobank/Login$1.smali:76-90` (onClick):
```
const-string v2, "johnson"      ; username
... v2.equals(username)  -> must match
const-string v2, "tricky1990"   ; password
... v2.equals(password)  -> must match
```
- **username = `johnson`**, **password = `tricky1990`**. No hashing/encoding/base64/xor — direct `.equals()`.
- Derivation from profile: `johnson` = email local-part (`johnson@picobank.com`); `tricky1990` = pet name `tricky` + DOB year `1990`.
- Success -> starts `OTP` activity (`Login$1.smali:93-110`); failure -> Toast "Incorrect credentials".
- Not used for anything server-side (login is purely client-side gate).

## Flag part 1 — IS in the APK, hidden as binary transaction amounts
- No literal `academy{`/`picoCTF{` anywhere (grep of dec/ = empty); flag is encoded.
- `MainActivity.smali:185-567`: each Transaction amount like `"$ 1110000"` is **7-bit (or shorter) binary ASCII**, displayed as if money. Decode `int(bits,2)` -> `chr`.
  - e.g. `$ 1110000`=112='p', `$ 1101001`=105='i', `$ 1100011`=99='c', ...
- Decoded in insertion (display) order, all 27 transactions:
  **`picoCTF{1_l13d_4b0ut_b31ng_`** (27 chars, ends with `_`, unclosed).
- `TransactionAdapter.smali:117-123` just renders amount text; nothing else hidden there. `Transaction.smali` is a plain POJO.
- Cross-checked: public picobank writeups confirm the same 27-char prefix.

## OTP flow
- `OTP.smali:111-244` `verifyOtp(otp)`:
  - `OTP.smali:116` server URL constant is the literal placeholder `"your server url"` (+ `/verify-otp`, line 128). Real URL is external (see network worker).
  - `OTP.smali:140-154` compares entered OTP against **`R$string;->otp_value`** (client-side).
  - `res/values/strings.xml:158` -> `<string name="otp_value">9673</string>`  => **OTP = `9673`** (4-digit).
  - Regardless of local match, it POSTs a `JsonObjectRequest` (POST) to `.../verify-otp` with body `{"otp":"<otp>"}` (`OTP.smali:188-235`).
- Server response handled in `OTP$2.smali:59-115`; JSON fields expected:
  - `"success"` (boolean) — `OTP$2.smali:69-77`
  - `"flag"` (string) — read only when success, `OTP$2.smali:80`
  - `"hint"` (string) — `OTP$2.smali:86` (likely `"The other part of the flag is hidden in the app"`)
  - (upstream also returns `"message":"OTP verified successfully"`.)
- On success both `flag` and `hint` are passed as Intent extras to MainActivity; error path `OTP$3.smali:39-44` is a no-op.
- **What the server returns after correct OTP:** `{"success":true, ..., "flag":"<part2>", "hint":"..."}` where part2 is the closing suffix ending in `}` (e.g. `s3cur3d_m0b1l3_l0g1n_f59ef39a}`; hash varies per instance).

## Full flag assembly
`<APK part1>` + `<server flag part2>` = e.g. `picoCTF{1_l13d_4b0ut_b31ng_s3cur3d_...}`.
NOTE: embedded prefix is literally `picoCTF{` not `academy{`. If the CyLab instance expects `academy{...}`, the inner content is `1_l13d_4b0ut_b31ng_` + server suffix; orchestrator decides the prefix.

## Secrets/keys
- Only secret material: login `johnson`/`tricky1990`, OTP `9673`, flag-part1 binary sequence. No crypto keys, no base64 blobs in APK. `Splash`/`Notification` are pure UI.
