# Pico Bank (CyLab RE — difficulty 2, id 529)

## Đề bài / file đính kèm
- Challenge RE diff2, event "picoMini by CMU-Africa", on-demand instance.
- Mô tả: Android app "Pico Bank"; phải crack username/password từ profile (Alex Johnson, johnson@picobank.com, DOB 14/03/1990, giao dịch cuối $345.67, pet `tricky`, màu yêu thích Blue). Flag có **2 phần**.
- File: trang web instance phục vụ APK: `http://<host>:<port>/download/pico-bank.apk` (link APK KHÔNG nằm trong description API — chỉ xuất hiện sau khi start instance).

## Recon
- Start instance `api.py start 529` → description lộ link web; index page link tới `/download/pico-bank.apk` (6.6 MB).
- `apktool d pico-bank.apk` → package `com.example.picobank`, dùng **Volley**. App classes: `Login`, `OTP`, `MainActivity`, `Transaction`, `TransactionAdapter`, `Notification`, `Splash`.

## Lỗ hổng phát hiện
- **Login client-side hardcode** (`Login$1.smali`): username `johnson` (tên cuối), password `tricky1990` (pet + năm sinh). Không hash, không gửi server.
- **OTP hardcode** trong resource: `otp_value = 9673` (`res/values/strings.xml:158`), so sánh local, KHÔNG liên quan mạng.
- **Chỉ 1 network call**: `POST /verify-otp` body `{"otp":"<4 số>"}` (base URL trong APK là placeholder `"your server url"` → phải lấy host:port từ instance). Response `{success, flag, hint}`; `MainActivity` KHÔNG đọc extras `flag`/`hint` ⇒ chỉ thấy trong HTTP response thô.
- **Flag part1 giấu trong lịch sử giao dịch** (`MainActivity.smali`): trường "số tiền" của mỗi transaction là **nhị phân 7-bit** (`$ 1110000` = `0x70` = `'p'`). Đọc theo thứ tự hiển thị → `picoCTF{1_l13d_4b0ut_b31ng_`.
  - **Bẫy register reuse**: nhiều entry (`Water Bill`, `Transport`, `Insurance`, `Vacation`, `Home Repairs`, `Charity Donation`, `Childcare`) truyền lại register (v9/v10/v11/v12) đã set ở entry khác ⇒ phải **mô phỏng gán register tuần tự** khi đọc smali, nếu chỉ regex `const-string .* "\$ [01]+"` sẽ thiếu ký tự.

## Kỹ thuật khai thác
1. Trích số tiền theo thứ tự, mô phỏng register reuse → ghép ký tự → part1.
2. `POST /verify-otp {"otp":"9673"}` → response chứa part2.
3. Ghép: `academy{` + part1 + part2.

## Exploit script
Xem file [exploit.py](exploit.py) (parse smali có mô phỏng register + POST OTP).

## Flag
`academy{redacted}`
- part1 (APK): `1_l13d_4b0ut_b31ng_`
- part2 (server OTP): `s3cur3d_...`

## Bài học / pattern để tái sử dụng
- **Link file có thể KHÔNG ở API description**: với instance on-demand, start rồi mới thấy web/URL phục vụ file. Luôn start + scrape trang index trước khi kết luận "không có file".
- **Stego dữ liệu số**: "số tiền"/số liệu UI có thể là nhị phân/hex/ASCII ⇒ thử decode `int(x,2)`, hex, base...; hint "investigate transaction history" là chỉ điểm.
- **Register reuse trong smali**: khi trích hằng số, phải đi theo luồng gán register (không chỉ regex dòng `const-string`); entry sau có thể tái dùng register của entry trước.
- **Đọc URL/config trong APK**: host có thể là placeholder ("your server url") → lấy host:port thật từ instance, đừng mất thời gian tìm "secret URL" không tồn tại.
- Flag gốc picoCTF dùng prefix `picoCTF{`; bản rehost CyLab thay bằng `academy{`.
