# Checkpass (CyLab Academy / picoCTF 2021 — RE, difficulty 3)

## Đề bài / file đính kèm
- `checkpass` (ELF x86-64, PIE, stripped, ~358KB — binary **Rust**).
- Mô tả: *"What is the password?"* — Flag format `academy{...}`.
- Hint: *"How is the password being checked?"*

## Recon
- Rust binary (nhiều symbol `_Unwind`, `pthread_*`). `main` chỉ gọi `sub_3BFF0(&v4, ..., a1, a2, 0)` với `v4 = sub_15CA0` ⇒ logic thật nằm ở **`sub_15CA0`**.
- `sub_15CA0` đọc arg, kiểm tra:
  - `v28[5] == 41` → độ dài password **41**.
  - `*(qword*)pw == 0x7B796D6564616361` = `"academy{"`, `pw[40] == '}'`.
  - Lấy 32 byte `pw[8..40)` → `sub_168C0(ptr, pw+8)` → nếu `sub_16360(ptr)` đúng thì `sub_16920()` in `"Success"`.
- `sub_168C0`: áp `sub_16940` **4 vòng** (round `0,1,2,3`).
- `sub_16940(a1, a2, r)`:
  1. Thay thế từng byte `a2[i] = sbox_r[a2[i]]` với `sbox_r = byte_8470[r*256 ..]`.
  2. Hoán vị: `a1[out] = a2[ perm_r[out] ]` với `perm_r` = 32 qword tại `asc_9FB0[r*256 + 8*out]`.
- `sub_16360`: so `a1[0..31]` với bảng `byte_9F70` (32 byte).

## Lỗ hổng phát hiện
- Chương trình mã hóa 32 byte nội dung flag theo cấu trúc SPN (Substitution-Permutation Network) 4 vòng với các bảng S-box và hoán vị cố định trong file ELF.
- Mọi phép toán trong từng vòng đều là song ánh (bijective / khả nghịch) ⇒ có thể giải mã ngược trực tiếp từ ciphertext mà không cần brute-force.

## Kỹ thuật khai thác (chạy ngược)
- Biết kết quả cuối `byte_9F70`; đảo từng vòng theo thứ tự **3→0**:
  - Đảo hoán vị: `sub[perm_r[out]] = state[out]`.
  - Đảo Sbox: tra bảng nghịch đảo của `sbox_r`.
- Ghép `academy{` + 32 byte tìm được + `}`.
- Bảng lấy trực tiếp từ file bằng `pwntools`: `ELF(f).read(0x8470, 1024)`, `.read(0x9FB0, 1024)`.

## Exploit script
Xem file [exploit.py](exploit.py) — đảo 4 vòng, in password.

## Flag
`academy{redacted}`

## Bài học / pattern để tái sử dụng
- **Binary Rust stripped**: đừng sợ kích thước lớn; tìm hàm thực tế được truyền vào harness/runtime (`main` thường chỉ wrap runtime khởi động).
- **Mã hoá dạng SPN / vòng lặp có S-box + Permutation**: nếu không có phụ thuộc khóa bí mật ngoài (bảng S-box và Permutation cố định trong binary), thuật toán luôn **khả nghịch hoàn toàn** theo chiều ngược lại.
