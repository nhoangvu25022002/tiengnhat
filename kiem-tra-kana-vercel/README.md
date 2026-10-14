# Kiểm Tra Kana (bản Vercel)

Trang thi trắc nghiệm Hiragana và Katakana cho nhiều người dùng chung.

- `/` trang thi: đăng nhập bằng họ tên và số điện thoại, 2 phần thi, chấm điểm tự động, xem điểm của mình.
- `/admin` trang quản lý: cần mật khẩu, xem toàn bộ bài làm, tìm kiếm, xóa, xuất Excel.

## Cấu trúc

- `public/` các trang web (index.html, admin.html, style.css)
- `api/index.js` máy chủ: nhận bài, chấm lại điểm, kiểm tra mật khẩu quản trị
- `lib/kana.js` bảng chữ Hiragana và Katakana dùng để chấm
- `vercel.json`, `package.json` cấu hình, không cần sửa

## Biến môi trường cần có

| Tên | Từ đâu |
| --- | --- |
| `KV_REST_API_URL`, `KV_REST_API_TOKEN` (hoặc `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`) | tự thêm khi gắn Upstash Redis vào dự án |
| `ADMIN_PASSWORD` | bạn tự đặt trong Settings, Environment Variables |

Sau khi thêm hoặc đổi biến, phải **Redeploy** thì máy chủ mới đọc được giá trị mới.
