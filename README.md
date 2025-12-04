# DES Cipher CLI Tool

## Giới thiệu

Công cụ dòng lệnh (CLI) cho việc mã hóa và giải mã văn bản bằng thuật toán DES (Data Encryption Standard). Dự án này được khởi tạo từ khung CLI refactor sẵn có, giúp bạn nhanh chóng thử nghiệm DES trên văn bản.

## Tính năng

- Mã hóa/giải mã văn bản sử dụng DES (block cipher 64-bit, key 56-bit hiệu dụng).
- Nhập văn bản trực tiếp, từ stdin (pipe) hoặc từ file.
- Giao diện dòng lệnh thân thiện, có tùy chọn copy ra clipboard / lưu file.
- Giữ nguyên xử lý chữ hoa/thường và ký tự không phải chữ cái theo cách an toàn (theo logic sẵn có, sẽ cập nhật theo đặc tả DES khi bạn bổ sung mã DES).

## Yêu cầu

- Python 3.7+ (được định nghĩa trong `pyproject.toml`).
- Các thư viện giao diện tùy chọn: `pyfiglet`, `colorama`, `pyperclip` (nếu cài sẽ có banner/màu/copy clipboard).

## Cài đặt và chạy

1. Cài đặt (editable):
   ```bash
   pip install -e .
   ```
2. Chạy chương trình:
   ```bash
   des
   ```
   (entry-point đã đổi sang lệnh `des`; bạn có thể đổi lại tùy ý trong `pyproject.toml`).

## Ghi chú

- Mã nguồn DES chưa được triển khai; hiện tại giữ nguyên khung CLI và logic mã hóa cũ để bạn thay thế bằng DES ở các bước tiếp theo.
- Bạn có thể bắt đầu bằng cách thay thế/viết mới `cipher.py` và luồng xử lý trong `workflows.py` cho phù hợp với DES.
