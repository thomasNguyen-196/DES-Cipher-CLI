"""
Application workflows that orchestrate the UI and DES cipher logic.
"""

import sys
from typing import Optional
from . import ui
from . import cipher


def _strip_saved_header(text: str) -> str:
    """
    Removes the single-line header we add when saving (e.g., 'Plaintext — Key: SECRET')
    so reusing a saved file won't accidentally re-process the header.
    """
    lines = text.splitlines()
    if lines and "key:" in lines[0].lower():
        lines = lines[1:]
        while lines and not lines[0].strip():
            lines = lines[1:]
    return "\n".join(lines)


def _read_text_input(label: str) -> str:
    """
    Reads potentially large text either from stdin (if piped), a file, or direct input.
    """
    if not sys.stdin.isatty():
        data = sys.stdin.read()
        return _strip_saved_header(data.rstrip("\n"))

    print(ui.FG["yellow"] + "Văn bản dài (trên ~1k ký tự) nên nhập qua file để tránh bị cắt." + ui.RESET)
    mode = ui.prompt("Chọn nhập trực tiếp [Enter] hoặc gõ 'f' để đọc từ file: ").strip().lower()
    if mode == "f":
        while True:
            path = ui.prompt("Đường dẫn file: ").strip()
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return _strip_saved_header(f.read())
            except Exception as e:
                print(ui.FG["red"] + f"Lỗi đọc file: {e}" + ui.RESET)
                retry = ui.prompt("Thử lại? (y/n): ").strip().lower()
                if retry != "y":
                    return ""
    return ui.prompt(f"{label}: ")


def _read_key() -> str:
    """Prompts for a DES key (string/hex; validation to be added with implementation)."""
    while True:
        key = ui.prompt("Key (ví dụ 8 ký tự ASCII hoặc 16 hex, bạn tự quy ước): ").strip()
        if key:
            return key
        print(ui.FG["red"] + "Key không được để trống. Thử lại." + ui.RESET)


def encrypt_flow():
    """Workflow for encrypting a message."""
    ui.clear()
    ui.banner()
    ui.boxed("ENCRYPT", "Nhập văn bản cần mã hóa và khóa DES.")
    plaintext = _read_text_input("Plaintext")
    key = _read_key()
    ciphertext = cipher.des_encrypt(plaintext, key)
    ui.boxed("KẾT QUẢ", ciphertext)
    post_output_actions(ciphertext, key=key, label="Ciphertext")


def decrypt_flow():
    """Workflow for decrypting a message."""
    ui.clear()
    ui.banner()
    ui.boxed("DECRYPT", "Nhập ciphertext và khóa DES.")
    ciphertext = _read_text_input("Ciphertext")
    key = _read_key()
    plaintext = cipher.des_decrypt(ciphertext, key)
    ui.boxed("KẾT QUẢ", plaintext)
    post_output_actions(plaintext, key=key, label="Plaintext")


def post_output_actions(text: str, key: Optional[str] = None, label: str = ""):
    """
    Handles actions after a result is generated (copy, save, etc.).
    When saving to file, the key (if provided) is written alongside the output.
    """
    print()
    print(ui.FG["cyan"] + "[1] Copy vào clipboard (nếu có pyperclip)   [2] Lưu vào file   [Enter] Quay lại" + ui.RESET)
    cmd = ui.prompt("Chọn: ").strip()
    if cmd == "1":
        if ui.pyperclip:
            try:
                ui.pyperclip.copy(text)
                print(ui.FG["green"] + "Đã copy vào clipboard." + ui.RESET)
            except Exception as e:
                print(ui.FG["red"] + f"Copy thất bại: {e}" + ui.RESET)
        else:
            print(ui.FG["yellow"] + "pyperclip không cài, không thể copy. Bạn có thể pip install pyperclip." + ui.RESET)
    elif cmd == "2":
        fname = ui.prompt("Tên file lưu (mặc định output.txt): ").strip() or "output.txt"
        content = text
        if key is not None:
            header_parts = []
            if label:
                header_parts.append(label)
            header_parts.append(f"Key: {key}")
            header = " — ".join(header_parts)
            content = f"{header}\n\n{text}"
        try:
            with open(fname, "w", encoding="utf-8") as f:
                f.write(content)
            print(ui.FG["green"] + f"Đã lưu vào {fname}" + ui.RESET)
        except Exception as e:
            print(ui.FG["red"] + f"Lưu thất bại: {e}" + ui.RESET)
    else:
        return
    ui.prompt("Nhấn Enter để tiếp tục...")


def show_help():
    """Displays the help screen."""
    ui.clear()
    ui.banner()
    help_text = (
        "Hướng dẫn ngắn:\n"
        "- Mã hóa/giải mã bằng thuật toán DES (đang xây dựng, placeholder cho logic DES).\n"
        "- Văn bản dài có thể đọc từ file (chọn 'f') hoặc pipe: cat file.txt | des\n"
        "- Sau khi có kết quả, bạn có thể copy hoặc lưu file.\n"
        "- Nếu muốn giao diện xịn hơn: pip install pyfiglet colorama pyperclip\n"
    )
    ui.boxed("HELP", help_text)
    ui.prompt("Nhấn Enter để về menu...")
