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


def _read_mode() -> str:
    """Prompts for mode: ecb or cfb."""
    while True:
        mode = ui.prompt("Mode (ecb/cfb) [ecb]: ").strip().lower() or "ecb"
        if mode in ("ecb", "cfb"):
            return mode
        print(ui.FG["red"] + "Mode không hợp lệ, chọn ecb hoặc cfb." + ui.RESET)


def _read_iv(optional: bool = False) -> Optional[str]:
    """
    Prompts for IV (16 hex hoặc 8 ký tự). When optional is True, empty IV returns None (auto-gen).
    """
    while True:
        iv = ui.prompt("IV (16 hex hoặc 8 ký tự, bỏ trống để tự sinh): ").strip()
        if iv:
            return iv
        if optional:
            return None
        print(ui.FG["red"] + "CFB cần IV. Thử lại." + ui.RESET)


def encrypt_flow():
    """Workflow for encrypting a message."""
    ui.clear()
    ui.banner()
    ui.boxed("ENCRYPT", "Nhập văn bản cần mã hóa và khóa DES. Chọn mode (ecb/cfb).")
    plaintext = _read_text_input("Plaintext")
    key = _read_key()
    mode = _read_mode()
    iv = _read_iv(optional=True) if mode == "cfb" else None
    cipher_hex, iv_hex = cipher.des_encrypt(plaintext, key, mode=mode, iv=iv)

    title = f"Ciphertext ({mode.upper()})"
    if iv_hex:
        print(ui.FG["cyan"] + f"IV (hex): {iv_hex}" + ui.RESET)
    ui.boxed(title, cipher_hex)
    post_output_actions(cipher_hex, key=key, iv=iv_hex, label=title)


def decrypt_flow():
    """Workflow for decrypting a message."""
    ui.clear()
    ui.banner()
    ui.boxed("DECRYPT", "Nhập ciphertext, chọn mode (ecb/cfb) và cung cấp IV nếu cần.")
    ciphertext = _read_text_input("Ciphertext")
    key = _read_key()
    mode = _read_mode()
    iv = _read_iv(optional=False) if mode == "cfb" else None
    plaintext = cipher.des_decrypt(ciphertext, key, mode=mode, iv=iv)
    ui.boxed("KẾT QUẢ", plaintext)
    post_output_actions(plaintext, key=key, iv=iv, label=f"Plaintext ({mode.upper()})")


def post_output_actions(
    text: str,
    key: Optional[str] = None,
    iv: Optional[str] = None,
    label: str = "",
):
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
            if iv:
                header_parts.append(f"IV: {iv}")
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
        "- Mã hóa/giải mã bằng thuật toán DES với mode ecb hoặc cfb.\n"
        "- ECB dùng PKCS#7 padding và trả ciphertext hex.\n"
        "- CFB cần IV 8 byte (16 hex hoặc 8 ký tự); encrypt trả về IV và ciphertext tách biệt (hex), decrypt yêu cầu IV nhập thủ công. CFB không cần padding và hỗ trợ chuỗi dài bất kỳ.\n"
        "- Văn bản dài có thể đọc từ file (chọn 'f') hoặc pipe: cat file.txt | des\n"
        "- Sau khi có kết quả, bạn có thể copy hoặc lưu file.\n"
        "- Nếu muốn giao diện xịn hơn: pip install pyfiglet colorama pyperclip\n"
    )
    ui.boxed("HELP", help_text)
    ui.prompt("Nhấn Enter để về menu...")
