import os
import sys
import winreg

def add_to_windows_startup(app_name="FavApp"):
    try:
        exe_path = sys.executable

        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE
        )
        value, regtype = winreg.QueryValueEx(key, app_name)
        if value == exe_path:
            return 200
        winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, exe_path)
        winreg.CloseKey(key)
        return 200
    except:
        return 401
