import tkinter as tk
from tkinter import messagebox

def log_info(message: str):
    print(f"[INFO] - {message}")

def log_warn(message: str):
    print(f"[WARN] - {message}")

def log_error(message: str):
    print(f"[ERROR] - {message}")

def log_success(message: str):
    print(f"[SUCCESS] - {message}")

def show_gui_popup(title: str, message: str):
    try:
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo(title, message)
        root.destroy()
    except Exception as e:
        log_warn(f"GUI popup failed: {e}")
