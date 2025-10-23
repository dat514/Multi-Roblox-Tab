import sys
import ctypes
from ctypes import windll, wintypes
import threading
import time
import psutil
import os
from pathlib import Path
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import logging

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

log_file = os.path.join(os.getenv('TEMP', '/tmp'), 'multi_roblox.log')
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)
logger.info("App started - Log file: %s", log_file)

def is_admin():
    try:
        is_admin_flag = windll.shell32.IsUserAnAdmin()
        logger.info("Admin check: %s", is_admin_flag)
        return is_admin_flag
    except Exception as e:
        logger.error("Admin check error: %s", e)
        return False

if not is_admin():
    logger.warning("Not admin, relaunching...")
    exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(sys.argv[0])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", exe_path, " ".join(sys.argv), None, 1)
    sys.exit(0)

logger.info("Running as Admin")

PROCESS_ALL_ACCESS = 0x1F0FFF
THREAD_ALL_ACCESS = 0x1F03FF

class NTSTATUS(wintypes.LONG): pass
STATUS_SUCCESS_VALUE = 0
STATUS_INFO_LENGTH_MISMATCH_VALUE = 0xC0000004
SystemExtendedHandleInformation = 64
ACCESS_MASK = wintypes.DWORD

class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
    _fields_ = [
        ('Object', ctypes.c_void_p),
        ('UniqueProcessId', ctypes.c_size_t),
        ('HandleValue', ctypes.c_size_t),
        ('GrantedAccess', ACCESS_MASK),
        ('CreatorBackTraceIndex', wintypes.USHORT),
        ('ObjectTypeIndex', wintypes.USHORT),
        ('HandleAttributes', wintypes.ULONG),
        ('Reserved', wintypes.ULONG)
    ]

class SYSTEM_HANDLE_INFORMATION_EX(ctypes.Structure):
    _fields_ = [
        ('NumberOfHandles', ctypes.c_size_t),
        ('Reserved', ctypes.c_size_t),
        ('Handles', SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * 1)
    ]

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [('Length', wintypes.USHORT), ('MaximumLength', wintypes.USHORT), ('Buffer', wintypes.LPWSTR)]

class OBJECT_NAME_INFORMATION(ctypes.Structure):
    _fields_ = [('Name', UNICODE_STRING)]

class OBJECT_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('Attributes', wintypes.ULONG),
        ('GrantedAccess', ACCESS_MASK),
        ('HandleCount', wintypes.ULONG),
        ('PointerCount', wintypes.ULONG),
        ('PagedPoolUsage', wintypes.ULONG),
        ('NonPagedPoolUsage', wintypes.ULONG),
        ('Reserved', wintypes.ULONG * 3),
        ('NameInformationLength', wintypes.ULONG),
        ('TypeInformationLength', wintypes.ULONG),
        ('SecurityDescriptorLength', wintypes.ULONG),
        ('CreateTime', wintypes.LARGE_INTEGER),
    ]

ntdll = ctypes.WinDLL("ntdll")
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_DUP_HANDLE = 0x0040
DUPLICATE_SAME_ACCESS = 0x00000002
DUPLICATE_CLOSE_SOURCE = 0x00000001

logger.info("DLLs loaded: ntdll, kernel32")

def list_handles():
    logger.debug("Calling list_handles")
    length = wintypes.ULONG(0)
    size = 0x100000
    for _ in range(20):
        buffer = ctypes.create_string_buffer(size)
        status = ntdll.NtQuerySystemInformation(SystemExtendedHandleInformation, buffer, size, ctypes.byref(length))
        status_val = status if isinstance(status, int) else (status.value if hasattr(status, 'value') else status)
        status_val = status_val & 0xFFFFFFFF
        logger.debug("NtQuery status: 0x%X, length: %d", status_val, length.value)
        
        if status_val == STATUS_SUCCESS_VALUE:
            break
        elif status_val == STATUS_INFO_LENGTH_MISMATCH_VALUE:
            size = max(size * 2, length.value + 0x10000)
            continue
        else:
            logger.error("list_handles failed with status 0x%X", status_val)
            return []
    handle_info = ctypes.cast(buffer, ctypes.POINTER(SYSTEM_HANDLE_INFORMATION_EX)).contents
    count = handle_info.NumberOfHandles
    logger.debug("Found %d handles", count)
    return (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * count).from_address(ctypes.addressof(handle_info.Handles))

def query_object_basic_info(h):
    info = OBJECT_BASIC_INFORMATION()
    retlen = wintypes.ULONG()
    status = ntdll.NtQueryObject(h, 0, ctypes.byref(info), ctypes.sizeof(info), ctypes.byref(retlen))
    status_val = status if isinstance(status, int) else (status.value if hasattr(status, 'value') else status)
    logger.debug("Basic info status: 0x%X", status_val)
    return info if (status_val & 0xFFFFFFFF) == STATUS_SUCCESS_VALUE else None

def query_object_name_info(h, length):
    bufsize = length + ctypes.sizeof(UNICODE_STRING)
    name_info = ctypes.create_string_buffer(bufsize)
    retlen = wintypes.ULONG()
    status = ntdll.NtQueryObject(h, 1, name_info, bufsize, ctypes.byref(retlen))
    status_val = status if isinstance(status, int) else (status.value if hasattr(status, 'value') else status)
    logger.debug("Name info status: 0x%X", status_val)
    
    if (status_val & 0xFFFFFFFF) == STATUS_SUCCESS_VALUE:
        return ctypes.cast(name_info, ctypes.POINTER(OBJECT_NAME_INFORMATION)).contents.Name.Buffer
    return None

def close_roblox_singleton_handle(pid):
    logger.info("Closing singleton for PID %d", pid)
    src = kernel32.OpenProcess(PROCESS_DUP_HANDLE, False, pid)
    if not src:
        logger.error("OpenProcess failed for PID %d", pid)
        return False
    target_events = [
        r"\sessions\1\basenamedobjects\roblox_singletonevent".lower(),
        r"ROBLOX_singletonMutex".lower(),
        r"ROBLOX_singletonEvent".lower()
    ]
    cur = wintypes.HANDLE(-1)
    handles = list_handles()
    if not handles:
        kernel32.CloseHandle(src)
        logger.error("No handles found")
        return False
    logger.debug("Scanning %d handles for PID %d", len(handles), pid)
    found_any = False
    for h in handles:
        if h.UniqueProcessId != pid:
            continue
        source_handle = wintypes.HANDLE(h.HandleValue & 0xFFFFFFFFFFFFFFFF)
        dup = wintypes.HANDLE()
        if not kernel32.DuplicateHandle(src, source_handle, cur, ctypes.byref(dup), 0, False, DUPLICATE_SAME_ACCESS):
            continue
        basic = query_object_basic_info(dup)
        if basic and basic.NameInformationLength > 0:
            name = query_object_name_info(dup, basic.NameInformationLength)
            if name and name.lower() in target_events:
                logger.info("Found and closing target handle: %s", name)
                temp = wintypes.HANDLE()
                if kernel32.DuplicateHandle(src, source_handle, cur, ctypes.byref(temp), 0, False, DUPLICATE_CLOSE_SOURCE):
                    kernel32.CloseHandle(temp)
                    found_any = True
        kernel32.CloseHandle(dup)
    kernel32.CloseHandle(src)
    if not found_any:
        logger.warning("No target handle found for PID %d", pid)
    return found_any

class MultiRobloxHandler:
    @staticmethod
    def method1_native_handle(pid, log_callback=None):
        try:
            if log_callback:
                log_callback(f"[Method 1] Attempting native handle enumeration...")
            
            for attempt in range(3):
                unlocked = close_roblox_singleton_handle(pid)
                if unlocked:
                    break
                if log_callback:
                    log_callback(f"[Method 1] Retry {attempt+1}/3...")
                time.sleep(1)
            
            if log_callback:
                log_callback(f"[Method 1] {'Success' if unlocked else 'Failed'}")
            
            return unlocked
        except Exception as e:
            logger.error("Method 1 error: %s", e)
            if log_callback:
                log_callback(f"[Method 1] Error: {str(e)[:50]}")
            return False
    
    @staticmethod
    def method2_powershell_mutex(pid, log_callback=None):
        try:
            if log_callback:
                log_callback(f"[Method 2] Attempting PowerShell mutex close...")
            
            mutex_names = [
                "ROBLOX_singletonMutex",
                "ROBLOX_singletonEvent",
                "roblox_singletonevent"
            ]
            
            ps_commands = []
            for mutex_name in mutex_names:
                ps_commands.append(f'''
                Add-Type -TypeDefinition @"
                using System;
                using System.Runtime.InteropServices;
                public class MutexHelper {{
                    [DllImport("kernel32.dll", SetLastError=true)]
                    public static extern IntPtr OpenMutex(uint dwDesiredAccess, bool bInheritHandle, string lpName);
                    [DllImport("kernel32.dll", SetLastError=true)]
                    public static extern bool CloseHandle(IntPtr hObject);
                }}
"@
                $handle = [MutexHelper]::OpenMutex(0x1F0001, $false, "{mutex_name}")
                if ($handle -ne [IntPtr]::Zero) {{
                    [MutexHelper]::CloseHandle($handle) | Out-Null
                    Write-Output "Closed {mutex_name}"
                }}
                '''.replace("{mutex_name}", mutex_name))
            
            ps_command = "; ".join(ps_commands)
            
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                timeout=5
            )
            
            success = "Closed" in result.stdout.decode()
            logger.debug("Method 2 PS output: %s", result.stdout.decode())
            
            if log_callback:
                log_callback(f"[Method 2] {'Success' if success else 'Failed'}")
            
            return success
        except Exception as e:
            logger.error("Method 2 error: %s", e)
            if log_callback:
                log_callback(f"[Method 2] Error: {str(e)[:50]}")
            return False
    
    @staticmethod
    def method3_suspend_resume(pid, log_callback=None):
        try:
            if log_callback:
                log_callback(f"[Method 3] Attempting process suspend/resume...")
            
            kernel32 = ctypes.windll.kernel32
            hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not hProcess:
                logger.error("OpenProcess failed for suspend/resume PID %d", pid)
                return False
            
            proc = psutil.Process(pid)
            threads = list(proc.threads())
            logger.debug("Suspending %d threads for PID %d", len(threads), pid)
            
            for thread in threads:
                hThread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, thread.id)
                if hThread:
                    kernel32.SuspendThread(hThread)
                    kernel32.CloseHandle(hThread)
            
            time.sleep(0.5)
            
            logger.debug("Resuming %d threads for PID %d", len(threads), pid)
            for thread in threads:
                hThread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, thread.id)
                if hThread:
                    kernel32.ResumeThread(hThread)
                    kernel32.CloseHandle(hThread)
            
            kernel32.CloseHandle(hProcess)
            
            if log_callback:
                log_callback(f"[Method 3] Completed")
            
            return True
        except Exception as e:
            logger.error("Method 3 error: %s", e)
            if log_callback:
                log_callback(f"[Method 3] Failed: {str(e)[:50]}")
            return False
    
    @staticmethod
    def method4_memory_access(pid, log_callback=None):
        try:
            if log_callback:
                log_callback(f"[Method 4] Verifying memory access...")
            
            kernel32 = ctypes.windll.kernel32
            PROCESS_VM_WRITE = 0x0020
            PROCESS_VM_OPERATION = 0x0008
            hProcess = kernel32.OpenProcess(
                PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 
                False, 
                pid
            )
            
            if hProcess:
                kernel32.CloseHandle(hProcess)
                if log_callback:
                    log_callback(f"[Method 4] Access granted")
                return True
            
            logger.warning("Method 4: OpenProcess failed for PID %d", pid)
            if log_callback:
                log_callback(f"[Method 4] Access denied")
            return False
        except Exception as e:
            logger.error("Method 4 error: %s", e)
            if log_callback:
                log_callback(f"[Method 4] Failed: {str(e)[:50]}")
            return False

def unlock_roblox_multi_method(pid, log_callback=None):
    logger.info("Unlocking PID %d with multi-methods", pid)
    handler = MultiRobloxHandler()
    
    methods = [
        ("Native Handle Close", handler.method1_native_handle),
        ("PowerShell Mutex", handler.method2_powershell_mutex),
        ("Suspend/Resume", handler.method3_suspend_resume),
        ("Memory Access", handler.method4_memory_access),
    ]
    
    if log_callback:
        log_callback(f"[PID {pid}] Starting unlock sequence...")
    
    success_count = 0
    for method_name, method_func in methods:
        try:
            if method_func(pid, log_callback):
                success_count += 1
                logger.info("Method %s succeeded for PID %d", method_name, pid)
        except Exception as e:
            logger.error("Method %s failed for PID %d: %s", method_name, pid, e)
            if log_callback:
                log_callback(f"[{method_name}] Error: {str(e)[:30]}")
    
    if log_callback:
        log_callback(f"[PID {pid}] Completed: {success_count}/{len(methods)} methods successful")
    
    logger.info("Unlock complete for PID %d: %s", pid, success_count > 0)
    return success_count > 0

class RobloxUnlockerApp:
    def __init__(self, root):
        logger.info("Initializing GUI")
        self.root = root
        self.root.title("Multi Roblox Unlocker")
        self.root.geometry("950x750")
        self.root.resizable(False, False)
        
        self.themes = {
            'dark': {
                'bg_dark': '#0a0e27',
                'bg_medium': '#16213e',
                'bg_light': '#1a2845',
                'accent': '#6c5ce7',
                'success': '#00ff88',
                'warning': '#fdcb6e',
                'danger': '#e74c3c',
                'text': '#ffffff',
                'text_secondary': '#a0a0a0'
            },
            'light': {
                'bg_dark': '#f5f6fa',
                'bg_medium': '#ffffff',
                'bg_light': '#e8eaf0',
                'accent': '#6c5ce7',
                'success': '#00b894',
                'warning': '#fdcb6e',
                'danger': '#e74c3c',
                'text': '#2d3436',
                'text_secondary': '#636e72'
            }
        }
        
        self.current_theme = 'dark'
        self.apply_theme()
        
        try:
            icon_path = resource_path("icon.ico")
            logger.info("Loading icon from: %s", icon_path)
            self.root.iconbitmap(default=icon_path)
        except Exception as e:
            logger.error("Icon load error: %s", e)

        self.is_running = False
        self.seen_pids = {}
        self.processing_pids = set()

        self.build_ui()
        self.log("Multi Roblox Unlocker Pro initialized")
        self.log("4 unlock methods loaded and ready")
        self.log("Administrator privileges: ACTIVE")
        self.log("Click 'START MONITORING' then launch Roblox from browser")
        self.log("━" * 80)
        logger.info("GUI initialized")

    def apply_theme(self):
        theme = self.themes[self.current_theme]
        self.bg_dark = theme['bg_dark']
        self.bg_medium = theme['bg_medium']
        self.bg_light = theme['bg_light']
        self.accent = theme['accent']
        self.success = theme['success']
        self.warning = theme['warning']
        self.danger = theme['danger']
        self.text = theme['text']
        self.text_secondary = theme['text_secondary']
        
        self.root.configure(bg=self.bg_dark)
        self.reconfigure_styles()

    def reconfigure_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Custom.Treeview", 
                       background=self.bg_light,
                       foreground=self.text,
                       fieldbackground=self.bg_light,
                       borderwidth=0,
                       rowheight=28)
        style.configure("Custom.Treeview.Heading",
                       background=self.bg_medium,
                       foreground=self.text,
                       borderwidth=1,
                       relief=tk.FLAT)
        style.map("Custom.Treeview",
                 background=[("selected", self.accent)])

    def toggle_theme(self):
        self.current_theme = 'light' if self.current_theme == 'dark' else 'dark'
        self.apply_theme()
        
        self.log_box.config(bg=self.bg_medium, fg=self.success, insertbackground=self.text)
        
        for widget in self.root.winfo_children():
            self.update_widget_colors(widget)
        
        self.log(f"Theme switched to {self.current_theme.upper()} mode")

    def update_widget_colors(self, widget):
        widget_type = widget.winfo_class()
        
        if widget_type == 'Frame':
            if 'header' in str(widget):
                widget.config(bg=self.bg_medium)
            elif 'info' in str(widget):
                widget.config(bg=self.bg_light)
            else:
                widget.config(bg=self.bg_dark)
        
        elif widget_type == 'Label':
            widget.config(bg=widget.master.cget('bg'), fg=self.text)
        
        elif widget_type == 'Button':
            pass
        
        for child in widget.winfo_children():
            self.update_widget_colors(child)

    def build_ui(self):
        logger.info("Building UI")
        header_frame = tk.Frame(self.root, bg=self.bg_medium, height=110)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        self.theme_btn = tk.Button(header_frame, text="🌙" if self.current_theme == 'dark' else "☀️", 
                                   font=("Segoe UI", 16), 
                                   bg=self.accent, fg="white",
                                   command=self.toggle_theme, cursor="hand2",
                                   relief=tk.FLAT, width=3, height=1,
                                   activebackground=self.success)
        self.theme_btn.place(x=880, y=10)
        
        tk.Label(header_frame, text="MULTI ROBLOX UNLOCKER", 
                font=("Segoe UI", 22, "bold"), 
                fg=self.success, bg=self.bg_medium).pack(pady=(15,5))
        
        tk.Label(header_frame, text="Advanced Multi-Method Bypass System v3.1 | dat514", 
                font=("Segoe UI", 10), 
                fg=self.text_secondary, bg=self.bg_medium).pack()
        
        tk.Label(header_frame, text="4 Unlock Methods | Windows 10/11 | Administrator Mode", 
                font=("Segoe UI", 9), 
                fg=self.text, bg=self.bg_medium).pack(pady=5)

        stats_frame = tk.Frame(self.root, bg=self.bg_dark)
        stats_frame.pack(fill=tk.X, padx=20, pady=15)
        
        card1 = tk.Frame(stats_frame, bg=self.bg_light, relief=tk.FLAT, bd=0)
        card1.pack(side=tk.LEFT, padx=5, fill=tk.BOTH, expand=True)
        tk.Label(card1, text="INSTANCES", font=("Segoe UI", 9, "bold"),
                fg=self.text_secondary, bg=self.bg_light).pack(pady=(8,2))
        self.stat_instances = tk.Label(card1, text="0", font=("Segoe UI", 20, "bold"),
                                       fg=self.accent, bg=self.bg_light)
        self.stat_instances.pack(pady=(0,8))
        
        card2 = tk.Frame(stats_frame, bg=self.bg_light, relief=tk.FLAT, bd=0)
        card2.pack(side=tk.LEFT, padx=5, fill=tk.BOTH, expand=True)
        tk.Label(card2, text="UNLOCKED", font=("Segoe UI", 9, "bold"),
                fg=self.text_secondary, bg=self.bg_light).pack(pady=(8,2))
        self.stat_unlocked = tk.Label(card2, text="0", font=("Segoe UI", 20, "bold"),
                                      fg=self.success, bg=self.bg_light)
        self.stat_unlocked.pack(pady=(0,8))
        
        card3 = tk.Frame(stats_frame, bg=self.bg_light, relief=tk.FLAT, bd=0)
        card3.pack(side=tk.LEFT, padx=5, fill=tk.BOTH, expand=True)
        tk.Label(card3, text="ACTIVE", font=("Segoe UI", 9, "bold"),
                fg=self.text_secondary, bg=self.bg_light).pack(pady=(8,2))
        self.stat_active = tk.Label(card3, text="0", font=("Segoe UI", 20, "bold"),
                                    fg=self.warning, bg=self.bg_light)
        self.stat_active.pack(pady=(0,8))

        table_frame = tk.Frame(self.root, bg=self.bg_dark)
        table_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=False)
        
        self.reconfigure_styles()
        
        columns = ("#", "PID", "Status", "Methods", "Time")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", 
                                height=7, style="Custom.Treeview")
        
        self.tree.heading("#", text="#")
        self.tree.heading("PID", text="Process ID")
        self.tree.heading("Status", text="Status")
        self.tree.heading("Methods", text="Methods")
        self.tree.heading("Time", text="Timestamp")
        
        self.tree.column("#", anchor="center", width=50)
        self.tree.column("PID", anchor="center", width=120)
        self.tree.column("Status", anchor="center", width=200)
        self.tree.column("Methods", anchor="center", width=100)
        self.tree.column("Time", anchor="center", width=120)
        
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        status_frame = tk.Frame(self.root, bg=self.bg_dark)
        status_frame.pack(pady=12)
        
        self.status_indicator = tk.Canvas(status_frame, width=24, height=24, 
                                         bg=self.bg_dark, highlightthickness=0)
        self.status_indicator.pack(side=tk.LEFT, padx=8)
        self.status_circle = self.status_indicator.create_oval(3, 3, 21, 21, 
                                                               fill="#95a5a6", outline="")
        
        self.status_label = tk.Label(status_frame, text="Status: Idle", 
                                     fg=self.text_secondary, font=("Segoe UI", 12, "bold"),
                                     bg=self.bg_dark)
        self.status_label.pack(side=tk.LEFT)

        btn_frame = tk.Frame(self.root, bg=self.bg_dark)
        btn_frame.pack(pady=15)
        
        self.start_btn = tk.Button(btn_frame, text="START", 
                                   width=18, height=2,
                                   font=("Segoe UI", 11, "bold"), 
                                   bg=self.success, fg="white",
                                   command=self.toggle, cursor="hand2",
                                   relief=tk.FLAT,
                                   activebackground=self.success)
        self.start_btn.grid(row=0, column=0, padx=6)
        
        self.kill_btn = tk.Button(btn_frame, text="TERMINATE", 
                                 width=18, height=2,
                                 font=("Segoe UI", 11, "bold"), 
                                   bg=self.danger, fg="white",
                                   command=self.end_selected, cursor="hand2",
                                   relief=tk.FLAT,
                                   activebackground=self.danger)
        self.kill_btn.grid(row=0, column=1, padx=6)
        
        self.open_logs_btn = tk.Button(btn_frame, text="LOGS", 
                                       width=18, height=2,
                                       font=("Segoe UI", 11, "bold"), 
                                       bg=self.accent, fg="white",
                                       command=self.open_log_folder, cursor="hand2",
                                   relief=tk.FLAT,
                                   activebackground=self.accent)
        self.open_logs_btn.grid(row=0, column=2, padx=6)

        log_container = tk.Frame(self.root, bg=self.bg_dark)
        log_container.pack(padx=20, pady=5, fill=tk.BOTH, expand=True)
        
        tk.Label(log_container, text="ACTIVITY LOG", 
                font=("Segoe UI", 10, "bold"), 
                fg=self.success, bg=self.bg_dark,
                anchor="w").pack(fill=tk.X, pady=(0,5))
        
        self.log_box = scrolledtext.ScrolledText(log_container, 
                                                 width=110, height=9, 
                                                 font=("Consolas", 9),
                                                 bg=self.bg_medium, 
                                                 fg=self.success,
                                                 insertbackground=self.text)
        self.log_box.pack(fill=tk.BOTH, expand=True)
        self.log_box.config(state=tk.DISABLED)

        credit_frame = tk.Frame(self.root, bg=self.bg_dark)
        credit_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=5)
        self.credit_label = tk.Label(credit_frame, text="dat514", 
                                     font=("Segoe UI", 8), fg=self.text_secondary, 
                                     bg=self.bg_dark)
        self.credit_label.pack(anchor=tk.SE, padx=20)

        footer_frame = tk.Frame(self.root, bg=self.bg_dark)
        footer_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        tk.Label(footer_frame, text="━" * 130, 
                fg=self.bg_light, bg=self.bg_dark).pack()
        
        tk.Label(footer_frame, 
                text="Created by dat514 | Version 3.1 | Multi-Method Technology | Fixed Method 1",
                font=("Segoe UI", 8), fg=self.text_secondary, bg=self.bg_dark).pack(pady=5)

    def log(self, msg):
        self.log_box.config(state=tk.NORMAL)
        timestamp = time.strftime("%H:%M:%S")
        self.log_box.insert(tk.END, f"[{timestamp}] {msg}\n")
        self.log_box.see(tk.END)
        self.log_box.config(state=tk.DISABLED)
        logger.info(msg)

    def update_stats(self):
        total = len(self.seen_pids)
        unlocked = sum(1 for p in self.seen_pids.values() if "✅" in p["status"])
        active = sum(1 for p in self.seen_pids.values() if "⚙️" in p["status"] or "⚠️" in p["status"])
        
        self.stat_instances.config(text=str(total))
        self.stat_unlocked.config(text=str(unlocked))
        self.stat_active.config(text=str(active))

    def toggle(self):
        if not self.is_running:
            logger.info("Starting monitoring")
            self.is_running = True
            self.start_btn.config(text="STOP", bg=self.warning)
            self.status_label.config(text="Status: Monitoring", fg=self.success)
            self.status_indicator.itemconfig(self.status_circle, fill=self.success)
            threading.Thread(target=self.worker, daemon=True).start()
            self.log("Monitoring started - Multi-method unlock active")
            self.log("━" * 80)
        else:
            logger.info("Stopping monitoring")
            self.is_running = False
            self.start_btn.config(text="START", bg=self.success)
            self.status_label.config(text="Status: Stopped", fg=self.danger)
            self.status_indicator.itemconfig(self.status_circle, fill=self.danger)
            self.log("Monitoring stopped")
            self.log("━" * 80)

    def worker(self):
        logger.info("Worker thread started")
        while self.is_running:
            try:
                logger.debug("Scanning processes...")
                current_pids = []
                for proc in psutil.process_iter(['pid', 'name']):
                    if proc.info['name'] == "RobloxPlayerBeta.exe":
                        pid = proc.info['pid']
                        current_pids.append(pid)
                        logger.debug("Found Roblox PID: %d", pid)
                        
                        if pid not in self.seen_pids and pid not in self.processing_pids:
                            logger.info("New Roblox PID detected: %d", pid)
                            self.processing_pids.add(pid)
                            self.seen_pids[pid] = {
                                "status": "⚙️ Initializing",
                                "methods": "0/4",
                                "time": time.strftime("%H:%M:%S")
                            }
                            self.root.after(0, self.update_table)
                            self.root.after(0, self.update_stats)
                            
                            self.log(f"NEW PROCESS DETECTED → PID {pid}")
                            self.log(f"Waiting for process initialization...")
                            
                            time.sleep(3)
                            
                            self.seen_pids[pid]["status"] = "⚙️ Unlocking..."
                            self.root.after(0, self.update_table)
                            
                            def log_callback(msg):
                                self.log(msg)
                            
                            success = unlock_roblox_multi_method(pid, log_callback)
                            
                            if success:
                                self.seen_pids[pid]["status"] = "✅ UNLOCKED"
                                self.seen_pids[pid]["methods"] = "✓"
                                self.log(f"✅ PID {pid} → SUCCESSFULLY UNLOCKED!")
                                self.log(f"You can now open another Roblox instance")
                                logger.info("Unlock success for PID %d", pid)
                            else:
                                self.seen_pids[pid]["status"] = "⚠️ ACTIVE"
                                self.seen_pids[pid]["methods"] = "✗"
                                self.log(f"⚠️  PID {pid} → Process active")
                                logger.warning("Unlock failed for PID %d", pid)
                            
                            self.log("━" * 80)
                            self.root.after(0, self.update_table)
                            self.root.after(0, self.update_stats)
                            self.processing_pids.remove(pid)
                
                for pid in list(self.seen_pids.keys()):
                    if pid not in current_pids:
                        logger.info("Process PID %d terminated", pid)
                        self.log(f"Process terminated → PID {pid}")
                        del self.seen_pids[pid]
                        self.processing_pids.discard(pid)
                        self.root.after(0, self.update_table)
                        self.root.after(0, self.update_stats)
                
                time.sleep(1)
                
            except Exception as e:
                logger.error("Worker error: %s", e)
                self.log(f"❌ ERROR: {e}")
                time.sleep(2)
        logger.info("Worker thread stopped")

    def update_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for i, (pid, info) in enumerate(self.seen_pids.items(), start=1):
            self.tree.insert("", "end", values=(
                i, 
                pid, 
                info["status"],
                info.get("methods", "-"),
                info.get("time", "-")
            ))

    def end_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select a Roblox instance to terminate.")
            return
        item = selected[0]
        pid = int(self.tree.item(item, "values")[1])
        
        if messagebox.askyesno("Confirm", f"Terminate Roblox PID {pid}?"):
            try:
                logger.info("Terminating PID %d", pid)
                psutil.Process(pid).terminate()
                if pid in self.seen_pids:
                    del self.seen_pids[pid]
                self.processing_pids.discard(pid)
                self.update_table()
                self.update_stats()
                self.log(f"Terminated PID {pid}")
                self.log("━" * 80)
            except Exception as e:
                logger.error("Terminate error: %s", e)
                self.log(f"❌ Error: {e}")
                messagebox.showerror("Error", f"Cannot terminate: {e}")

    def open_log_folder(self):
        log_dir = Path(os.getenv("LOCALAPPDATA", "")) / "Roblox" / "logs"
        logger.debug("Opening logs dir: %s", log_dir)
        if log_dir.exists():
            os.startfile(log_dir)
            self.log(f"Opened: {log_dir}")
        else:
            messagebox.showerror("Error", "Roblox logs folder not found!")
            self.log("Logs folder not found")

if __name__ == "__main__":
    logger.info("Starting mainloop")
    root = tk.Tk()
    app = RobloxUnlockerApp(root)
    root.mainloop()
    logger.info("Mainloop ended")