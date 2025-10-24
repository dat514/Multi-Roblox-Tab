# 🧩 Multi Roblox Unlocker v3.1  
**Advanced Multi-Instance Unlocker for Roblox – by dat514**

---

## ⚙️ Overview

**Multi Roblox Unlocker ** allows you to **run multiple Roblox instances** on Windows 10/11.  
It uses **4 advanced unlocking methods** to automatically remove the Roblox **single-instance restriction**, letting you open multiple accounts at once.

> 🧠 Current GUI Version: **v3.1**  
> ✅ Fixed Method 1 (Native Handle Close)  
> 💾 Precompiled `.exe` available in [Releases](https://github.com/dat514/Multi-Roblox-Tab/releases/latest)

---

## 🚀 Features

| Feature | Description |
|----------|-------------|
| 🧠 **4 Unlock Methods** | Native Handle Close, PowerShell Mutex, Suspend/Resume, Memory Access |
| 🔍 **Auto Process Detection** | Automatically detects `RobloxPlayerBeta.exe` and applies unlocking |
| 📊 **Live Statistics** | Displays Roblox instances, unlock success, and activity status |
| 🎨 **Modern UI** | Dark/Light theme with live theme toggle |
| 🔐 **Admin Privilege** | Automatically relaunches with Administrator rights if needed |
| 🧾 **Detailed Logging** | Logs stored at `%TEMP%\multi_roblox.log` |
| 💾 **Ready-to-use EXE** | Available in Releases, no Python required |

---

## 🖥️ How to Use

### 1️⃣ Download
Grab the latest `.exe` build here:   [Releases](https://github.com/dat514/Multi-Roblox-Tab/releases/latest)

### 2️⃣ Run the Tool
- Launch **MultiRobloxUnlocker.exe**  
- It will **request Administrator access** automatically (required for handle access)

### 3️⃣ Start Roblox
- Click **START MONITORING**  
- Then open Roblox from your browser or desktop app  
- The tool will detect the Roblox process and apply all 4 unlock methods automatically  

### 4️⃣ Monitor Results
- If unlocked successfully → Status shows **✅ UNLOCKED**  
- If not yet unlocked → Status shows **⚠️ ACTIVE**

---

## 🧰 Unlocking Methods

| Method | Description |
|---------|--------------|
| **Method 1: Native Handle Close** | Scans and closes Roblox singleton handles |
| **Method 2: PowerShell Mutex** | Uses PowerShell to close Roblox mutex locks |
| **Method 3: Suspend/Resume** | Temporarily suspends and resumes Roblox threads |
| **Method 4: Memory Access Check** | Verifies process memory access and confirms control |

---

## 📊 Interface Overview

- **START / STOP** – Begin or stop process monitoring  
- **TERMINATE** – Kill a selected Roblox process  
- **LOGS** – Open the Roblox log folder (`%LOCALAPPDATA%\Roblox\logs`)  
- **🌙 / ☀️** – Toggle dark/light mode  
- **ACTIVITY LOG** – Shows detailed unlock progress and system activity  

---

## 🧱 Build from Source (Optional)

If you prefer to build your own `.exe`:

```pip install psutil pyinstaller```
```pyinstaller --noconfirm --onefile --windowed --icon=icon.ico main.py```
Output will appear in the dist/ folder.

## ⚠️ Disclaimer
❗ This tool does NOT modify Roblox gameplay or bypass its security systems.
It only removes the multi-instance restriction for legitimate use cases (e.g., development, multi-account testing).

Always run as Administrator

Does not inject code, patch memory, or alter Roblox binaries

Some methods may require updates if Roblox changes its internal locking system

## ⚒️ Credits
Build with Python 3.x, Tkinter/ttk, ctypes, psutil, subprocess, logging, threading, os, pathlib, sys


