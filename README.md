# VT_Sentinel
A Very Long Time-Wasting Experiment; I got it to partially work, just not as an *.EXE (Need Virus Total API)
# 🛡️ VT_Sentinel — Virus & Threat Monitor  
**Designed by NemesisC64**

VT_Sentinel is a powerful, user-friendly virus monitoring tool for Windows. It continuously watches your system for potentially malicious `.exe` or `.zip` files and scans them via [VirusTotal](https://www.virustotal.com/) using your personal API key. In addition, it tracks suspicious network IPs, logs all events, and gives you full control through a graphical interface.

---

## 🚀 Features Overview

### 🧠 VirusTotal Integration
- Uploads newly detected `.exe` or `.zip` files for scanning.
- Requires your own free [VirusTotal API key](https://developers.virustotal.com/reference/getting-started).
- Skips duplicates to conserve API quota.
- Logs scan results into `logs/scan_log.txt`.

### 📡 Network Monitor
- Monitors and displays **incoming external IP addresses**.
- Geolocation and WHOIS info shown in-app.
- Flags and alerts suspicious or blacklisted IPs.

### 🔊 Alert System
- Plays a customizable **audio alert** when malware or blacklisted IP is detected.
- Visual pop-up alerts and log entry creation.

### 📁 File System Monitoring
- Automatically monitors all folders for new `.exe` or `.zip` files.
- Smart deduplication prevents repeated scans of the same file.

### 🖥️ Graphical Interface
- Modern, organized layout built with Tkinter:
  - **Home**
  - **Scan Log**
  - **Network Monitor**
  - **Settings**
  - **Logs**
  - **User Guide**
  - **About**

### 📂 Logging
- Events are logged to readable `.txt` files:
  - `logs/scan_log.txt`
  - `logs/ip_log.txt`

---

## ⚙️ Installation & Setup

### 🧰 Requirements
- Windows 10 or 11
- Internet connection
- A free VirusTotal API key

### 🔄 Running the App

#### 🔹 Option A: Using the Precompiled `.exe`
1. Launch `vt_sentinel.exe` in the `/dist/` folder.  
2. Enter your VirusTotal API key at first launch.  
3. You're protected.

#### 🔹 Option B: Running from Source
1. Open a terminal in the project folder.  
2. Run:

```bash
pip install -r requirements.txt
python vt_sentinel.py
```

---

## 🧪 Recommended Usage

- Run VT_Sentinel at system startup for maximum protection.
- Avoid uploading highly confidential files (VirusTotal stores uploaded content).
- Review logs weekly (`scan_log.txt`, `ip_log.txt`) for signs of unusual activity.
- Use the settings tab to customize alerts and monitoring behavior.
- Keep your VirusTotal API key private and secure.

---

## 🔐 Security Notes

- Files are uploaded **only** to VirusTotal for malware scanning.
- The API key is stored **locally** in the `.env` file and never transmitted elsewhere.
- No data is collected, shared, or sold. There is **zero telemetry**.
- Logs are saved in `.txt` format and can be deleted manually.

---

## 📂 Folder Structure

```
VT_Sentinel/
├── vt_sentinel.py ← Main app script
├── README.md ← This documentation
├── requirements.txt ← Python dependencies
├── start_sentinel.bat ← Optional launcher
├── .env ← Auto-created with your API key
├── /assets/
│ ├── icon.ico
│ └── alert.wav
├── /logs/
│ ├── scan_log.txt
│ └── ip_log.txt
├── /dist/
│ └── vt_sentinel.exe
```
---

## 👤 Author

**Created by NemesisC64**  
Ethical developer focused on security, privacy, and open access to tools.  
This program is designed to help users identify threats and monitor suspicious activity — nothing more, nothing less.

---

## 📝 License

**Freeware – Personal Use Only**

- You may use, modify, and share this software for **free**.
- Commercial redistribution or sale is **not allowed** without written consent.
- You must credit the author if you distribute it.
- Use at your own risk. No liability is assumed.
