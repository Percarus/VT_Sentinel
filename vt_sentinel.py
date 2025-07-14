import atexit
import os
import sys
import time
import threading
import hashlib
import queue
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import webbrowser
import json
import csv
from pathlib import Path
from dotenv import load_dotenv, set_key
import requests
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import vt
from PIL import Image, ImageTk  # For icons and images
import platform
import socket
import ipaddress
import winsound

# Load or create .env for API key storage
ENV_PATH = Path('./.env')
if not ENV_PATH.exists():
    ENV_PATH.touch()

load_dotenv(dotenv_path=ENV_PATH)

api_key = os.getenv("VT_API_KEY")

if not api_key:
    raise Exception("VirusTotal API key not found in .env file.")

client = vt.Client(api_key)

# Automatically close the client on exit
atexit.register(client.close)

# Constants
APP_NAME = "VT Sentinel"
VERSION = "1.0.0"
API_KEY_ENV = "VT_API_KEY"

# Supported file extensions to scan
SCAN_EXTENSIONS = {'.exe', '.zip', '.msi', '.dll', '.bat', '.cmd', '.js'}

# Paths
LOGS_DIR = Path('./logs')
ASSETS_DIR = Path('./assets')

LOGS_DIR.mkdir(exist_ok=True)
ASSETS_DIR.mkdir(exist_ok=True)

SCAN_LOG_PATH = LOGS_DIR / 'scan_log.txt'
IP_LOG_PATH = LOGS_DIR / 'ip_log.txt'

# VirusTotal API key management
def get_api_key():
    key = os.getenv(API_KEY_ENV)
    if not key:
        return None
    return key.strip()

def save_api_key(key):
    set_key(str(ENV_PATH), API_KEY_ENV, key)

# Hashing helper
def sha256sum(filename):
    h = hashlib.sha256()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

# Function to open URLs in default browser
def open_url(url):
    webbrowser.open(url)

class APIPromptDialog(tk.Toplevel):
    def __init__(self, master, on_submit):
        super().__init__(master)
        self.title(f"{APP_NAME} - Enter VirusTotal API Key")
        self.resizable(False, False)
        self.on_submit = on_submit

        self.label = ttk.Label(self, text="Please enter your VirusTotal API Key:")
        self.label.pack(padx=20, pady=(20, 5))

        self.api_key_var = tk.StringVar()
        self.entry = ttk.Entry(self, textvariable=self.api_key_var, width=50)
        self.entry.pack(padx=20, pady=5)
        self.entry.focus()

        self.submit_btn = ttk.Button(self, text="Submit", command=self.submit)
        self.submit_btn.pack(pady=(10, 20))

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Center the dialog over the parent window
        self.geometry(f"+{master.winfo_rootx() + 50}+{master.winfo_rooty() + 50}")

    def submit(self):
        key = self.api_key_var.get().strip()
        if not key:
            messagebox.showwarning("Input Required", "API Key cannot be empty.")
            return
        self.on_submit(key)
        self.destroy()

    def on_close(self):
        if not get_api_key():
            if messagebox.askyesno("Exit?", "No API Key entered. Exit the application?"):
                self.master.destroy()
        else:
            self.destroy()

class ScanEventHandler(FileSystemEventHandler):
    def __init__(self, scan_queue, blacklist):
        super().__init__()
        self.scan_queue = scan_queue
        self.blacklist = blacklist

    def on_created(self, event):
        if not event.is_directory and self.should_scan(event.src_path):
            self.scan_queue.put(event.src_path)

    def on_modified(self, event):
        if not event.is_directory and self.should_scan(event.src_path):
            self.scan_queue.put(event.src_path)

    def should_scan(self, filepath):
        path = Path(filepath)
        if path.suffix.lower() not in SCAN_EXTENSIONS:
            return False
        for bl_item in self.blacklist:
            if bl_item in filepath:
                return False
        return True

class ScannerThread(threading.Thread):
    def __init__(self, api_key, scan_queue, log_path, alert_callback=None):
        super().__init__(daemon=True)
        self.api_key = api_key
        self.vt = vt.Client(api_key)
        self.scan_queue = scan_queue
        self.log_path = log_path
        self.alert_callback = alert_callback
        self.seen_hashes = set()
        self.running = True

    def run(self):
        while self.running:
            try:
                filepath = self.scan_queue.get(timeout=1)
                self.process_file(filepath)
                self.scan_queue.task_done()
            except queue.Empty:
                continue

    def process_file(self, filepath):
        try:
            if not os.path.exists(filepath):
                return
            file_hash = sha256sum(filepath)
            if file_hash in self.seen_hashes:
                return
            self.seen_hashes.add(file_hash)

            if self.already_logged(file_hash):
                return

            resp = self.vt.get_file_report(file_hash)

            if resp is None or resp.get('response_code') == 0:
                self.upload_and_scan(filepath)
            else:
                self.log_scan_result(filepath, file_hash, resp)
                if self.is_malicious(resp):
                    self.alert_user(filepath, file_hash, resp)
        except Exception as e:
            print(f"Error scanning {filepath}: {e}")

    def upload_and_scan(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                resp = self.vt.upload_file(f, filename=os.path.basename(filepath))
            self.log_scan_result(filepath, sha256sum(filepath), resp)
            if self.is_malicious(resp):
                self.alert_user(filepath, sha256sum(filepath), resp)
        except Exception as e:
            print(f"Error uploading {filepath}: {e}")

    def log_scan_result(self, filepath, file_hash, resp):
        with open(self.log_path, 'a', encoding='utf-8') as f:
            line = f"{time.strftime('%Y-%m-%d %H:%M:%S')}, {filepath}, {file_hash}, {json.dumps(resp)}\n"
            f.write(line)

    def already_logged(self, file_hash):
        if not os.path.exists(self.log_path):
            return False
        with open(self.log_path, 'r', encoding='utf-8') as f:
            for line in f:
                if file_hash in line:
                    return True
        return False

    def is_malicious(self, resp):
        positives = resp.get('positives') if resp else 0
        return positives and positives > 0

    def alert_user(self, filepath, file_hash, resp):
        if self.alert_callback:
            self.alert_callback(filepath, file_hash, resp)

    def stop(self):
        self.running = False

class NetworkMonitorThread(threading.Thread):
    def __init__(self, update_callback=None, log_path=IP_LOG_PATH):
        super().__init__(daemon=True)
        self.update_callback = update_callback
        self.log_path = log_path
        self.running = True
        self.known_ips = set()

    def run(self):
        while self.running:
            try:
                self.scan_connections()
                time.sleep(10)
            except Exception as e:
                print(f"Network monitor error: {e}")

    def scan_connections(self):
        conns = psutil.net_connections(kind='inet')
        new_ips = set()
        for conn in conns:
            if conn.raddr:
                ip = conn.raddr.ip
                if self.is_external_ip(ip):
                    new_ips.add(ip)
        added_ips = new_ips - self.known_ips
        for ip in added_ips:
            info = self.get_ip_info(ip)
            self.log_ip(ip, info)
            if self.update_callback:
                self.update_callback(ip, info)
        self.known_ips.update(new_ips)

    def is_external_ip(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)
        except ValueError:
            return False

    def get_ip_info(self, ip):
        try:
            url = f"https://ipapi.co/{ip}/json/"
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    'ip': ip,
                    'city': data.get('city', 'N/A'),
                    'region': data.get('region', 'N/A'),
                    'country': data.get('country_name', 'N/A'),
                    'org': data.get('org', 'N/A'),
                    'asn': data.get('asn', 'N/A'),
                }
        except Exception:
            pass
        return {'ip': ip, 'city': 'N/A', 'region': 'N/A', 'country': 'N/A', 'org': 'N/A', 'asn': 'N/A'}

    def log_ip(self, ip, info):
        with open(self.log_path, 'a', encoding='utf-8') as f:
            line = f"{time.strftime('%Y-%m-%d %H:%M:%S')}, {ip}, {info['city']}, {info['region']}, {info['country']}, {info['org']}, {info['asn']}\n"
            f.write(line)

    def stop(self):
        self.running = False

class LogsViewer(ttk.Frame):
    def __init__(self, master, scan_log_path=SCAN_LOG_PATH, ip_log_path=IP_LOG_PATH):
        super().__init__(master)
        self.scan_log_path = scan_log_path
        self.ip_log_path = ip_log_path

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True)

        # File Scan Log Tab
        self.scan_log_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_log_frame, text="File Scan Log")

        self.scan_tree = ttk.Treeview(self.scan_log_frame,
                                      columns=('Timestamp', 'File', 'SHA256', 'Result'),
                                      show='headings')
        for col in ('Timestamp', 'File', 'SHA256', 'Result'):
            self.scan_tree.heading(col, text=col)
            self.scan_tree.column(col, anchor='w', width=150)
        self.scan_tree.pack(fill='both', expand=True)

        self.refresh_scan_btn = ttk.Button(self.scan_log_frame, text="Refresh", command=self.load_scan_log)
        self.refresh_scan_btn.pack(pady=5)

        # IP Log Tab
        self.ip_log_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.ip_log_frame, text="IP Log")

        self.ip_tree = ttk.Treeview(self.ip_log_frame,
                                    columns=('Timestamp', 'IP', 'City', 'Region', 'Country', 'Org', 'ASN'),
                                    show='headings')
        for col in ('Timestamp', 'IP', 'City', 'Region', 'Country', 'Org', 'ASN'):
            self.ip_tree.heading(col, text=col)
            self.ip_tree.column(col, anchor='w', width=120)
        self.ip_tree.pack(fill='both', expand=True)

        self.refresh_ip_btn = ttk.Button(self.ip_log_frame, text="Refresh", command=self.load_ip_log)
        self.refresh_ip_btn.pack(pady=5)

        self.load_scan_log()
        self.load_ip_log()

    def load_scan_log(self):
        self.scan_tree.delete(*self.scan_tree.get_children())
        if not self.scan_log_path.exists():
            return
        with open(self.scan_log_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    timestamp, filepath, filehash, result_json = line.strip().split(',', 3)
                    self.scan_tree.insert('', 'end', values=(timestamp, filepath, filehash, result_json))
                except ValueError:
                    continue

    def load_ip_log(self):
        self.ip_tree.delete(*self.ip_tree.get_children())
        if not self.ip_log_path.exists():
            return
        with open(self.ip_log_path, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) == 7:
                    self.ip_tree.insert('', 'end', values=tuple(parts))

class SettingsManager:
    def __init__(self, settings_path=Path('./settings.json')):
        self.settings_path = settings_path
        self.settings = {
            'blacklist': [],
            'scan_enabled': True,
            'api_key': api_key,
        }
        self.load()

    def load(self):
        if self.settings_path.exists():
            try:
                with open(self.settings_path, 'r', encoding='utf-8') as f:
                    self.settings.update(json.load(f))
            except Exception:
                pass

    def save(self):
        with open(self.settings_path, 'w', encoding='utf-8') as f:
            json.dump(self.settings, f, indent=4)

    def get_blacklist(self):
        return self.settings.get('blacklist', [])

    def add_to_blacklist(self, item):
        if item not in self.settings['blacklist']:
            self.settings['blacklist'].append(item)
            self.save()

    def remove_from_blacklist(self, item):
        if item in self.settings['blacklist']:
            self.settings['blacklist'].remove(item)
            self.save()

    def is_scan_enabled(self):
        return self.settings.get('scan_enabled', True)

    def set_scan_enabled(self, enabled):
        self.settings['scan_enabled'] = enabled
        self.save()

    def get_api_key(self):
        return self.settings.get('api_key', '')

    def set_api_key(self, key):
        self.settings['api_key'] = key
        self.save()

class ThreadManager:
    def __init__(self):
        self.threads = []

    def add_thread(self, thread):
        thread.start()
        self.threads.append(thread)

    def stop_all(self):
        for t in self.threads:
            if hasattr(t, 'stop'):
                t.stop()
        for t in self.threads:
            t.join(timeout=2)

class SettingsTab(ttk.Frame):
    def __init__(self, master, settings_manager, save_api_key_callback):
        super().__init__(master)
        self.settings_manager = settings_manager
        self.save_api_key_callback = save_api_key_callback

        self.api_key_var = tk.StringVar(value=self.settings_manager.get_api_key())

        ttk.Label(self, text="VirusTotal API Key:").pack(pady=(10, 2))
        self.api_entry = ttk.Entry(self, textvariable=self.api_key_var, width=60)
        self.api_entry.pack(pady=5)

        ttk.Button(self, text="Save API Key", command=self.save_api_key).pack(pady=5)

        ttk.Label(self, text="Blacklist (one entry per line):").pack(pady=(10, 2))
        self.blacklist_text = tk.Text(self, height=8)
        self.blacklist_text.pack(padx=10, pady=5, fill='both', expand=True)
        self.load_blacklist()

        ttk.Button(self, text="Save Blacklist", command=self.save_blacklist).pack(pady=5)

        self.scan_enabled_var = tk.BooleanVar(value=self.settings_manager.is_scan_enabled())
        self.scan_enabled_checkbox = ttk.Checkbutton(self, text="Enable automatic scanning", variable=self.scan_enabled_var,
                                                     command=self.toggle_scan)
        self.scan_enabled_checkbox.pack(pady=10)

    def save_api_key(self):
        key = self.api_key_var.get().strip()
        if not key:
            messagebox.showwarning("Input Required", "API Key cannot be empty.")
            return
        self.settings_manager.set_api_key(key)
        self.save_api_key_callback(key)
        messagebox.showinfo("Saved", "API Key saved.")

    def load_blacklist(self):
        bl = self.settings_manager.get_blacklist()
        self.blacklist_text.delete('1.0', tk.END)
        self.blacklist_text.insert('1.0', '\n'.join(bl))

    def save_blacklist(self):
        content = self.blacklist_text.get('1.0', tk.END).strip()
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        self.settings_manager.settings['blacklist'] = lines
        self.settings_manager.save()
        messagebox.showinfo("Saved", "Blacklist saved.")

    def toggle_scan(self):
        self.settings_manager.set_scan_enabled(self.scan_enabled_var.get())

def alert_callback(filepath, file_hash, resp):
    # Simple alert using a popup and a beep
    message = f"Malicious file detected!\n\nPath: {filepath}\nSHA256: {file_hash}\n"
    message += f"Detection count: {resp.get('positives', 0)} / {resp.get('total', 'N/A')}"
    winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
    messagebox.showwarning("VirusTotal Alert", message)

class VTSentinelApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} v{VERSION}")
        self.geometry("900x600")
        self.minsize(800, 500)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Load or prompt for API key
        self.api_key = get_api_key()
        if not self.api_key:
            self.wait_window(APIPromptDialog(self, self.save_api_key))

        # Settings manager
        self.settings_manager = SettingsManager()

        # Thread manager
        self.thread_manager = ThreadManager()

        # Setup notebook and tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True)

        self.home_tab = ttk.Frame(self.notebook)
        self.scan_tab = ttk.Frame(self.notebook)
        self.network_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)
        self.logs_tab = ttk.Frame(self.notebook)
        self.user_guide_tab = ttk.Frame(self.notebook)
        self.about_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.home_tab, text="Home")
        self.notebook.add(self.scan_tab, text="File Scan Log")
        self.notebook.add(self.network_tab, text="Network Monitor")
        self.notebook.add(self.settings_tab, text="Settings")
        self.notebook.add(self.logs_tab, text="Logs Viewer")
        self.notebook.add(self.user_guide_tab, text="User Guide")
        self.notebook.add(self.about_tab, text="About")

        self.setup_home_tab()
        self.setup_scan_tab()
        self.setup_network_tab()
        self.setup_settings_tab()
        self.setup_logs_tab()
        self.setup_user_guide_tab()
        self.setup_about_tab()

        # Scan queue
        self.scan_queue = queue.Queue()

        # Blacklist
        self.blacklist = self.settings_manager.get_blacklist()

        # Scanner thread
        self.scanner_thread = ScannerThread(self.api_key, self.scan_queue, SCAN_LOG_PATH, alert_callback=alert_callback)

        # Observer for downloads folder
        self.observer = Observer()
        downloads_path = Path.home() / "Downloads"
        if downloads_path.exists():
            event_handler = ScanEventHandler(self.scan_queue, self.blacklist)
            self.observer.schedule(event_handler, str(downloads_path), recursive=True)

        # Network monitor thread
        self.network_monitor = NetworkMonitorThread(update_callback=self.network_update_callback)

        if self.settings_manager.is_scan_enabled() and downloads_path.exists():
            self.observer.start()
            self.thread_manager.add_thread(self.scanner_thread)
            self.thread_manager.add_thread(self.network_monitor)

        # Network list treeview for network tab
        self.network_list = ttk.Treeview(self.network_tab,
                                         columns=('IP', 'City', 'Region', 'Country', 'Org', 'ASN'),
                                         show='headings')
        for col in ('IP', 'City', 'Region', 'Country', 'Org', 'ASN'):
            self.network_list.heading(col, text=col)
            self.network_list.column(col, width=120, anchor='w')
        self.network_list.pack(fill='both', expand=True, padx=10, pady=10)

    def setup_home_tab(self):
        label = ttk.Label(self.home_tab, text="Welcome to VT Sentinel", font=("Segoe UI", 16))
        label.pack(pady=20)

    def setup_scan_tab(self):
        self.scan_log_text = tk.Text(self.scan_tab)
        self.scan_log_text.pack(fill='both', expand=True)
        self.load_scan_log()
        ttk.Button(self.scan_tab, text="Refresh", command=self.load_scan_log).pack(pady=5)

    def load_scan_log(self):
        if SCAN_LOG_PATH.exists():
            with open(SCAN_LOG_PATH, 'r', encoding='utf-8') as f:
                content = f.read()
            self.scan_log_text.delete('1.0', tk.END)
            self.scan_log_text.insert('1.0', content)
        else:
            self.scan_log_text.delete('1.0', tk.END)
            self.scan_log_text.insert('1.0', "No scan logs available.")

    def setup_network_tab(self):
        # Already created self.network_list in __init__
        pass

    def network_update_callback(self, ip, info):
        def update_ui():
            for child in self.network_list.get_children():
                if self.network_list.item(child)['values'][0] == ip:
                    return
            self.network_list.insert('', 'end', values=(
                ip, info.get('city'), info.get('region'), info.get('country'), info.get('org'), info.get('asn')
            ))
        self.after(0, update_ui)

    def setup_settings_tab(self):
        self.settings_tab_frame = SettingsTab(self.settings_tab, self.settings_manager, self.save_api_key)
        self.settings_tab_frame.pack(fill='both', expand=True)

    def setup_logs_tab(self):
        self.logs_viewer = LogsViewer(self.logs_tab)
        self.logs_viewer.pack(fill='both', expand=True)

    def setup_user_guide_tab(self):
        guide_text = (
            "User Guide\n\n"
            "Home: Overview and status.\n"
            "File Scan Log: Displays scanned files and results.\n"
            "Network Monitor: Shows IP connections and alerts.\n"
            "Settings: Configure API key, blacklists, and scan options.\n"
            "Logs Viewer: View detailed logs.\n"
            "User Guide: This help text.\n"
            "About: Information about this software.\n"
        )
        text_widget = tk.Text(self.user_guide_tab, wrap='word')
        text_widget.insert('1.0', guide_text)
        text_widget.configure(state='disabled')
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)

    def setup_about_tab(self):
        about_text = (
            f"{APP_NAME} v{VERSION}\n"
            "Designed by NemesisC64\n\n"
            "This software uses VirusTotal API to scan files and monitor network activity.\n"
            "Please enter your VirusTotal API key to get started.\n"
        )
        label = ttk.Label(self.about_tab, text=about_text, justify='center', font=("Segoe UI", 12))
        label.pack(padx=20, pady=20)

    def save_api_key(self, key):
        save_api_key(key)
        self.api_key = key
        self.settings_manager.set_api_key(key)
        messagebox.showinfo("API Key Saved", "VirusTotal API key saved successfully.")

    def on_close(self):
        if messagebox.askokcancel("Quit", "Are you sure you want to exit?"):
            self.thread_manager.stop_all()
            self.observer.stop()
            self.observer.join()
            self.destroy()

def main():
    app = VTSentinelApp()
    app.mainloop()

if __name__ == "__main__":
    main()

