import os
import platform
import hashlib
import requests
import plyer
import threading
import customtkinter as ctk
from plyer import notification
from tkinter import filedialog
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# API Configuration
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files/"

def get_file_hash(file_path):
    """Compute SHA-256 hash of a file"""
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        log_output(f"⚠️ Error hashing file: {e}")
        return None

def check_threat_online(file_path):
    """Check file hash against VirusTotal API"""
    file_hash = get_file_hash(file_path)
    if not file_hash:
        log_output("❌ Unable to compute file hash.")
        return

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(VIRUSTOTAL_URL + file_hash, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        if data["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
            return "Malicious File Detected"
    else:
        log_output(f"⚠️ VirusTotal API error: {response.status_code}")

    return None


def log_output(message):
    output_box.configure(state="normal")
    output_box.insert("end", message + "\n")
    output_box.configure(state="disabled")
    output_box.see("end")

def notify(title, message):
    notification.notify(title=title, message=message, timeout=5)

def update_progress(value):
    progress_bar.set(value)
    progress_label.configure(text=f"{int(value * 100)}%")

def scan_file(file_path=None):
    if not file_path:
        file_path = filedialog.askopenfilename()
        if not file_path:
            log_output("❌ No file selected.")
            return
    
    log_output(f"🔍 Scanning file: {file_path} ...")
    try:
        threat = check_threat_online(file_path)
        if threat:
            message = f"🚨 {threat} in {file_path}"
            log_output(message)
            notify("Threat Detected!", message)
            return
        
        log_output(f"✅ No threats found in {file_path}.")
    except Exception as e:
        log_output(f"⚠️ Error scanning file: {e}")


def scan_folder(folder_path):
    if os.path.exists(folder_path):
        log_output(f"🔍 Scanning folder: {folder_path} ...")
        total_files = sum(len(files) for _, _, files in os.walk(folder_path))
        scanned = 0
        for root_dir, _, files in os.walk(folder_path):
            for file in files:
                scan_file(os.path.join(root_dir, file))
                scanned += 1
                update_progress(scanned / total_files)
        log_output("✅ Folder scan completed.")
    else:
        log_output("❌ Invalid folder path.")

def scan_system():
    scan_path = "C:\\" if platform.system() == "Windows" else "/"
    log_output(f"🚀 Full system scan in: {scan_path} ...")
    scan_folder(scan_path)
    log_output("✅ Full system scan completed.")

class RealTimeScanner(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            log_output(f"🔍 New file detected: {event.src_path}. Scanning...")
            scan_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            log_output(f"🔄 Modified file: {event.src_path}. Scanning...")
            scan_file(event.src_path)

def start_real_time_scan(folder_path):
    global observer
    if os.path.exists(folder_path):
        log_output(f"📡 Monitoring: {folder_path}")
        observer = Observer()
        event_handler = RealTimeScanner()
        observer.schedule(event_handler, folder_path, recursive=True)
        observer.start()
    else:
        log_output("❌ Invalid directory.")

def stop_real_time_scan():
    global observer
    if observer:
        observer.stop()
        observer.join()
        log_output("🛑 Real-time scanning stopped.")

# GUI Setup
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

root = ctk.CTk()
root.title("🛡️ QuickShield Antivirus")
root.geometry("700x600")
root.resizable(False, False)

ctk.CTkLabel(root, text="QuickShield Antivirus", font=("Arial", 24, "bold")).pack(pady=(20, 0))
ctk.CTkLabel(root, text="________________________", font=("Arial", 20, "bold")).pack(pady=(0, 5))

btn_scan_file = ctk.CTkButton(root, text="📄 Scan File", command=scan_file, width=250, fg_color="#4CAF50")
btn_scan_file.pack(pady=5)

btn_scan_folder = ctk.CTkButton(root, text="📂 Scan Folder", command=lambda: scan_folder(filedialog.askdirectory()), width=250, fg_color="#2196F3")
btn_scan_folder.pack(pady=5)

btn_scan_system = ctk.CTkButton(root, text="🖥️ Full System Scan", command=scan_system, width=250, fg_color="#FF9800")
btn_scan_system.pack(pady=5)

btn_real_time_scan = ctk.CTkButton(root, text="📡 Start Real-Time Scan", command=lambda: start_real_time_scan(filedialog.askdirectory()), width=250, fg_color="#9C27B0")
btn_real_time_scan.pack(pady=5)

btn_stop_real_time = ctk.CTkButton(root, text="🛑 Stop Real-Time Scan", command=stop_real_time_scan, width=250, fg_color="#F44336")
btn_stop_real_time.pack(pady=5)

output_box = ctk.CTkTextbox(root, height=250, width=650, wrap="word", state="disabled")
output_box.pack(pady=10)

progress_bar = ctk.CTkProgressBar(root, width=650)
progress_bar.pack(pady=5)
progress_label = ctk.CTkLabel(root, text="0%")
progress_label.pack(pady=5)

root.mainloop()
