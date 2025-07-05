import os
import platform
import hashlib
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Threat database
known_threats = {
    "44d88612fea8a8f36de82e1278abb02f": "EICAR Test Virus",
    "c157a79031e1c40f85931829bc5fc552": "Ransomware.Locker",
    "098f6bcd4621d373cade4e832627b4f6": "Trojan.Generic",
}

# Suspicious file extensions
suspicious_extensions = {".exe", ".bat", ".cmd", ".vbs", ".dll", ".scr", ".ps1", ".js"}

# Malicious patterns
malicious_patterns = [
    b"powershell -nop -w hidden -c",
    b"cmd.exe /c",
    b"vssadmin.exe delete shadows /all /quiet",
]

# Function to scan a single file
def scan_file(file_path):
    if not os.path.exists(file_path):
        return f"❌ File not found: {file_path}"
    try:
        with open(file_path, "rb") as f:
            file_content = f.read()
            file_hash = hashlib.md5(file_content).hexdigest()

            # Check for known threats
            if file_hash in known_threats:
                return f"Threat detected {known_threats[file_hash]}"

            # Check for suspicious extensions
            _, file_extension = os.path.splitext(file_path)
            if file_extension.lower() in suspicious_extensions:
                return f"Suspicious file type detected: {file_extension}"

            # Check for malicious patterns
            for pattern in malicious_patterns:
                if pattern in file_content:
                    return f"🚨 Malicious script detected in {file_path}"

            return f"No Threat detected"
    except Exception as e:
        return f"Error scanning file: {e}"


# Function to scan an entire folder
def scan_folder(folder_path):
    if not os.path.exists(folder_path):
        print(f"Folder not found: {folder_path}")
        return

    print(f"🔍 Scanning folder: {folder_path} ...")
    for root, _, files in os.walk(folder_path):
        for file in files:
            scan_file(os.path.join(root, file))
    print(f"✅ Folder scan completed.")



# Command-line interface for user input
def main():
    while True:
        print("\n=== QuickShield Antivirus ===")
        print("1. Scan a file")
        print("2. Scan a folder")
       
        print("5. Exit")
        choice = input("Select an option: ")

        if choice == "1":
            file_path = input("Enter the file path: ")
            scan_file(file_path)
        elif choice == "2":
            folder_path = input("Enter the folder path: ")
            scan_folder(folder_path)
        elif choice == "5":
            print("Exiting QuickShield Antivirus. Stay safe!")
            break
        else:
            print("❌ Invalid option. Please try again.")

if __name__ == "__main__":
    main()
