# === 0. Unit Tests & Setup ===
python -m pytest Imp/tests/ -v
python -c "import sys; sys.path.insert(0, 'Imp'); from common.npcap import list_adapters; [print(f'{a[0]} -> {a[1]}') for a in list_adapters()]"

# === 1. Victim Services ===
# FTP Server (Port 21)
python Imp\victim\ftp_server.py --port 21

# HTTP Server (Port 80)
python Imp\victim\http_server.py --port 80

# Defense Engine (Passive)
python Imp\defense\main.py --adapter "\Device\NPF_{439707FA-9208-4AF9-BEDE-002C5F9EE7CB}" --threshold 8 --window 10

# Defense Engine (Active Blocker)
python Imp\defense\main.py --adapter "\Device\NPF_{439707FA-9208-4AF9-BEDE-002C5F9EE7CB}" --threshold 8 --window 10 --block

# OpenSSH Victim Setup
Start-Service sshd
net user test test123 /add
net localgroup administrators test /add

# === 2. Attacker Runs ===
# Full Chain Attack (Ports 21, 22, 80, 81)
python Imp\attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.116 --ports 21 22 80 81

# Active Defense Probe & Verification
python Imp\attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.116 --ports 21 22 80 81
python Imp\attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.116 --ports 21 80

# Closed-Port RST Fingerprint (Zero-Open-Port)
python Imp\attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.116 --ports 80 81 82 --skip-banners --skip-exploits

# === 3. SSH Exploits ===
.\scripts\test_ssh_attack.ps1 quiet
.\scripts\test_ssh_attack.ps1 loud

# === 4. 100-Port Scale Test ===
.\scripts\test_scan_100.ps1

# === 5. Cross-Platform Targets ===
# Kali Linux VM
python Imp\attacker\main.py --adapter "\Device\NPF_{97791388-568A-4124-AB80-5BF4BC58551D}" --target 192.168.56.101 --ports 21 22 80
python Imp\attacker\main.py --adapter "\Device\NPF_{97791388-568A-4124-AB80-5BF4BC58551D}" --target 192.168.56.101 --ports 22 80 81 --skip-exploits
python Imp\attacker\main.py --adapter "\Device\NPF_{97791388-568A-4124-AB80-5BF4BC58551D}" --target 192.168.56.101 --ports 22 80 81 --skip-exploits --prefer-icmp

# iPad (Port 80 VLC Web Sharing)
python Imp\attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.152 --ports 80 81 --skip-exploits

# Android Phone (Port 2221 WiFi FTP)
python Imp\attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.169 --ports 2221 2122 --skip-exploits

# === 6. Standalone Probes ===
python Imp\attacker\exploits\http_traversal.py --target 192.168.0.116 --port 80
python Imp\attacker\exploits\ftp_anon.py --target 192.168.0.116 --port 21
python Imp\attacker\banner.py --target 192.168.0.116 --ports 21 22 80
python Imp\attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.116 --ports 21 22 80 --skip-banners --skip-exploits

# === 7. Cleanup ===
netsh advfirewall firewall delete rule name=CustomPortScanBlock*
netsh advfirewall set allprofiles state on
Stop-Service sshd
net user test /delete
Remove-Item C:\Users\test -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "Imp\victim\lab_root\uploads\shell.py" -Force -ErrorAction SilentlyContinue
