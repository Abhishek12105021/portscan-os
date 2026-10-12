#port scan
.\scripts\test_scan_100.ps1

# finger printing

# icmp + firewall on
python Imp\attacker\main.py --adapter "\Device\NPF_{79613882-4F62-495C-9891-92E06A2C6E9B}" --target 10.175.160.165 --ports 21 22 80 81 --skip-exploits --prefer-icmp

# open 21,80 / closed port + firewall off
python Imp\attacker\main.py --adapter "\Device\NPF_{79613882-4F62-495C-9891-92E06A2C6E9B}" --target 10.175.160.165 --ports 21 22 80 81 --skip-exploits

# exploit check - firewall on/off does not matter
python Imp\attacker\main.py --adapter "\Device\NPF_{79613882-4F62-495C-9891-92E06A2C6E9B}" --target 10.175.160.165 --ports 21 22 80 81


#ssh exploit
.\scripts\test_ssh_attack.ps1 quiet
.\scripts\test_ssh_attack.ps1 loud

#defense 

# firewall needs to be on to enforce the rule

#honeyport
python Imp\attacker\main.py --adapter "\Device\NPF_{79613882-4F62-495C-9891-92E06A2C6E9B}" --target 10.175.160.165 --ports 21 22 80 81 
#fast syn-fin flag - fast scan
python Imp\attacker\main.py --adapter "\Device\NPF_{79613882-4F62-495C-9891-92E06A2C6E9B}" --target 10.175.160.165 --ports 21 22 80 
# slow stealth scan
python Imp\attacker\main.py --adapter "\Device\NPF_{79613882-4F62-495C-9891-92E06A2C6E9B}" --target 10.175.160.165 --ports 21 22 80 135 139 443 445 8080 8443 3306 5432 1433 1521 25 110 993 995 53 88 123 --delay 2.5 
