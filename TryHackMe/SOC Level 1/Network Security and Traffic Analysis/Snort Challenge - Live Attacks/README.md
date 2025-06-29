# TryHackMe - Snort Challenges 2 Walkthrough

**Room**: Snort Challenges 2  
**Difficulty**: Medium  
**Platform**: TryHackMe

## Task 1 - Introduction

The room invites you to a challenge where you will investigate a series of traffic data and stop malicious activity under two different scenarios. Let's start working with Snort to analyse live and captured traffic.

Before joining this room, we suggest completing the Snort room.


**Note**: There are two VMs attached to this challenge. Each task has dedicated VMs. You don't need SSH or RDP, the room provides a "Screen Split" feature.

## Task 2 - Scenario 1 | BruteForce

### Objective
Observe the traffic with Snort and identify the anomaly before writing a rule to filter malicious packets to stop the brute force attack.

### Steps:
1. First, start Snort in sniffer mode and try to figure out the attack source, service and port
2. Then, write an IPS rule and run Snort in IPS mode to stop the brute-force attack
3. Once you stop the attack properly, you will have the flag on the desktop

### Key Points:
- Create the rule and test it with "-A console" mode
- Use "-A full" mode and the default log path to stop the attack
- Write the correct rule and run the Snort in IPS "-A full" mode
- Block the traffic at least for a minute and then the flag file will appear on your desktop

### Solution Process:

**Step 1: Traffic Analysis**
```bash
sudo snort -vde
```

Found SSH breach activity in the traffic - identified the attack as an SSH brute force attempt.

![snort challenges 2breachfound](https://github.com/user-attachments/assets/e6c325a9-db32-42f6-b365-2dc9374681f8)

**Step 2: Create IPS Rule**
Added rule to `/etc/snort/rules/local.rules`:
```
alert tcp any any <> any any (msg:"Breach Found";content:"ssh",nocase;sid:1000001;rev:1;)
```

**Step 3: Run Snort in IPS Mode**
```bash
sudo snort -c /etc/snort/rules/local.rules -q -Q --daq afpacket -i eth0:eth1 -A full
```

This command filters and drops packets with "ssh" in their payload, stopping the breach.

### Questions and Answers:

**Stop the attack and get the flag (which will appear on your Desktop)**
- **Answer**: `THM{81b7fef657f8aaa6e4e200d616738254}`

**What is the name of the service under attack?**
- **Answer**: `ssh`

**What is the used protocol/port in the attack?**
- **Method**: Run the previous command but with `-A console`
- **Answer**: `TCP/22`

![protocolport](https://github.com/user-attachments/assets/1190d2e9-5757-48f8-a725-129003bb143f)


## Task 3 - Scenario 2 | Reverse-Shell

### Objective
Filter malicious outbound traffic to stop a reverse shell attack.

### Steps:
1. First, start Snort in sniffer mode and try to figure out the attack source, service and port
2. Then, write an IPS rule and run Snort in IPS mode to stop the attack
3. Once you stop the attack properly, you will have the flag on the desktop

### Key Points:
- Create the rule and test it with "-A console" mode
- Use "-A full" mode and the default log path to stop the attack
- Write the correct rule and run the Snort in IPS "-A full" mode
- Block the traffic at least for a minute and then the flag file will appear on your desktop

### Solution Process:

**Step 1: Traffic Analysis**
```bash
sudo snort -vde
```

Found suspicious Ubuntu IP in the traffic indicating a reverse shell connection.

![snort challenges 2ubuntu](https://github.com/user-attachments/assets/05fbb12c-a231-4960-83b0-1317d8a46545)


**Step 2: Create IPS Rule**
Added rule to `/etc/snort/rules/local.rules`:
```
alert tcp any any <> any any (msg:"Breach Found";content:"ubuntu",nocase;sid:1000001;rev:1;)
```

**Step 3: Run Snort in IPS Mode**
```bash
sudo snort -c /etc/snort/rules/local.rules -q -Q --daq afpacket -i eth0:eth1 -A full
```

Successfully stopped the reverse shell attack.

### Questions and Answers:

**Stop the attack and get the flag (which will appear on your Desktop)**
- **Answer**: `THM{0ead8c494861079b1b74ec2380d2cd24}`

**What is the used protocol/port in the attack?**
- **Method**: Run the previous command but with `-A console`
- **Answer**: `TCP/4444`

![snort challenges 2port44](https://github.com/user-attachments/assets/18078871-ded6-437f-a7af-467da488947f)


**Which tool is highly associated with this specific port number?**
- **Research**: Referenced multiple websites including [CBT Nuggets - What is Port 4444](https://www.cbtnuggets.com/common-ports/what-is-port-4444)
- **Answer**: `metasploit`

## Conclusion

All attacks have been successfully intercepted and terminated using custom Snort IPS rules. Both scenarios demonstrated effective network security monitoring and threat mitigation techniques.

## Skills Learned

- **Network Traffic Analysis**: Using Snort in sniffer mode to identify malicious activity
- **IDS/IPS Rule Creation**: Writing custom Snort rules with content-based detection
- **Attack Pattern Recognition**: Identifying SSH brute force and reverse shell attacks
- **Command Line Proficiency**: Operating Snort with various modes and parameters
- **Incident Response**: Implementing real-time threat mitigation strategies
