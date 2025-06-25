# TryHackMe Write-Up: Trooper

## Overview

- **Room**: [Trooper](https://tryhackme.com/room/trooper)
- **Difficulty**: Medium
- **Focus Areas**: Threat Intelligence, APT Analysis, MITRE ATT&CK, OpenCTI
- **Objective**: Analyze an APT using a provided report and CTI platforms to identify malware, TTPs, and attribution.

---

## Tools & Platforms Used

- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [OpenCTI](https://www.opencti.io/)
- [Threat Report](https://www.trendmicro.com/en_th/research/18/c/tropic-trooper-new-strategy.html)
---

## Questions & Answers

### 1. **What kind of phishing campaign does APT X use?**
- Navigated to **MITRE ATT&CK Navigator → Initial Access**
- Located technique: `T1566.001 - Spearphishing Attachment`

> ✅ **Answer**: `Spear-phishing emails`

---

### 2. **What is the name of the malware used by APT X?**
- Found in the attached **APT report**

> ✅ **Answer**: `USBferry`

---

### 3. **What is the malware’s STIX ID?**
- Opened **OpenCTI → Arsenal → USBferry**
- Found under the details panel:

> ✅ **Answer**: `malware--5d0ea014-1ce9-5d5c-bcc7-f625a07907d0`

---

### 4. **With the use of a USB, what technique was used for initial access?**
- Located in **MITRE Navigator → Initial Access**
- Identified technique: `T1091 - Replication Through Removable Media`

> ✅ **Answer**: `Replication through removable media`

---

### 5. **What is the identity of APT X?**
- Found on USBferry’s profile in OpenCTI
- Associated group: **Tropic Trooper**

> ✅ **Answer**: `Tropic Trooper`

---

### 6. **How many attack pattern techniques are associated with the APT?**
- Navigated to **OpenCTI → Threats → Tropic Trooper → Knowledge Overview**

> ✅ **Answer**: `39`

---

### 7. **What is the name of the tool linked to the APT?**
- Located in the **Tools tab** within OpenCTI's APT profile

> ✅ **Answer**: `BITSAdmin`

---

### 8. **What sub-technique does the APT use under “Valid Accounts”?**
- MITRE Navigator → Valid Accounts → Expanded to sub-techniques

> ✅ **Answer**: `Local Accounts`

---

### 9. **Under what tactics does the above technique fall?**
- Looked up **Local Accounts** in OpenCTI → Kill Chain Phases:

> ✅ **Answer**:  
`Defense Evasion`,  
`Privilege Escalation`,  
`Persistence`,  
`Initial Access`

---

### 10. **What technique is the group known for using under the tactic “Collection”?**
- MITRE Navigator → Collection tactic
- Identified: `T1119 - Automated Collection`

> ✅ **Answer**: `Automated Collection`

---

## MITRE ATT&CK Summary for Tropic Trooper

| Tactic              | Technique                        | ID         |
|---------------------|-----------------------------------|------------|
| Initial Access      | Spearphishing Attachment          | T1566.001  |
| Initial Access      | Replication via Removable Media   | T1091      |
| Initial Access      | Valid Accounts – Local Accounts   | T1078.003  |
| Privilege Escalation| Local Accounts                    | T1078.003  |
| Persistence         | Local Accounts                    | T1078.003  |
| Defense Evasion     | Local Accounts                    | T1078.003  |
| Collection          | Automated Collection              | T1119      |
| Tools               | BITSAdmin                         | —          |
| Malware             | USBferry                          | —          |

---

## Key Takeaways

- Navigated and cross-referenced threat data between **MITRE ATT&CK** and **OpenCTI**
- Practiced identifying **TTPs** (tactics, techniques, procedures) from STIX objects and threat reports
- Strengthened familiarity with **APT attribution**, **malware identification**, and **kill chain logic**
- Demonstrated capability to trace the full CTI lifecycle: from indicators to actor profile

---

## References

- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [OpenCTI](https://www.opencti.io/)
- [MITRE ATT&CK Techniques](https://attack.mitre.org/)
- TryHackMe Room: [Trooper](https://tryhackme.com/room/trooper)

---


