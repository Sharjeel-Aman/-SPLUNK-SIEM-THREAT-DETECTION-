[README (1).md](https://github.com/user-attachments/files/33888118/README.1.md)
# 🔐 SIEM Log Monitoring & Threat Detection Using Splunk

> **A Hands-On Blue Team / SOC Analyst Lab Project**
>
> **Author:** Sharjeel Aman | *Cybersecurity Student & Aspiring SOC Analyst*

## 📌 Project Overview

This project demonstrates core Security Operations Center (SOC) operations using **Splunk Enterprise** and **Microsoft Sysmon** within a Windows lab environment.

The primary objective was to configure endpoint telemetry collection, monitor Windows security events, investigate failed login attempts, analyze command-line process execution, configure detection alerts, and build an operational SOC dashboard.

### Key Highlights

- **SIEM & Log Management:** Configured Splunk to ingest Windows Security Logs and Sysmon telemetry.
- **Threat Detection & SPL:** Developed custom Search Processing Language (SPL) queries for authentication monitoring and process execution tracking.
- **Alerting & Visualization:** Designed threshold-based Splunk alerts and created an operational SOC dashboard for real-time visibility.
- **Analytical Rigor:** Applied defensive investigation methodologies, ensuring clear distinction between historical benign logs and active threat testing.

## 🏗️ Lab Architecture

```
┌──────────────────────────────────────┐
│            Kali Linux VM             │
│                                      │
│    Security Testing Environment      │
│   (Hydra - Planned SMB Password Test)│
└──────────────────┬───────────────────┘
                   │
                   │ SMB Test Traffic
                   ▼
┌──────────────────────────────────────┐
│         Windows Lab Machine          │
│                                      │
│  • Windows Security Logs (Event 4625)│
│  • Sysmon Operational Logs (Event 1) │
│  • PowerShell Execution Activity     │
└──────────────────┬───────────────────┘
                   │
                   │ Local Event Collection
                   ▼
┌──────────────────────────────────────┐
│          Splunk Enterprise           │
│                                      │
│  • SPL Search & Event Analysis       │
│  • Failed Login Alerting Rules       │
│  • SOC Monitoring Dashboard          │
└──────────────────────────────────────┘

```

> **Note:** Event ingestion from Windows to Splunk was established locally. Historical failed login events were analyzed as baseline data, while synthetic brute-force testing via Hydra was planned in an isolated subnet.

## 🛠️ Tools & Technologies

| Tool / Technology         | Category           | Purpose                                                            |
| ------------------------- | ------------------ | ------------------------------------------------------------------ |
| **Splunk Enterprise**     | SIEM / Analytics   | Ingestion, log search, alert creation, and dashboard visualization |
| **Microsoft Sysmon**      | Endpoint Telemetry | Granular Windows process-creation logging (Event ID 1)             |
| **Windows Security Logs** | System Telemetry   | Authentication auditing and security event logs (Event ID 4625)    |
| **Kali Linux**            | Security Testing   | Controlled security testing environment                            |
| **Hydra**                 | Testing Framework  | Authorized SMB authentication testing                              |
| **PowerShell / CMD**      | CLI / Automation   | Benign execution simulations and system diagnostics                |
| **SPL**                   | Query Language     | Processing, filtering, and aggregating security data in Splunk     |
| **VirtualBox**            | Virtualization     | Isolated host environment for lab execution                        |

## 🚨 Investigation 1: Windows Failed Login Monitoring

### Objective

Identify Windows failed login attempts (Event ID 4625), analyze target accounts and source IP addresses, and determine if the activity indicates brute-force or password-spraying behavior.

### Target Telemetry Details

- **Target Hostname:** `THREAT-HUNTER`
- **Target Event ID:** `4625` (An account failed to log on)
- **Events Analyzed:** `22` historical failed-login events
- **SIEM Ingestion Index:** Default / System Log Indices (`index=*`)

### Detection Queries (SPL)

#### Aggregate View by Source Address & Account

```
index=* EventCode=4625
| stats count as Failed_Attempts by Source_Network_Address, Account_Name, Logon_Type
| sort - Failed_Attempts

```

#### Granular Timeline Inspection

```
index=* EventCode=4625
| table _time, host, EventCode, Account_Name, Source_Network_Address, Logon_Type, Authentication_Package
| sort - _time

```

### 🔍 SOC Analyst Findings

- Search results identified **22 failed login events** across historical data.
- **Analytical Note:** While useful for baseline authentication monitoring, these events were not immediately flagged as a confirmed brute-force attack. Analysts must cross-examine the `Source_Network_Address`, timestamp clustering, and `Logon_Type` (e.g., Type 3 for network logins, Type 2 for interactive) before escalating.

## ⚠️ Investigation 2: PowerShell Process Creation Monitoring

### Objective

Review PowerShell execution telemetry in Sysmon to analyze command-line arguments and identify potential abuse of administrative utilities.

### Test Command Executed

The following non-malicious command was run to generate process-creation telemetry:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Host 'Simulated Attack - SOC Lab Test'"

```

### Detection Query (SPL)

Searching Sysmon **Event ID 1** (Process Creation) within the dedicated index:

```
index=test_index EventCode=1 Image="*powershell.exe"
| table _time, host, User, Image, CommandLine, ParentImage
| sort - _time

```

### 🔍 SOC Analyst Findings

- Verified that Sysmon accurately captured the command execution, including command-line switches (`-NoProfile`, `-ExecutionPolicy Bypass`).
- **SOC Perspective:** PowerShell is a legitimate administrative tool. Analysts must look for contextual anomaly indicators—such as un-pivoted parent processes (e.g., `cmd.exe`, `wmiprvse.exe`, or web servers like `w3wp.exe`), encoded commands (`-EncodedCommand`), or unusual executing users—before classifying activity as malicious.

## 🔔 Splunk Alert Configuration

To move from manual threat hunting to automated detection, a Splunk alert rule was configured for authentication monitoring.

### Standard Production Alert Rule (Threshold-Based)

Rather than alerting on single occurrences (which creates alert fatigue), the detection was enhanced to trigger when failed logins exceed a baseline threshold:

```
index=* EventCode=4625
| stats count as failed_attempts by Source_Network_Address, Account_Name
| where failed_attempts >= 5

```

### Rule Parameters

- **Alert Name:** `Windows Failed Login Threshold Exceeded`
- **Trigger Condition:** Number of Results > 0
- **Threshold:** `≥ 5` failed attempts within a 5-minute window
- **Action:** Add to Triggered Alerts / Notify SOC Analyst

## 📊 SOC Monitoring Dashboard

To support continuous security monitoring, a dedicated **SOC Monitoring Dashboard** was generated in Splunk.

### Key Panels & Visualizations

#### 1. Failed Login Events Over Time (Timechart)

```
index=* EventCode=4625
| timechart span=1h count as "Failed Logins"

```

#### 2. Top Target Accounts (Bar Chart / Table)

```
index=* EventCode=4625
| stats count as "Attempts" by Account_Name, Source_Network_Address
| sort - "Attempts"
| head 10

```

## 🔧 How to Reproduce the Lab

### Prerequisites

- Windows 10/11 Virtual Machine
- Splunk Enterprise Installed locally
- Microsoft Sysmon
- VirtualBox or VMware Workstation

### Step 1: Install & Configure Sysmon

1. Download Sysmon from the official [Microsoft Sysinternals Page](https://learn.microsoft.com/sysinternals/downloads/sysmon "null").
2. Open **Command Prompt as Administrator** in the Sysmon directory.
3. Install Sysmon using the default configuration (or supply a custom config XML):
   ```
   sysmon64.exe -accepteula -i

   ```
4. Verify that the Sysmon service is running:
   ```
   sc query Sysmon64

   ```

### Step 2: Configure Splunk Log Ingestion

Edit the Splunk input configuration file on your Windows machine to ingest Sysmon logs:

`C:\Program Files\Splunk\etc\system\local\inputs.conf`

Add the following stanza:

```
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = test_index
renderXml = true

```

*Note: Ensure `test_index` is created via the Splunk Web UI (`Settings > Indexes > New Index`) and restart Splunk if necessary.*

#### Verify Ingestion in Splunk

```
index=test_index | stats count by sourcetype

```

### Step 3: Execute Simulated Commands

1. Run the benign PowerShell test command in Command Prompt or PowerShell:
   ```
   powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Host 'Simulated Attack - SOC Lab Test'"

   ```
2. Open Splunk and search for the execution using the Sysmon process query to confirm telemetry flow.

## 📈 Summary of Results

| Component                 | Status / Result                                                       |
| ------------------------- | --------------------------------------------------------------------- |
| **Failed-Login Analysis** | Successfully queried and aggregated 22 historical Event ID 4625 logs. |
| **Sysmon Integration**    | Process creation telemetry (Event ID 1) ingested into `test_index`.   |
| **PowerShell Simulation** | Command-line parameters successfully extracted and audited.           |
| **Splunk Alerting**       | Implemented a threshold-based alert rule to minimize noise.           |
| **SOC Dashboard**         | Built operational panel visualizing authentication trends over time.  |

## 🧠 Key Learnings & Skill Takeaways

- **Advanced SPL Querying:** Developed skills in writing efficient SPL queries using aggregations (`stats`), time-series rendering (`timechart`), and conditional logic (`where`).
- **Telemetry Parsing:** Gained hands-on experience parsing Windows Security Logs and Sysmon event structures.
- **Alert Noise Reduction:** Understood the necessity of threshold-based alerting over presence-based alerting to prevent analyst burnout.
- **Analytical Discipline:** Reinforced the rule of verifying threat activity via log correlation before drawing definitive conclusions.

### 🏷️ Related Keywords

`Cybersecurity` • `Splunk` • `SIEM` • `SOC Analyst` • `Blue Team` • `Sysmon` • `Threat Detection` • `Log Analysis` • `Windows Event Logs`
