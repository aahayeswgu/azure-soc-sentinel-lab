# Azure Cloud SOC — Microsoft Sentinel Honeynet & Live Attack Map

A hands-on Security Operations lab built in Microsoft Azure: I stood up an intentionally
exposed Windows honeypot on the public internet, forwarded its security logs into a
**Microsoft Sentinel** SIEM, hunted the resulting attacks with **KQL**, enriched them with
**GeoIP** data, and visualized where the real-world attackers were coming from on a live
**attack map**.

![Attack map of failed login attempts by geographic origin](images/attack-map.png)

> Within roughly a day of being exposed, the honeypot logged **tens of thousands** of failed
> login attempts from around the world — Belgium (12.3K), the Netherlands (12K), Poland (10.2K),
> Vietnam, Germany, and the US — a vivid demonstration of how fast an internet-facing host is
> discovered and brute-forced.

---

## What this project demonstrates

- **Cloud infrastructure (Azure IaaS):** resource groups, virtual networks/subnets, network
  security groups, and a Windows VM
- **SIEM deployment & administration:** Microsoft Sentinel on top of a Log Analytics workspace
- **Log pipeline engineering:** Azure Monitor Agent (AMA) + a Data Collection Rule (DCR)
  forwarding Windows Security events into a central repository
- **Threat hunting with KQL:** querying, filtering, projecting, and joining log data
- **Threat-intel enrichment:** a GeoIP watchlist resolving attacker IPs to physical locations
- **Security visualization:** a Sentinel Workbook rendering attack origins on a world map
- **SOC fundamentals:** Windows security event analysis (Event ID **4625** — failed logon),
  attacker behavior, and the case for defense-in-depth

---

## Architecture

```
                          PUBLIC INTERNET  (attackers, bots, brute-forcers)
                                   |
                                   v
        +--------------------------------------------------------------+
        |  Azure Subscription  >  Resource Group (RG-SOC-Lab)          |
        |                                                              |
        |   Virtual Network (10.0.0.0/16)                              |
        |     +------------------------------------------------+       |
        |     |  Windows VM "honeypot"                         |       |
        |     |   - Public IP, RDP exposed                     |       |
        |     |   - NSG: DANGER rule = Allow ANY/ANY/ANY in    |       |
        |     |   - Windows Firewall disabled (intentional)    |       |
        |     |   - Azure Monitor Agent (AMA)                  |       |
        |     +-----------------------+------------------------+       |
        |                             | Security event logs            |
        |                Data Collection Rule (DCR-Windows)            |
        |                             v                                |
        |             Log Analytics Workspace (LAW-soc-lab)           |
        |                             |                                |
        |                             v                                |
        |             Microsoft Sentinel  (SIEM)                       |
        |               - KQL hunting (Event ID 4625)                 |
        |               - GeoIP watchlist enrichment                  |
        |               - Workbook: "Windows VM attack map"           |
        +--------------------------------------------------------------+
```

### Tech stack

| Layer | Service / Tool |
|---|---|
| Cloud | Microsoft Azure (East US 2) |
| Compute | Windows 10 VM (honeypot) |
| Network | Virtual Network, Subnet, Network Security Group |
| Log collection | Azure Monitor Agent + Data Collection Rule |
| Log repository | Azure Log Analytics Workspace |
| SIEM | Microsoft Sentinel |
| Query language | KQL (Kusto Query Language) |
| Enrichment | GeoIP watchlist (IP range → lat/long/city/country) |
| Visualization | Azure / Sentinel Workbook |

---

## Build walkthrough

### 1. Azure infrastructure
Created a resource group, a virtual network (`10.0.0.0/16`) and subnet to host the lab.
Note the network is deliberately bare — no DDoS protection, Azure Firewall, or private
endpoints — to keep the honeypot reachable.

![Virtual network](images/virtual-network.png)

### 2. The honeypot VM + an intentionally wide-open firewall
Deployed a Windows VM with a public IP, then **removed the default RDP-only inbound rule and
replaced it with an "allow any" rule** so the host would be discovered and attacked as quickly
as possible. The internal Windows Firewall was also disabled.

![NSG with a permissive DANGER rule](images/nsg-danger-rule.png)

### 3. Central logging — Log Analytics + the data collection pipeline
Stood up a Log Analytics workspace as the central log repository, then used the Azure Monitor
Agent and a Data Collection Rule to forward the VM's Windows **Security** events into it.

![Log Analytics workspace](images/log-analytics-workspace.png)
![Data collection rule](images/data-collection-rule.png)

### 4. The SIEM and the full resource set
Connected the workspace to Microsoft Sentinel. The complete lab — VM, public IP, NSG, NIC,
disk, DCR, workspace, Sentinel (SecurityInsights), and the attack-map workbook:

![Resource group contents](images/resource-group.png)

### 5–7. Hunt, enrich, and visualize
Queried failed logons in KQL, enriched the attacker IPs against a GeoIP watchlist, and plotted
the results in a Sentinel Workbook (the attack map at the top of this README).

---

## KQL used

Find failed logon attempts (Windows Event ID **4625**) and project the fields that matter:

```kql
SecurityEvent
| where EventID == 4625                         // an account failed to log on
| project TimeGenerated, Computer, AttackerIP = IpAddress, Account, Activity
| sort by TimeGenerated desc
```

Enrich each attacker IP with geographic data from the GeoIP watchlist and aggregate for the map:

```kql
let GeoIPDB = _GetWatchlist("geoip");
SecurityEvent
| where EventID == 4625
| evaluate ipv4_lookup(GeoIPDB, IpAddress, network)
| project
    TimeGenerated, Computer,
    AttackerIP       = IpAddress,
    City             = cityname,
    Country          = countryname,
    Latitude         = latitude,
    Longitude        = longitude,
    FriendlyLocation = strcat(cityname, " (", countryname, ")")
| summarize FailedAttempts = count()
    by AttackerIP, City, Country, FriendlyLocation, Latitude, Longitude
| sort by FailedAttempts desc
```

---

## Results & key findings

- **Exposure is detected in minutes to hours.** Automated scanners and brute-force bots found
  the open RDP surface almost immediately.
- **Volume is relentless.** The map reflects **tens of thousands** of failed logon attempts,
  with single source regions exceeding 10K attempts each.
- **Geography is global.** Top origins included Belgium, the Netherlands, Poland, Vietnam,
  Germany, and the United States.
- **A SIEM turns noise into signal.** Raw Windows Event Viewer logs are unreadable at this
  volume; Sentinel + KQL + a watchlist made the attack pattern legible and visual.

---

## Limitations & next steps

This lab stops at detection and visualization. To grow it toward a realistic SOC:

- **Analytic rules & incidents** — turn the 4625 spike into Sentinel alerts that auto-create
  and triage incidents
- **Automation (SOAR)** — playbooks to auto-respond (e.g., block source IP ranges)
- **Harden the host** — restore least-privilege NSG rules and measure the drop in noise
- **Broader telemetry** — Sysmon, Defender for Endpoint, and additional data connectors
- **MITRE ATT&CK mapping** — classify observed techniques (e.g., T1110 Brute Force)

> ⚠️ A honeypot is intentionally insecure. It was isolated, monitored, and torn down after the
> exercise. Never run an "allow any" host on a network you care about.

---

## Acknowledgment

This is a hands-on build of the well-known Azure + Microsoft Sentinel SOC honeynet lab
popularized by **Josh Madakor**. The architecture and lab concept are his; the deployment,
configuration, queries, and analysis here are my own work.
