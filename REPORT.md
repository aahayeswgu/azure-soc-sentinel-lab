# Lab Report: A Honeypot SIEM in Azure

I built this to test something I had only ever read about: how fast does a machine get attacked once it is sitting on the open internet, and can I watch it happen in real data instead of taking someone's word for it? The short version is that it gets attacked almost right away, and a SIEM is what turns that flood of noise into something you can actually read.

## The idea: a honeypot wired into a SIEM

A honeypot is a machine you stand up on purpose to get attacked. It has no real users and no real data, so anything that touches it is either a scanner, a bot, or a person who has no business being there. That makes it a clean signal. Every login attempt is hostile by definition, which means I do not have to separate legitimate traffic from malicious traffic the way I would on a production host.

On its own a honeypot just collects dust and log entries. The useful part is pointing a SIEM at it. In this lab the host generates the events and Microsoft Sentinel collects, stores, queries, and visualizes them. The honeypot is the bait; the SIEM is how I see what the bait caught.

## How it is built

Everything runs in a single Azure resource group in East US 2.

- A virtual network on 10.0.0.0/16 with one subnet, and nothing protecting it. No Azure Firewall, no DDoS plan, no private endpoints. The door is open on purpose.
- A Windows 10 VM with a public IP, acting as the honeypot. Azure's default network security group only allows RDP inbound, so I deleted that rule and replaced it with an allow-any inbound rule. I also turned off the Windows firewall on the host. At that point the box was reachable from anywhere, on any port.
- Azure Monitor Agent on the VM, with a Data Collection Rule that forwards the Windows Security event log into a Log Analytics workspace. The workspace is the central store.
- Microsoft Sentinel connected on top of the workspace. This is where the hunting queries and the attack-map workbook live.

So the flow is: attacker hits the VM, Windows writes a security event, the agent and DCR ship it to Log Analytics, and Sentinel makes it queryable.

## What I hunted for

When an account fails to log on, Windows writes Event ID 4625. On a normal machine you see a few of these. On this one it became a firehose, which is exactly the point.

The first query just pulls the failed logons so I can confirm the attacks are landing, and a second pass counts them per source IP to see who is hitting hardest:

```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Computer, AttackerIP = IpAddress, Account, Activity
| sort by TimeGenerated desc

// who is hammering the host hardest
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress
| sort by FailedAttempts desc
```

There is also a five-minute window version I left running like a live-fire view, just to watch the count climb in close to real time:

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(5m)
| project TimeGenerated, Computer, AttackerIP = IpAddress, Account
```

A raw IP does not tell me much, so I enriched each one against a GeoIP watchlist (about 55K rows of IP ranges mapped to a location) loaded into Sentinel. The `ipv4_lookup` operator does the join, and the aggregation at the end is what feeds the map:

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

I dropped that result into a Sentinel Workbook and plotted it on a world map, which is the image at the top of the repo.

## What we captured

Within about a day of the host being exposed, it had logged tens of thousands of failed logon attempts. A handful of source regions stood out:

- Belgium, roughly 12.3K attempts
- Netherlands, close to 12K
- Poland, around 10.2K
- Vietnam, Germany, and the United States not far behind

These were not people sitting at keyboards. The pattern - high volume, steady, spread across the globe and aimed straight at the exposed RDP surface - is automated. Bots crawl public IP ranges around the clock looking for open ports and weak credentials, and this box walked right into that. The Account field on the 4625 events showed the usual spray of common usernames (administrator, admin, and so on), which is the brute-force signature you would expect.

Two things stuck with me. First, there was no warm-up. The traffic showed up fast, so discovery is clearly not the hard part for an attacker; the whole internet is being scanned constantly. Second, the raw event log is unreadable at this scale. Scrolling Event Viewer through tens of thousands of entries tells you nothing. The SIEM is what turned that flat wall of 4625 events into a ranked, mapped picture I could understand in seconds, and that is the entire argument for running one.

## Where I would take it next

This lab stops at detection and visualization, which is really only the front half of a SOC. The next steps I have in mind:

- Turn the 4625 spike into a Sentinel analytic rule so it raises an incident on its own instead of me running queries by hand.
- Add a SOAR playbook to respond automatically, for example blocking a source range once it crosses a threshold.
- Put the NSG back to least privilege and re-run the same queries to measure how much the noise drops. That before-and-after would say a lot on its own.
- Bring in more telemetry, like Sysmon and a Defender connector, so I am not leaning on a single event ID.
- Map what I saw to MITRE ATT&CK. The brute forcing lines up with T1110, and naming techniques is how you start building real detections instead of one-off queries.

## A note on safety

The honeypot is insecure by design. I kept it isolated, watched it the entire time it was up, and tore it down when I was finished. Running an allow-any host is fine as a controlled experiment and a bad idea anywhere you care about.

The lab concept follows Josh Madakor's Azure SOC walkthrough. The build, the queries, the analysis, and this report are my own.
