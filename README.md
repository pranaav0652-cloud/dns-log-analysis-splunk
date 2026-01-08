# Analyzing DNS Log Files Using Splunk SIEM

## Project Overview
This project simulates a real-world Security Operations Center (SOC) investigation by ingesting and analyzing DNS log data using Splunk SIEM.

The objective is to detect and investigate suspicious DNS activity that may indicate malware communication, domain generation algorithms (DGA), reconnaissance, or other malicious behavior — following a structured SOC analyst workflow.


## Objectives
- Ingest DNS log data into Splunk SIEM using a custom index and sourcetype
- Perform DNS threat detection using SPL queries
- Identify anomalous DNS behavior such as:
    - High-volume DNS activity
    - Rare domain lookups (DGA indicators)
    - Reverse DNS (PTR) reconnaissance
    - Known malicious domain communication

- Apply threat intelligence validation to support investigations
- Demonstrate Tier-1 SOC analyst workflows

## SOC Analyst Relevance
This project mirrors common SOC responsibilities, including:

- Log ingestion and validation in a SIEM
- Writing and tuning detection queries (SPL)
- Investigating suspicious network behavior
- Using threat intelligence to validate findings
- Following a structured investigation approach

## Environment & Tools
- **SIEM**: Splunk Enterprise
- **Log Source**: DNS log files (.log / .txt)
- **Index**: dns_index
- **Sourcetype**: dns_logs
- **Query Language**: SPL (Search Processing Language)
- **Threat Intelligence**: VirusTotal


## Data Ingestion Workflow

### 1. Prepared DNS log files containing:
- Source IP
- Destination IP
- Queried domain
- Query type
- Response code

### 2. Uploaded logs via Splunk Web -> Add Data

### 3. Configured:
- Custom sourcetype: dns_logs
- Dedicated index: dns_index

### 4. Verified ingestion and parsing:

```spl
index=dns_index sourcetype=dns_logs
```


## Detection & Analysis Use Cases

### 1. DNS Event Exploration
Reviewed DNS events to understand available fields and data structure.

```spl
index=dns_index sourcetype=dns_logs
```

### 2. Field Extraction & Validation
Identified critical DNS fields for investigation.

```spl
index=dns_index sourcetype=dns_logs
| table _time src_ip query query_type response_code
```

### 3. High-Volume DNS Activity Detection
Detected hosts generating an unusually high number of DNS queries.

```spl
index=dns_index sourcetype=dns_logs
| stats count by src_ip
| sort - count
```
Filtered sources exceeding a defined threshold:

```spl
index=dns_index sourcetype=dns_logs
| stats count by src_ip
| where count > 1000
```

### 4. Top DNS Query Sources
Identified systems generating the most DNS traffic.

```spl
index=dns_index sourcetype=dns_logs
| stats count by src_ip
```

### 5. Reverse DNS (PTR) Reconnaissance Detection
Investigated PTR queries that may indicate scanning or reconnaissance.

```spl
index=dns_index sourcetype=dns_logs PTR
```

### 6. Rare DNS Query Detection (DGA Indicators)
Detected low-frequency domain queries that may suggest DGA-based malware.

```spl
index=dns_index sourcetype=dns_logs
| stats count by query
| where count < 5
```

### 7. Known Malicious Domain Investigation
Searched for DNS queries associated with known malicious domains and validated using threat intelligence.

```spl
index=dns_index sourcetype=dns_logs query="maliciousdomain.com"
```
**Threat Validation:**
Domains were cross-checked using VirusTotal to confirm malicious reputation.


## Detection Use Cases Implemented
- High-volume DNS abuse detection
- Rare domain query identification (DGA indicators)
- Reverse DNS reconnaissance analysis
- Known malicious domain investigation
- DNS anomaly analysis using statistical thresholds

## Skills Demonstrated
- Splunk SIEM configuration & usage
- SPL query development
- DNS security analysis
- Threat detection & investigation
- Threat intelligence validation
- SOC analyst investigative workflow

## Conclusion
This project demonstrates how DNS log analysis using Splunk SIEM can effectively support threat detection and investigation within a SOC environment. By applying structured analysis, SPL queries, and threat intelligence validation, DNS telemetry can provide critical insights into malicious network activity.

