# Analyzing DNS Log Files Using Splunk SIEM

## Introduction
DNS (Domain Name System) logs play a critical role in monitoring network activity and detecting potential security threats. By analyzing DNS traffic, security analysts can identify suspicious behaviors such as malware communication, domain generation algorithms (DGA), and reconnaissance activity.  

This project demonstrates how **Splunk SIEM** can be used to ingest, analyze, and investigate DNS logs following a **Security Operations Center (SOC) analyst workflow**.


## Prerequisites
Before analyzing DNS logs in Splunk, ensure the following:
- Splunk Enterprise is installed and properly configured.
- DNS log files are available for ingestion into Splunk.
- Basic familiarity with SPL (Search Processing Language).


## Steps to Upload Sample DNS Log Files to Splunk SIEM

### 1. Prepare Sample DNS Log Files
- Obtain a sample DNS log file in a supported format (e.g., `.log` or `.txt`).
- Ensure the logs contain relevant DNS information such as:
  - Source IP address
  - Destination IP address
  - Queried domain name
  - Query type
  - Response code
- Store the log file in a directory accessible by the Splunk instance.


### 2. Upload Log Files to Splunk
- Log in to the Splunk Web interface.
- Navigate to **Settings → Add Data**.
- Select **Upload** as the data input method.


### 3. Choose File
- Click **Select File** and upload the prepared DNS log file.


### 4. Set Sourcetype
- In the **Set Source Type** section, configure a custom sourcetype for DNS logs (e.g., `dns_logs`).
- Preview events to ensure the DNS data is parsed correctly.


### 5. Configure Index and Host
- Assign a dedicated index (e.g., `dns_index`) to store DNS events.
- Configure the host field as required for identification.


### 6. Review and Submit
- Review all ingestion settings including file name, sourcetype, host, and index.
- Click **Submit** to ingest the DNS log file into Splunk.


### 7. Verify Data Ingestion
- Navigate to the Splunk Search interface.
- Run the following query to confirm DNS events are indexed and searchable:

```spl
index=dns_index sourcetype=dns_logs
```

## Steps to Analyze DNS Log Files in Splunk SIEM

### 1. Search for DNS Events
- Retrieve all DNS events to understand the structure and available fields.

```spl
index=dns_index sourcetype=dns_logs
```

### 2. Extract Relevant Fields
- Identify important DNS fields such as source IP, domain name, query type, and response code.
- Display extracted fields to support structured analysis.

```spl
index=dns_index sourcetype=dns_logs
| table _time src_ip
```

### 3. Identify Anomalies in DNS Activity
- Analyze DNS traffic for unusual patterns or spikes that may indicate suspicious behavior.

```spl
index=dns_index sourcetype=dns_logs
| stats count by src_ip
| sort - count
```

### 4. Find Top DNS Query Sources
- Identify hosts generating the highest volume of DNS queries.

```spl
index=dns_index sourcetype=dns_logs
| stats count by src_ip
```

### 5. Detect High-Volume DNS Activity
- Filter DNS sources that exceed a defined activity threshold for further investigation.

```spl
index=dns_index sourcetype=dns_logs
| stats count by src_ip
| where count > 1000
```

### 6. Investigate Reverse DNS (PTR) Lookups
- Analyze PTR queries to identify potential scanning or reconnaissance activity.

```spl
index=dns_index sourcetype=dns_logs PTR
```

### 7. Identify Rare DNS Queries
- Detect low-frequency DNS queries that may indicate domain generation algorithms (DGA).

```spl
index=dns_index sourcetype=dns_logs
| stats count by query
| where count < 5
```

### 8. Investigate Known Malicious Domains
- Search DNS logs for known malicious domains using threat intelligence references such as VirusTotal.

```spl
index=dns_index sourcetype=dns_logs query="maliciousdomain.com"
```

## Conclusion
Analyzing DNS log files using Splunk SIEM enables security analysts to detect abnormal network behavior and investigate potential threats effectively. Through DNS log ingestion, statistical analysis, and anomaly detection, this project demonstrates how DNS monitoring can strengthen an organization’s overall security posture.

These steps can be adapted or expanded based on specific environments, datasets, or threat-hunting objectives.
