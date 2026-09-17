# Azure-Sentinel-Security-Analytics-Visualization

## Project Overview

This project demonstrates the implementation of a Microsoft Sentinel security visualization focused on inbound authentication activity using **DeviceLogonEvents**. By filtering, enriching, and aggregating remote authentication telemetry, this project transforms raw endpoint authentication data into an interactive **KQL (Kusto Query Language) Workbook**.

The primary objective was to build a geographic visualization that identifies where external authentication activity originates and distinguishes successful authentication from failed attempts.

---

## Core Visualization & Scenario Implemented

### 1. Inbound Authentication Origins

* **Log Source:** `DeviceLogonEvents`
* **Objective:** Maps public external source IP addresses (`RemoteIP`) associated with `Network` and `RemoteInteractive` logons to identify geographic authentication patterns.
* **Business Value:** Provides analysts with geographic and source-level context for investigating unusual successful authentications, high-volume authentication sources, and repeated authentication failures.

#### Visual Dashboard
### Inbound Authentication Origins — DeviceLogonEvents
<img width="1589" height="470" alt="image" src="https://github.com/user-attachments/assets/04473d08-41bf-493f-80b1-6d88074f51ff" />

#### The KQL Query

```kusto
DeviceLogonEvents
| where Timestamp {TimeRange}
| where RemoteIPType == "Public"
| where isnotempty(RemoteIP)
| where LogonType in ("Network", "RemoteInteractive")
| extend geo = geo_info_from_ip_address(RemoteIP)
| extend Latitude  = toreal(geo.latitude),
         Longitude = toreal(geo.longitude),
         Country   = tostring(geo.country),
         City      = tostring(geo.city)
| where isnotempty(Latitude) and isnotempty(Longitude)
| summarize Attempts        = count(),
            Successes       = countif(ActionType == "LogonSuccess"),
            Failures        = countif(ActionType == "LogonFailed"),
            TargetedDevices = dcount(DeviceName),
            Accounts        = make_set(AccountName, 25)
         by RemoteIP, Country, City, Latitude, Longitude
| extend MapLabel = strcat(RemoteIP, " (", Country, ") — ", Successes, " success / ", Attempts, " total")
| project Latitude, Longitude, MapLabel, Attempts, Successes, Failures, TargetedDevices, RemoteIP, Country, City, Accounts
| order by Successes desc, Attempts desc
```

### 📊 Dashboard Analysis & Key Findings

### 🔍 KQL Query Breakdown

* **Filters External Activity:** Uses `RemoteIPType == "Public"` to focus on authentication originating from publicly routable IP addresses.
* **Focuses on Remote Authentication:** Filters `LogonType` for `Network` and `RemoteInteractive` activity.
* **Enriches Source IPs:** Uses the native `geo_info_from_ip_address()` function to translate source IP addresses into geographic information.
* **Aggregates Authentication Activity:** Calculates total attempts, successful logons, failed logons, targeted devices, and associated accounts for each source IP.

### 🗺️ Map Visualization & Legend Key

* **Authentication Origins:** Bubbles represent the approximate geographic location of external source IP addresses generating remote authentication activity.
* **Bubble Size (Volume):** Larger bubbles represent a higher number of authentication attempts.
* **Authentication Success:** The legend tracks the number of successful logons associated with each source.
* **Color Coding:** The map uses a green-to-red heatmap based on authentication attempt volume.

### ⚠️ Key Security Anomalies Detected

* **Unexpected Successful Authentication:** A successful `LogonSuccess` originating from a country or region where the organization does not normally operate can represent a potentially significant authentication anomaly.
* **High-Volume Sources:** Large bubbles can identify source IPs generating unusually high volumes of authentication attempts and may warrant investigation for brute-force, password-spraying, or other automated activity.
* **Repeated Authentication Failures:** Sources producing large numbers of `LogonFailed` events can indicate repeated credential attempts against exposed systems.
* **Multiple Targeted Devices or Accounts:** The `TargetedDevices` and `Accounts` fields provide additional context for determining whether a source is concentrating activity against multiple systems or identities.

> Geographic anomalies are investigative signals rather than standalone proof of malicious activity. VPNs, proxies, cloud infrastructure, shared networks, and approximate IP geolocation can produce unexpected locations.

---

### 2. Source IP Authentication Breakdown

* **Log Source:** `DeviceLogonEvents`
* **Objective:** Provides a source-level breakdown of successful and failed authentication activity.
* **Business Value:** Allows analysts to move from geographic observations to individual source IPs and examine authentication volume, targeted devices, and associated accounts.

#### The KQL Query

```kusto
DeviceLogonEvents
| where Timestamp {TimeRange}
| where RemoteIPType == "Public" and isnotempty(RemoteIP)
| where LogonType in ("Network", "RemoteInteractive")
| extend geo = geo_info_from_ip_address(RemoteIP)
| summarize Attempts  = count(),
            Successes = countif(ActionType == "LogonSuccess"),
            Failures  = countif(ActionType == "LogonFailed"),
            Devices   = dcount(DeviceName),
            Accounts  = make_set(AccountName, 25)
         by RemoteIP,
            Country = tostring(geo.country),
            City    = tostring(geo.city)
| order by Successes desc, Attempts desc
```

### 📊 Dashboard Analysis & Key Findings

## 🔍 KQL Query Breakdown

* **Filters Public Sources:** Limits the analysis to authentication events associated with public source IP addresses.
* **Focuses on Remote Logons:** Includes `Network` and `RemoteInteractive` authentication types.
* **Enriches Geographic Context:** Uses `geo_info_from_ip_address()` to associate source IPs with countries and cities.
* **Ranks Authentication Sources:** Summarizes attempts, successes, failures, devices, and accounts, then orders sources by successful authentication activity.

---

## 🗺️ Source IP Analysis

* **Source IP:** Identifies the external address responsible for the authentication activity.
* **Authentication Volume:** `Attempts` represents the total number of authentication events from the source.
* **Success vs. Failure:** `Successes` and `Failures` allow analysts to compare authentication outcomes.
* **Targeted Devices:** `Devices` identifies how many devices were associated with the source.
* **Associated Accounts:** `Accounts` provides the identities observed in the authentication activity.

---

## ⚠️ Key Security Anomalies Detected

* **Successful Authentication From an Unusual Region:** Successful activity from an unexpected geographic location should be correlated with user, device, and identity context.
* **High-Volume Authentication:** Large numbers of attempts from a single source may indicate automated authentication activity.
* **Multiple Account Targets:** A source interacting with numerous accounts may warrant investigation for password spraying or credential attacks.
* **Multiple Device Targets:** A source reaching multiple devices can provide additional context when determining the scope of an authentication campaign.

---

**NOTE:** The source data for this visualization uses the `DeviceLogonEvents` table and required a different approach from identity-based `SigninLogs` data. The workbook uses the native `geo_info_from_ip_address()` function rather than the GeoIP watchlist approach used in some other visualizations. This demonstrates how SIEM queries must be adapted to the structure and capabilities of each log source.

---

## Technical Architecture & Workflow

1. **Ingestion:** Authentication telemetry is collected in **Microsoft Sentinel / Log Analytics** through the `DeviceLogonEvents` data source.
2. **Data Extraction:** Used **Kusto Query Language (KQL)** to filter public remote authentication activity, enrich source IPs with geographic information, and aggregate authentication results.
3. **Visualization:** Configured a **Microsoft Sentinel Workbook** using geographic map and table visualizations to transform raw authentication telemetry into an analyst-friendly security dashboard.

---

## Skills Demonstrated

* **Microsoft Sentinel:** Building and configuring security workbooks and visualizations.
* **KQL & Data Analysis:** Filtering, aggregating, and transforming endpoint authentication telemetry.
* **Security Data Enrichment:** Using `geo_info_from_ip_address()` to add geographic context to source IP addresses.
* **Threat Hunting & Investigation:** Identifying unusual authentication patterns and high-volume sources.
* **Data Visualization:** Translating raw authentication events into geographic and source-level security dashboards.

