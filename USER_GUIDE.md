# WAF Security Console - User Guide

Welcome to the **WAF Security Console**! This dashboard provides a real-time, comprehensive interface for monitoring, analyzing, and responding to Web Application Firewall (WAF) events. 

This guide will walk you through the key features and how to effectively use the console to secure your infrastructure.

---

## 1. Dashboard Overview

The top section of your dashboard provides a high-level view of your current security posture:
- **Total Requests / Blocked / Passed**: See at a glance how much traffic is being analyzed and what percentage is being intercepted.
- **Threat Index**: A dynamic, composite score (0-100) representing your real-time risk level based on volume, severity, spread, and velocity of attacks.
- **Sparkline Trend**: A 24-hour visual trend of your threat index to quickly identify if an attack is escalating or subsiding.

### Auto-Refresh & Live Data
By default, the dashboard fetches new data every **10 seconds**. You can pause this using the **Pause** button in the top right corner. You can also manually refresh the data at any time by clicking the **Refresh** button.

---

## 2. Actionable Insights & 1-Click Mitigation

The **Actionable Insights** panel is your automated security analyst. It groups related events and identifies complex attack patterns such as:
- **Brute Force Attacks**
- **Privilege Escalation Attempts**
- **New Attack Patterns**
- **Bot Campaigns**

### Taking Action
For each insight, you can instantly generate mitigation rules. Click on any of the action buttons (e.g., **Block IPs**, **Whitelist Path**, **Create Rule**). 

1. A modal will appear with the exact configuration code needed to mitigate the threat.
2. Use the language switcher at the top of the modal to choose your environment (**Nginx**, **Apache**, **ModSecurity**, or **iptables**).
3. Click **Copy** to grab the code and paste it into your server configuration.
4. Click **Mark Resolved** to dismiss the insight.

---

## 3. Threat Intelligence & Analytics

### Interactive Charts
- **Event Trend**: A timeline of events to visualize traffic spikes.
- **Top Triggered Rules & Attacked URLs**: Understand exactly *how* attackers are trying to breach your system and *what* they are targeting.
- **Traffic Classification**: A breakdown of your traffic between Humans, Verified Bots, AI Agents, and Malicious Bots.

### Geolocation Intelligence
The **Interactive Map** plots the physical origin of incoming requests.
- **Markers View**: Shows clustered IPs. Red indicates blocked requests, blue indicates passed requests. Hover over a marker to see specific IP and country details.
- **Heatmap View**: Visualizes high-density areas of attack origins.
- **Attack Lines**: Draws lines from the origin IP to your server location.

---

## 4. Advanced Filtering & Search

Click the **Advanced Filters** button (the slider icon) in the top right to open the filter drawer. You can slice and dice your data to find exactly what you are looking for:

- **Time Range**: View data from the last 1 hour up to the last 30 days.
- **Server**: Filter by Nginx or Apache.
- **Severity & Status**: Isolate `CRITICAL` events or filter by HTTP response codes (e.g., 403 Forbidden).
- **Targeted Search**: Search by specific IP addresses, Rule IDs, or free-text search queries.

*Note: Filters update the URL automatically, so you can bookmark or share specific views with your team.*

---

## 5. Event Timelines & Log Management

### Recent Events
The timeline provides a chronological feed of all triggered WAF rules. 
- Click on any event row to open a **Detailed View** containing the full request line, User-Agent, bot analysis scores, and the raw JSON payload.
- Use the **Show More** button at the bottom to load older events.

### Access & Error Logs
Raw server logs are presented in clean, scrollable tables at the bottom of the dashboard. 
- **Access Logs**: Monitor raw HTTP requests, status codes, and response sizes.
- **Error Logs**: View underlying server errors and backend application faults.

---

## 6. Exporting Data

If you need to share data with stakeholders or perform external analysis (e.g., in Excel or a SIEM tool), simply click the **Export CSV** button in the top right. 
This will download all currently filtered ModSecurity events into a structured CSV file.

---

### Need Help?
Ensure your backend Python environment (`app.py`, `config.py`) is running and connected to your Supabase instance, and that your WAF log shipper (`log-shipper@apache.service`) is actively ingesting events. Check the **System Health** indicator in the top right — if it's green, your database connection and latency are optimal!
