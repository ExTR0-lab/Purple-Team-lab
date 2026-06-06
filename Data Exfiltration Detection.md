Data exfiltration is one of the most serious cybersecurity threats faced by organizations today. It occurs when an attacker transfers sensitive information from an internal system to an external destination without authorization. One technique commonly used by attackers is DNS tunneling, where encoded data is hidden inside DNS queries to bypass traditional security controls.

In this project, I used Splunk Enterprise to analyze DNS logs and identify potential indicators of data exfiltration. The goal was to detect abnormal DNS behavior by examining query patterns, identifying suspicious domains, and investigating unusually long DNS queries that may contain encoded data.

The dataset used for this analysis was stored in the data_exfil index, and DNS events were filtered using the dns_logs sourcetype.

---

# Identifying Source IPs Generating DNS Traffic

The first step in the investigation was to identify which internal hosts were generating DNS queries. Understanding which systems are actively making DNS requests helps analysts determine where suspicious activity might be originating from.

![1](https://github.com/user-attachments/assets/54542a03-487e-445f-8ce3-3d750014d7f3)

Analysis

The results showed several internal IP addresses generating DNS traffic, including:

192.168.1.104,192.168.1.101,192.168.1.105,192.168.1.103,192.168.1.102

Hosts generating an unusually high number of DNS requests may indicate abnormal behavior and should be examined more closely during an investigation.

---

# Identifying Domains Being Queried

After identifying the active hosts, the next step was to analyze which domains were being queried. Attackers performing DNS tunneling often communicate with domains they control in order to receive or transmit encoded data.

![Image](https://github.com/user-attachments/assets/8e407d1b-764b-494b-9a47-0d10f4e3f408)

Analysis

The results showed several domains being queried, such as:

stackoverflow.com,mozilla.org,tamcorp.net

Some of these domains are clearly legitimate, such as Stack Overflow or Mozilla. However, domains like tamcorp.net may require additional investigation if they appear frequently or contain unusual query patterns.

Analyzing DNS query destinations helps security analysts identify suspicious or unknown domains that may be involved in malicious activity.

# Detecting Suspicious Long DNS Queries

One of the common indicators of DNS tunneling is unusually long DNS queries. Attackers often encode data inside subdomains, which makes the query strings much longer than normal DNS requests.

To identify this behavior, I searched for DNS queries longer than 30 characters.

![Image](https://github.com/user-attachments/assets/ac01cd1c-c8c3-4721-a077-405c4e21f2a2)

Analysis

The results revealed several suspicious domain queries, including:

36er95gzqeabe3ymiht.tunnelcorp.net

apj51x7azdeikfa5wjt.tunnelcorp.net

0fvgpds1ybcbma94rq7e.tunnelcorp.net

0g3uxie9b84dzfbg3b12.tunnelcorp.net

These domains contain long, random-looking strings that resemble encoded data. This pattern is commonly associated with DNS tunneling, where attackers split encoded information into multiple DNS requests to exfiltrate data from a compromised system.

---

# Measuring the Scale of Suspicious Activity

After identifying the suspicious queries, the next step was to determine how many such events were present in the dataset.

![Image](https://github.com/user-attachments/assets/7e2b5ccb-43d8-4b7c-b52a-f1cbb7154375)

The query returned: 315 events

Analysis

This means that 315 DNS requests contained unusually long domain queries. Such a pattern strongly suggests possible DNS tunneling behavior and potential data exfiltration activity.

At this stage, a security analyst would typically continue the investigation by identifying:

Which internal host generated the queries

The reputation of the destination domain

Whether the activity represents confirmed data exfiltration

---

# Conclusion

High volumes of DNS queries from specific hosts

Communication with unusual domains

Abnormally long DNS query strings that may contain encoded data

During this investigation, 315 suspicious DNS queries containing encoded subdomains were identified, many associated with the domain tunnelcorp.net. These patterns are consistent with techniques used in DNS tunneling, where attackers hide sensitive information inside DNS requests.

---
