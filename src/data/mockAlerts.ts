import { AlertPlaybook, AlertCategory } from "@/types/alert";

export const mockAlerts: AlertPlaybook[] = [
  // --- 1. Authentication & Access Alerts ---
  {
    id: 'brute-force',
    name: 'Brute Force Attack Detected',
    category: 'Authentication',
    description: 'A high volume of failed login attempts targeting a single or multiple accounts over a short period, indicating an automated credential guessing attempt.',
    causes: [
      'Weak passwords being targeted.',
      'Automated scripts or bots attempting credential stuffing.',
      'Misconfigured rate limiting or account lockout policies.',
    ],
    actions: [
      'Step 1: **Verify the Alert.** Confirm the volume and rate of failed logins in the SIEM/Log Analytics tool.',
      'Step 2: **Identify Targets.** Determine the source IP address(es) and the specific user account(s) being targeted.',
      'Step 3: **Check for Success.** Search logs immediately to see if any login attempts from the source IP were successful during the attack window.',
      'Step 4: **Containment (Source).** If the source IP is external and malicious, block it temporarily at the perimeter firewall or WAF.',
      'Step 5: **Containment (Account).** If a specific user account was successfully compromised, immediately disable or suspend the account.',
      'Step 6: **Mitigation.** Force a password reset for all targeted user accounts, successful or not, and enforce Multi-Factor Authentication (MFA).',
      'Step 7: **Post-Incident Review.** Review authentication logs for signs of lateral movement or resource access by the compromised account (if applicable).',
    ],
    queries: [
      { tool: 'Splunk', query: 'index=auth sourcetype=login status=failure | stats count by src_ip, user | where count > 50 | sort -count' },
      { tool: 'Wazuh', query: 'rule.groups:authentication_failure AND srcip != "internal_network" | group by srcip, user' },
    ],
    tools: ['SIEM/Log Analytics', 'Firewall/WAF', 'Identity Provider (IdP) Management Console'],
    escalation: 'Escalate to Incident Response Team (IRT) if successful login is confirmed, or if the attack source cannot be blocked and persists.',
  },
  {
    id: 'successful-login-new-location',
    name: 'Successful Login from New Location',
    category: 'Authentication',
    description: 'A user successfully logged in from a geographic location or network segment never before seen for that user, potentially indicating a compromised account.',
    causes: [
      'Compromised credentials used by an attacker.',
      'Legitimate user traveling without prior notification (False Positive).',
      'Use of a new VPN or proxy service.',
    ],
    actions: [
      'Step 1: **Contact User.** Immediately contact the user via an out-of-band method (phone call, internal chat) to verify the login activity.',
      'Step 2: **Review Login Details.** Check the login time, source IP, device type, and authentication method used.',
      'Step 3: **Containment (If Unverified).** If the user cannot be reached or denies the activity, immediately suspend the account and invalidate all active sessions.',
      'Step 4: **Check for Post-Login Activity.** Review logs for immediate actions taken after login (e.g., mailbox rule changes, data access, new cloud resource creation).',
      'Step 5: **Remediation.** If confirmed malicious, force a password reset and enforce MFA. If legitimate, update the user baseline.',
    ],
    queries: [
      { tool: 'Azure AD', query: 'SigninLogs | where ResultType == 0 and Location != "Known Locations" | summarize count() by UserPrincipalName, Location' },
    ],
    tools: ['Identity Provider Logs', 'HR/Travel Records', 'Communication Tools (Phone/Chat)'],
    escalation: 'Escalate if the login is confirmed malicious and subsequent unauthorized activity (Step 4) is detected.',
  },
  {
    id: 'privilege-escalation',
    name: 'Privilege Escalation Detected',
    category: 'Authentication',
    description: 'A standard user account successfully gaining elevated privileges (e.g., root or administrator) on a local system or cloud environment.',
    causes: [
      'Exploitation of a known OS or application vulnerability.',
      'Misconfigured service permissions.',
      'Abuse of weak service account credentials.',
    ],
    actions: [
      'Step 1: **Isolate Host/Account.** Immediately isolate the affected endpoint from the network or suspend the compromised cloud role/account.',
      'Step 2: **Identify Method.** Determine the method used for privilege escalation (e.g., specific exploit, misconfiguration abuse).',
      'Step 3: **Capture Snapshot.** Take a memory and disk image snapshot of the compromised system for deep forensic analysis.',
      'Step 4: **Identify Persistence.** Check for new user accounts, scheduled tasks, or modified registry keys created by the attacker.',
      'Step 5: **Patch/Remediate.** Apply the necessary patch or correct the misconfiguration that allowed the escalation.',
      'Step 6: **Re-image.** Re-image the host or redeploy the cloud resource to ensure complete removal of malicious components.',
    ],
    queries: [
      { tool: 'EDR', query: 'Process: Create AND parent_process="low_privilege_user" AND new_process="system_shell"' },
      { tool: 'Windows Event Log', query: 'EventID=4672 (Special Privileges Assigned)' },
    ],
    tools: ['EDR', 'Forensic Toolkit', 'Vulnerability Scanner', 'Cloud IAM Logs'],
    escalation: 'Escalate if the escalation leads to lateral movement or compromise of critical domain/cloud accounts.',
  },

  // --- 2. Network & Firewall Alerts ---
  {
    id: 'suspicious-network-traffic',
    name: 'Suspicious Outbound Network Traffic (C2)',
    category: 'Network',
    description: 'Unusual high volume or connections from an internal host to known malicious IPs or non-standard ports, often indicating Command and Control (C2) activity or data exfiltration.',
    causes: [
      'Internal host is compromised and communicating with an external C2 server.',
      'Data exfiltration attempt using non-standard protocols.',
      'Misconfigured application or service generating false positives.',
    ],
    actions: [
      'Step 1: **Validate Destination.** Check the destination IP/domain against threat intelligence feeds (e.g., VirusTotal, AlienVault) to confirm malicious intent.',
      'Step 2: **Identify Source.** Determine the source host (IP and hostname) and the specific process generating the traffic.',
      'Step 3: **Containment.** Immediately isolate the source host from the network using EDR or NAC.',
      'Step 4: **Perimeter Block.** Block the destination IP/domain at the perimeter firewall/proxy to prevent further communication.',
      'Step 5: **Forensic Analysis.** Perform a deep forensic analysis on the isolated host to identify the malware, persistence mechanisms, and scope of compromise.',
      'Step 6: **Review PCAPs.** Analyze packet captures (PCAPs) if available to understand the data being transmitted and the communication protocol.',
    ],
    queries: [
      { tool: 'SIEM/Log Analytics', query: 'index=network traffic_outbound | where dest_ip IN (malicious_ip_list) | top limit=10 src_ip' },
      { tool: 'Firewall Logs', query: 'search action=allowed AND dest_port=4444 AND src_ip="[INTERNAL_HOST_IP]"' },
    ],
    tools: ['Network Monitoring Tools (NMS)', 'Firewall Logs', 'IDS/IPS', 'EDR'],
    escalation: 'Escalate if data exfiltration is confirmed, or if the traffic is coming from a critical server.',
  },
  {
    id: 'port-scan-detected',
    name: 'Port Scan Detected',
    category: 'Network',
    description: 'A single source IP attempting to connect to multiple ports or hosts in a short time, indicating reconnaissance activity.',
    causes: [
      'External attacker mapping the network perimeter.',
      'Internal compromised host performing lateral reconnaissance.',
      'Legitimate vulnerability scanner or network monitoring tool (False Positive).',
    ],
    actions: [
      'Step 1: **Identify Source.** Determine the source IP address and check if it belongs to a known scanner or internal asset.',
      'Step 2: **Verify Intent.** If external, check threat intelligence feeds. If internal, check the host status via EDR.',
      'Step 3: **Containment (External).** If confirmed malicious and external, block the source IP at the firewall/IPS immediately.',
      'Step 4: **Containment (Internal).** If internal, isolate the host and proceed with the Malware/Compromise playbook.',
      'Step 5: **Review Targets.** Check the logs of the targeted hosts/ports to see if any connections were successful or if any vulnerabilities were exploited.',
    ],
    queries: [
      { tool: 'IDS/IPS', query: 'alert_name="Port Scan" | group by src_ip, dest_ip' },
      { tool: 'NetFlow', query: 'flow_count > 100 AND dest_port_count > 20 | group by src_ip' },
    ],
    tools: ['IDS/IPS', 'Firewall', 'NetFlow Analyzer'],
    escalation: 'Escalate if the scan is followed immediately by an exploit attempt or if the source is a critical internal asset.',
  },

  // --- 3. Endpoint & Malware Alerts ---
  {
    id: 'malware-detected',
    name: 'Malware Detected on Host',
    category: 'Endpoint',
    description: 'Antivirus or EDR solution detected a known malicious file or process on an endpoint.',
    causes: [
      'User downloaded a malicious file.',
      'Exploit kit delivered payload.',
      'Remnant of a previous infection.',
    ],
    actions: [
      'Step 1: **Verify EDR Action.** Confirm that the EDR/AV tool successfully quarantined or blocked the threat.',
      'Step 2: **Isolate Host.** If the threat was not fully contained, immediately isolate the affected endpoint from the network.',
      'Step 3: **Full Scan.** Initiate a full, deep scan on the isolated host to check for persistence mechanisms or secondary payloads.',
      'Step 4: **IOC Search.** Extract the file hash and search the SIEM/EDR across the entire environment for other instances of the IOC.',
      'Step 5: **Remediation.** If clean, restore the host to the network. If persistent infection is found, proceed to re-image the machine.',
    ],
    queries: [
      { tool: 'EDR', query: 'event_type="Malware_Detection" AND action="Quarantine_Failed"' },
      { tool: 'SIEM', query: 'file_hash="[MALICIOUS_HASH]"' },
    ],
    tools: ['EDR Console', 'SIEM', 'Forensic Tools'],
    escalation: 'Escalate if the malware is confirmed to be ransomware or if the IOC is found on multiple critical systems.',
  },
  {
    id: 'ransomware-behavior',
    name: 'Ransomware Behavior Detected',
    category: 'Endpoint',
    description: 'Detection of suspicious file encryption, mass file renaming, or deletion activity characteristic of ransomware.',
    causes: [
      'Successful execution of a ransomware payload.',
      'User opening a malicious document or clicking a link.',
    ],
    actions: [
      'Step 1: **Immediate Isolation.** Immediately isolate the affected host(s) from the network. Do NOT shut down the machine.',
      'Step 2: **Identify Scope.** Determine the initial point of infection and how many files/shares have been accessed or encrypted.',
      'Step 3: **Process Termination.** Use EDR to terminate the malicious encryption process across all affected hosts.',
      'Step 4: **IOC Extraction.** Extract file hashes, process names, and any ransom notes for threat intelligence.',
      'Step 5: **Engage IR.** Notify the Incident Response Team and management immediately due to the high impact.',
      'Step 6: **Backup Verification.** Verify the integrity and availability of recent backups for recovery.',
    ],
    queries: [
      { tool: 'EDR', query: 'event_type="File_Modification" AND file_extension IN (".lock", ".encrypted") | top hostname' },
    ],
    tools: ['EDR Console', 'Backup Management System', 'Forensic Toolkit'],
    escalation: 'CRITICAL. Engage Crisis Management Team immediately.',
  },
  {
    id: 'lateral-movement',
    name: 'Lateral Movement via PsExec or RDP',
    category: 'Endpoint',
    description: 'Detection of remote execution tools (like PsExec) or unusual RDP connections originating from a non-admin workstation to other internal hosts.',
    causes: [
      'Attacker using compromised credentials to move across the network.',
      'Misconfigured automation script (False Positive).',
    ],
    actions: [
      'Step 1: **Identify Source and Destination.** Determine the source host (compromised) and the destination host(s) being targeted.',
      'Step 2: **Isolate Source.** Immediately isolate the source host from the network.',
      'Step 3: **Check Destination.** Review logs on the destination host(s) for successful authentication and subsequent command execution.',
      'Step 4: **Identify Credentials.** Determine which user account was used for the lateral movement and immediately reset its password.',
      'Step 5: **Forensic Analysis.** Perform a deep dive on the source host to find the initial compromise vector and persistence mechanisms.',
    ],
    queries: [
      { tool: 'EDR', query: 'process_name="psexec.exe" OR process_name="mstsc.exe" AND src_ip="[NON_ADMIN_WORKSTATION]"' },
      { tool: 'Windows Event Log', query: 'EventID=4624 AND LogonType=10 (RemoteInteractive)' },
    ],
    tools: ['EDR', 'Active Directory Logs', 'SIEM'],
    escalation: 'Escalate immediately, as this indicates a confirmed breach and active attacker presence.',
  },

  // --- 4. Email & Phishing Alerts (Data Security) ---
  {
    id: 'phishing-email-detected',
    name: 'Phishing Email Detected',
    category: 'Data Security',
    description: 'An email flagged by security tools or reported by a user containing malicious links, attachments, or impersonation attempts.',
    causes: [
      'User clicked a malicious link or opened an attachment.',
      'Lack of robust email filtering allowed the email through.',
      'Targeted spear-phishing campaign.',
    ],
    actions: [
      'Step 1: **Isolate and Analyze.** Forward the suspicious email to the security mailbox for analysis. Do NOT click links or open attachments.',
      'Step 2: **Analyze Headers.** Examine email headers to determine the true origin and authenticity.',
      'Step 3: **Containment (Email).** Use the Email Security Gateway (ESG) to search for and immediately remove the email from all user inboxes.',
      'Step 4: **Containment (Endpoint).** If an attachment was opened or a link was clicked, isolate the affected user endpoint.',
      'Step 5: **Scan and Remediate.** Run a full scan on the isolated endpoint. If malware is found, follow the Malware playbook.',
      'Step 6: **Block Indicators.** Add malicious sender addresses, domains, and file hashes to perimeter block lists.',
    ],
    queries: [
      { tool: 'Microsoft Defender', query: 'EmailEvents | where ThreatTypes contains "Phish" and DeliveryAction == "Delivered"' },
      { tool: 'ESG', query: 'search subject="Invoice Q3" AND attachment_hash="[MALICIOUS_HASH]"' },
    ],
    tools: ['Email Security Gateway (ESG)', 'Sandbox Analysis Tool', 'EDR'],
    escalation: 'Escalate if credentials were entered, malware infection is confirmed, or if the campaign is widespread.',
  },
  {
    id: 'compromised-mailbox',
    name: 'Compromised Mailbox Detected',
    category: 'Data Security',
    description: 'Alert triggered by unusual mailbox activity, such as creation of forwarding rules, mass deletion, or sending spam/phishing emails.',
    causes: [
      'Stolen credentials used to access the mailbox.',
      'Session token theft.',
      'Vulnerability exploitation (e.g., Exchange server).',
    ],
    actions: [
      'Step 1: **Immediate Containment.** Immediately suspend the user account and invalidate all active sessions (force logoff).',
      'Step 2: **Identify Compromise Time.** Determine the exact time the attacker gained access and the source IP.',
      'Step 3: **Review Mailbox Changes.** Check for newly created forwarding rules, delegated permissions, or deleted items.',
      'Step 4: **Scope of Attack.** Review sent items to see if the attacker sent phishing emails internally or externally. Notify affected parties.',
      'Step 5: **Remediation.** Force a password reset and ensure MFA is enabled. Remove any malicious forwarding rules or permissions.',
      'Step 6: **User Interview.** Interview the user to understand how credentials might have been compromised.',
    ],
    queries: [
      { tool: 'Exchange Logs', query: 'operation="Set-Mailbox" AND parameter="ForwardingAddress"' },
      { tool: 'SIEM', query: 'event_type="Email_Sent" AND recipient_count > 500 AND sender="[USER]"' },
    ],
    tools: ['Email Audit Logs', 'Identity Provider Console', 'DLP/CASB'],
    escalation: 'Escalate if the mailbox was used to send sensitive data externally or if it was a high-privilege account.',
  },
  {
    id: 'data-download-sensitive',
    name: 'Data Download from Sensitive Folder',
    category: 'Data Security',
    description: 'A user or service account initiated a large download or copy operation from a folder marked as highly confidential.',
    causes: [
      'Insider threat (malicious or negligent).',
      'Compromised account used for data exfiltration.',
      'Legitimate business need (False Positive).',
    ],
    actions: [
      'Step 1: **Identify User/Account.** Determine the identity of the user or service account performing the action.',
      'Step 2: **Containment.** If the account is suspicious or unverified, temporarily suspend its access to the sensitive data source.',
      'Step 3: **Contact User.** Contact the user/owner out-of-band to verify the legitimacy and necessity of the download.',
      'Step 4: **Check Destination.** Determine where the data was downloaded (e.g., local machine, external cloud storage, USB).',
      'Step 5: **DLP Review.** Review DLP logs for any attempts to transfer the data outside the network perimeter.',
      'Step 6: **Forensic Review.** If malicious, initiate a forensic review of the endpoint/cloud storage used for the download.',
    ],
    queries: [
      { tool: 'DLP', query: 'event_type="File_Transfer" AND sensitivity="High" AND volume > 1GB' },
      { tool: 'File Server Logs', query: 'operation="Read" AND path="[SENSITIVE_PATH]" | group by user' },
    ],
    tools: ['DLP System', 'File Audit Logs', 'EDR'],
    escalation: 'Escalate immediately if the data is confirmed to be PII/IP and was transferred to an external, unauthorized location.',
  },

  // --- 5. Cloud Security Alerts ---
  {
    id: 'new-root-user-login',
    name: 'New Root User Login',
    category: 'Cloud',
    description: 'The primary cloud root/owner account has logged in, which should be extremely rare and only used for specific administrative tasks.',
    causes: [
      'Compromise of the root account credentials.',
      'Unauthorized administrative action requiring root privileges.',
      'Legitimate, but poorly governed, administrative task.',
    ],
    actions: [
      'Step 1: **Immediate Verification.** Determine who initiated the login and why. Contact the designated root account owner immediately.',
      'Step 2: **Review Activity.** Review all actions taken by the root account immediately after login (e.g., IAM changes, resource deletion, key creation).',
      'Step 3: **Containment.** If unauthorized, immediately change the root password and rotate the access keys. Ensure MFA is enabled and enforced.',
      'Step 4: **Lockdown.** If possible, restrict root account access to a specific jump box or IP range.',
      'Step 5: **Audit.** Perform a full audit of IAM policies and resource configurations for unauthorized changes.',
    ],
    queries: [
      { tool: 'AWS CloudTrail', query: 'userIdentity.type="Root" AND eventName="ConsoleLogin"' },
      { tool: 'Azure Activity Log', query: 'operationName="Microsoft.Security/securityPricings/write" AND caller="RootUser"' },
    ],
    tools: ['Cloud Provider Console (IAM)', 'CloudTrail/Activity Logs'],
    escalation: 'CRITICAL. Escalate immediately. Root account compromise is the highest risk event in the cloud.',
  },
  {
    id: 'public-s3-bucket-exposure',
    name: 'Public S3 Bucket Exposure',
    category: 'Cloud',
    description: 'Detection of a cloud storage bucket configured for public read or write access, potentially exposing sensitive data.',
    causes: [
      'Misconfiguration during deployment (e.g., "Everyone" access granted).',
      'Automated script error or manual oversight.',
      'Lack of continuous cloud security posture management (CSPM).',
    ],
    actions: [
      'Step 1: **Verify Public Access.** Immediately confirm the public access status of the identified bucket using the cloud provider console.',
      'Step 2: **Containment.** Change the bucket policy immediately to restrict access to internal users only (or specific roles/IPs).',
      'Step 3: **Scope Assessment.** Determine what data was stored in the bucket and if it contained sensitive information (PII, credentials).',
      'Step 4: **Audit Logs.** Review cloud access logs for the bucket to identify any unauthorized external access or downloads during the exposure window.',
      'Step 5: **Remediation.** If sensitive data was exposed, follow data breach notification procedures.',
      'Step 6: **Preventative Action.** Update Infrastructure as Code (IaC) templates and enforce CSPM policies to prevent recurrence.',
    ],
    queries: [
      { tool: 'AWS CloudTrail', query: 'eventName=PutBucketAcl AND requestParameters.acl="public-read"' },
      { tool: 'CSPM Tool', query: 'search resource_type="s3_bucket" AND public_access="true"' },
    ],
    tools: ['Cloud Provider Console (IAM/Storage)', 'CSPM Tool', 'Cloud Access Logs'],
    escalation: 'Escalate immediately if PII, financial data, or critical intellectual property was exposed.',
  },
  {
    id: 'iam-policy-change',
    name: 'IAM Policy Change',
    category: 'Cloud',
    description: 'A change was made to a critical Identity and Access Management (IAM) policy, potentially granting excessive permissions.',
    causes: [
      'Malicious actor attempting to gain persistence or broader access.',
      'Legitimate deployment or maintenance activity (False Positive).',
    ],
    actions: [
      'Step 1: **Identify Change.** Determine the exact policy that was modified, the user/role that made the change, and the time.',
      'Step 2: **Verify Legitimacy.** Check change management records or contact the user/team responsible for the change.',
      'Step 3: **Revert Change.** If unauthorized, immediately revert the IAM policy to its previous secure state.',
      'Step 4: **Containment.** If malicious, suspend the user/role that made the change and investigate for compromise.',
      'Step 5: **Audit Permissions.** Review the new permissions granted by the policy to assess the potential blast radius.',
    ],
    queries: [
      { tool: 'AWS CloudTrail', query: 'eventName IN ("AttachUserPolicy", "PutRolePolicy")' },
      { tool: 'GCP Audit Logs', query: 'methodName="SetIamPolicy"' },
    ],
    tools: ['Cloud IAM Console', 'Cloud Audit Logs', 'Change Management System'],
    escalation: 'Escalate if the policy change grants administrative access or allows resource deletion.',
  },

  // --- 6. Other / SIEM & Threat Intelligence Alerts ---
  {
    id: 'ioc-match',
    name: 'IOC Match from Threat Feed',
    category: 'Other',
    description: 'An internal system communicated with an IP address, domain, or used a file hash identified as malicious by external threat intelligence feeds.',
    causes: [
      'Compromised internal host communicating with a known C2 server.',
      'Internal user accessing a known malicious website.',
      'Outdated threat feed leading to a False Positive.',
    ],
    actions: [
      'Step 1: **Validate IOC.** Confirm the IOC (IP/Domain/Hash) is still considered malicious and relevant to the environment.',
      'Step 2: **Identify Source.** Determine the internal host (IP and hostname) that matched the IOC.',
      'Step 3: **Containment.** Immediately isolate the source host from the network.',
      'Step 4: **Perimeter Block.** Block the malicious external IOC at the firewall/proxy.',
      'Step 5: **Forensic Analysis.** Perform a deep forensic analysis on the isolated host to determine the nature of the compromise and persistence.',
    ],
    queries: [
      { tool: 'SIEM', query: 'index=network dest_ip="[MALICIOUS_IP]" OR file_hash="[MALICIOUS_HASH]"' },
    ],
    tools: ['Threat Intelligence Platform', 'SIEM', 'EDR', 'Firewall'],
    escalation: 'Escalate if the IOC match involves a critical server or if the communication was successful and persistent.',
  },
  {
    id: 'log-source-stopped',
    name: 'Log Source Stopped Sending Data',
    category: 'Other',
    description: 'The SIEM or log aggregator has not received logs from a critical source (e.g., Domain Controller, Firewall) for a defined period.',
    causes: [
      'Log forwarder service failure on the source machine.',
      'Network connectivity issue between source and SIEM.',
      'Malicious actor attempting to blind the security team (Attack on Logging).',
    ],
    actions: [
      'Step 1: **Verify Connectivity.** Check network connectivity (ping, traceroute) between the log source and the SIEM collector.',
      'Step 2: **Check Service Status.** Log into the source machine and verify that the log forwarding service is running.',
      'Step 3: **Review Source Logs.** Check the local event logs on the source machine for errors related to logging or security tool tampering.',
      'Step 4: **Restore Service.** Restart the log forwarding service or fix the network path.',
      'Step 5: **Backfill Logs.** If logs were missed, attempt to backfill the missing data into the SIEM for continuity.',
      'Step 6: **Investigate Tampering.** If tampering is suspected (Step 3), treat the source machine as compromised and follow the Malware playbook.',
    ],
    queries: [
      { tool: 'SIEM Health', query: 'index=_internal sourcetype=health_check component="Log_Source" status="Down"' },
    ],
    tools: ['SIEM Health Dashboard', 'System Administration Tools (RDP/SSH)', 'Network Monitoring'],
    escalation: 'Escalate if the log source is critical (e.g., Domain Controller) and the outage exceeds 30 minutes, or if tampering is suspected.',
  },
];

export const categories: AlertCategory[] = ['Authentication', 'Network', 'Endpoint', 'Data Security', 'Cloud', 'Other'];