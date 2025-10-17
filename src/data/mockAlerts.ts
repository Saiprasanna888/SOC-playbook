import { AlertPlaybook, AlertCategory } from "@/types/alert";

export const mockAlerts: AlertPlaybook[] = [
  // --- 1. Authentication & Access Alerts (Total: 5) ---
  {
    id: 'brute-force',
    name: 'Brute Force Attack Detected',
    category: 'Authentication & Access',
    description: 'A high volume of failed login attempts targeting a single or multiple accounts over a short period.',
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
    ],
    queries: [
      { tool: 'SIEM', query: 'index=auth status=failure | stats count by src_ip, user | where count > 50 | sort -count' },
    ],
    tools: ['SIEM/Log Analytics', 'Firewall/WAF', 'Identity Provider (IdP) Management Console'],
    escalation: 'Escalate if successful login is confirmed, or if the attack source cannot be blocked and persists.',
  },
  {
    id: 'impossible-travel',
    name: 'Impossible Travel Detected',
    category: 'Authentication & Access',
    description: 'A single user successfully logging in from two geographically distant locations within an impossible time frame, strongly indicating a compromised account.',
    causes: [
      'Stolen credentials used by an attacker in a different region.',
      'VPN usage or proxy hopping (False Positive).',
    ],
    actions: [
      'Step 1: **Immediate Suspension.** Immediately suspend the user account and invalidate all active sessions.',
      'Step 2: **Contact User.** Contact the user via an out-of-band method (phone, internal chat) to verify the recent login activity.',
      'Step 3: **Analyze Login Chain.** Review the full login history for the user, noting IPs, devices, and MFA status for both suspicious logins.',
      'Step 4: **Check for Post-Login Activity.** Review logs for immediate actions taken after the second (malicious) login (e.g., mailbox rule changes, data access).',
      'Step 5: **Remediation.** If confirmed malicious, force a password reset, ensure MFA is enabled, and perform a full endpoint scan on the user\'s primary device.',
    ],
    queries: [
      { tool: 'Cloud Identity Logs', query: 'LoginEvents | where TimeDifference < 1 hour and Distance > 5000 km' },
    ],
    tools: ['Identity Provider Logs', 'Communication Tools', 'EDR'],
    escalation: 'Escalate if the account is high-privilege or if data access/modification occurred after the second login.',
  },
  {
    id: 'suspicious-admin-creation',
    name: 'Suspicious Admin Account Creation',
    category: 'Authentication & Access',
    description: 'A new administrative or highly privileged account was created outside of standard change control procedures.',
    causes: [
      'Compromised administrator account used to create a backdoor account.',
      'Misconfigured automation script.',
    ],
    actions: [
      'Step 1: **Identify Creator.** Determine the user or service account that created the new administrative account.',
      'Step 2: **Verify Change Control.** Check the change management system for an approved ticket corresponding to this creation time.',
      'Step 3: **Containment.** If unauthorized, immediately disable the newly created administrative account.',
      'Step 4: **Investigate Creator.** If the creator account was compromised, immediately suspend it and follow the Compromised Account playbook.',
      'Step 5: **Audit Permissions.** Review the permissions granted to the new account and ensure no other unauthorized changes were made to IAM policies.',
    ],
    queries: [
      { tool: 'AD/IAM Logs', query: 'EventID=4720 AND TargetUserName="*Admin*" AND CallerUserName!="Approved_Admins"' },
    ],
    tools: ['Active Directory/IAM Console', 'Change Management System', 'SIEM'],
    escalation: 'High priority. Escalate immediately if the creator account was compromised.',
  },
  {
    id: 'failed-mfa-login',
    name: 'Failed MFA Login in Cloud Console',
    category: 'Authentication & Access',
    description: 'Multiple failed attempts to satisfy the Multi-Factor Authentication requirement, often following a successful password entry, indicating an MFA bypass attempt (e.g., push bombing).',
    causes: [
      'Attacker possessing valid credentials attempting to bypass MFA.',
      'User error or device malfunction (False Positive).',
      'MFA push bombing attack.',
    ],
    actions: [
      'Step 1: **Identify User and Source.** Determine the user account and the source IP address attempting the login.',
      'Step 2: **Contact User.** Contact the user out-of-band to verify if they are currently attempting to log in and receiving MFA prompts.',
      'Step 3: **Containment.** If unauthorized, immediately block the source IP and temporarily disable the user\'s MFA method (e.g., revoke session tokens).',
      'Step 4: **Review MFA Logs.** Check the MFA provider logs for the type of failure (e.g., denied push, incorrect code).',
      'Step 5: **Remediation.** If confirmed malicious, force a password reset and enroll the user in a stronger MFA method (e.g., FIDO2 key instead of push notification).',
    ],
    queries: [
      { tool: 'Cloud Identity Logs', query: 'LoginEvents | where ResultType == 500121 and FailureReason contains "MFA"' },
    ],
    tools: ['Identity Provider Logs', 'MFA Management Console', 'Communication Tools'],
    escalation: 'Escalate if the targeted user is high-privilege or if the attack persists after initial containment.',
  },
  {
    id: 'successful-login-new-location',
    name: 'Successful Login from New Location',
    category: 'Authentication & Access',
    description: 'A user successfully logged in from a geographic location or network segment never before seen for that account.',
    causes: [
      'User traveling or working remotely (False Positive).',
      'Compromised credentials used by an attacker.',
      'New VPN endpoint or proxy usage.',
    ],
    actions: [
      'Step 1: **Verify Location.** Check the geolocation data for the new IP address.',
      'Step 2: **Contact User.** Contact the user out-of-band to confirm if they initiated the login from that location.',
      'Step 3: **Check Device/Agent Health.** If the login is confirmed, ensure the endpoint security agent is healthy and running.',
      'Step 4: **Containment (If Malicious).** If unauthorized, immediately suspend the account, invalidate the session, and force a password reset.',
      'Step 5: **Audit Activity.** Review post-login activity (e.g., file access, email forwarding rules) for signs of compromise.',
    ],
    queries: [
      { tool: 'Identity Logs', query: 'LoginEvents | where user="[USER]" and geo_location NOT IN (baseline_locations)' },
    ],
    tools: ['Identity Provider Logs', 'Communication Tools', 'GeoIP Database'],
    escalation: 'Escalate if the user cannot be reached or if post-login malicious activity is detected.',
  },

  // --- 2. Network & Firewall Alerts (Total: 4) ---
  {
    id: 'dns-tunneling',
    name: 'DNS Tunneling Detected',
    category: 'Network & Firewall',
    description: 'Detection of data being covertly transmitted over the DNS protocol, often characterized by unusually large or frequent DNS queries to a specific external server.',
    causes: [
      'Compromised internal host.',
      'Use of a DNS tunneling tool (e.g., Iodine, Dnscat2).',
      'Attacker bypassing traditional firewall rules.',
    ],
    actions: [
      'Step 1: **Verify Alert.** Confirm the alert by checking the volume and length of DNS queries from the source IP. Look for non-standard characters (high entropy) in the query names.',
      'Step 2: **Identify Source.** Determine the hostname and user associated with the source IP address.',
      'Step 3: **Containment.** Immediately isolate the source host from the network to stop data exfiltration.',
      'Step 4: **Perimeter Block.** Block the external destination DNS server IP and domain at the firewall and DNS filter.',
      'Step 5: **Forensic Analysis.** Analyze the isolated host for the presence of DNS tunneling software or malware that initiated the connection.',
      'Step 6: **Remediation.** If malware is found, follow the Malware Eradication playbook. If a legitimate tool was misused, enforce policy.',
    ],
    queries: [
      { tool: 'DNS Logs', query: 'query_length > 100 AND query_count > 500 | group by src_ip, query_domain' },
    ],
    tools: ['DNS Server Logs', 'SIEM/Log Analytics', 'EDR', 'Firewall/IPS'],
    escalation: 'Escalate if the host is a critical server or if confirmed sensitive data was exfiltrated.',
  },
  {
    id: 'data-exfiltration-attempt',
    name: 'Data Exfiltration Attempt',
    category: 'Network & Firewall',
    description: 'Detection of unusually large outbound data transfers to an external, non-corporate destination, often using encrypted or non-standard protocols.',
    causes: [
      'Insider threat attempting to steal data.',
      'Malware communicating with a C2 server to upload stolen data.',
      'Misconfigured backup or synchronization service (False Positive).',
    ],
    actions: [
      'Step 1: **Identify Source and Destination.** Determine the source host, user, and the external destination IP/domain receiving the data.',
      'Step 2: **Containment.** Immediately isolate the source host from the network.',
      'Step 3: **Verify Legitimacy.** Contact the user/owner out-of-band to verify the transfer. Check change management for approved large transfers.',
      'Step 4: **DLP Review.** Check DLP logs to see if the transferred data was tagged as sensitive (PII, IP).',
      'Step 5: **Perimeter Block.** Block the destination IP/domain at the firewall/proxy.',
      'Step 6: **Forensic Analysis.** If malicious, perform a forensic analysis on the source host to identify the method and scope of data collection.',
    ],
    queries: [
      { tool: 'NetFlow/Firewall', query: 'traffic_outbound > 1GB AND dest_ip NOT IN (corporate_destinations) | top src_ip' },
    ],
    tools: ['NetFlow Analyzer', 'DLP System', 'Firewall Logs', 'EDR'],
    escalation: 'CRITICAL. Escalate immediately if sensitive data exfiltration is confirmed.',
  },
  {
    id: 'port-scan-detected',
    name: 'Port Scan Detected',
    category: 'Network & Firewall',
    description: 'A host is rapidly scanning a range of IP addresses or ports on the network, indicating reconnaissance activity.',
    causes: [
      'Attacker mapping the internal network.',
      'Vulnerability scanner or penetration testing tool (False Positive).',
      'Misconfigured network monitoring tool.',
    ],
    actions: [
      'Step 1: **Identify Scanner and Target.** Determine the source IP performing the scan and the target IP range.',
      'Step 2: **Verify Legitimacy.** Check if the source IP belongs to an approved security tool or team (e.g., vulnerability scanner).',
      'Step 3: **Containment.** If unauthorized, block the source IP at the internal firewall or network access control (NAC) layer.',
      'Step 4: **Check for Follow-up Activity.** Review logs for any immediate connection attempts or exploitation attempts following the scan.',
      'Step 5: **Forensic Analysis.** If the source is an internal host, isolate it and check for malware or unauthorized tools.',
    ],
    queries: [
      { tool: 'IPS/Firewall Logs', query: 'event_type="Port_Scan" | group by src_ip, dest_ip_range' },
    ],
    tools: ['IPS/Firewall Console', 'NAC', 'Asset Inventory'],
    escalation: 'Escalate if the scan is followed by successful exploitation attempts.',
  },
  {
    id: 'connection-to-malicious-ip',
    name: 'Connection to Known Malicious IP',
    category: 'Network & Firewall',
    description: 'An internal host initiated a connection to an external IP address identified as malicious (e.g., C2, malware distribution) by threat intelligence.',
    causes: [
      'Active malware infection on the internal host.',
      'User accidentally browsing a malicious website.',
    ],
    actions: [
      'Step 1: **Validate IOC.** Confirm the external IP is still listed as malicious in threat feeds.',
      'Step 2: **Identify Source Host.** Determine the internal source IP, hostname, and the process that initiated the connection.',
      'Step 3: **Containment.** Immediately isolate the source host from the network.',
      'Step 4: **Perimeter Block.** Block the malicious external IP at the firewall/proxy.',
      'Step 5: **Forensic Analysis.** Perform a deep scan on the isolated host to identify the malware or root cause of the connection.',
      'Step 6: **IOC Search.** Search the entire environment (SIEM, EDR) for the malicious IP and any associated file hashes.',
    ],
    queries: [
      { tool: 'Proxy/Firewall Logs', query: 'dest_ip="[MALICIOUS_IP]" AND action="Allowed"' },
    ],
    tools: ['Threat Intelligence Platform', 'Firewall/Proxy', 'EDR'],
    escalation: 'High priority. Escalate if the connection resulted in a successful data transfer or payload download.',
  },

  // --- 3. Endpoint & Malware Alerts (Total: 5) ---
  {
    id: 'ransomware-behavior',
    name: 'Ransomware Behavior Detected',
    category: 'Endpoint & Malware',
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
    id: 'fileless-malware',
    name: 'Fileless Malware Activity',
    category: 'Endpoint & Malware',
    description: 'Detection of malicious activity executed entirely in memory or via legitimate system tools (e.g., PowerShell, WMI) without dropping a traditional executable file.',
    causes: [
      'Exploitation of a vulnerability leading to in-memory payload execution.',
      'Use of living-off-the-land binaries (LOLBAS) by an attacker.',
    ],
    actions: [
      'Step 1: **Capture Memory.** Immediately capture a memory dump of the affected host before isolation (if possible) to preserve volatile data.',
      'Step 2: **Isolate Host.** Isolate the affected endpoint from the network.',
      'Step 3: **Analyze Process Tree.** Review the process tree in the EDR to identify the parent process that launched the suspicious script (e.g., PowerShell, wmic).',
      'Step 4: **Identify Persistence.** Check registry keys (Run keys), WMI event subscriptions, and scheduled tasks for persistence mechanisms.',
      'Step 5: **IOC Extraction.** Extract any encoded commands or scripts found in the process arguments for decoding and analysis.',
      'Step 6: **Remediation.** Re-image the host, as fileless malware can be difficult to fully eradicate without a clean OS install.',
    ],
    queries: [
      { tool: 'EDR', query: 'process_name="powershell.exe" AND command_line CONTAINS "EncodedCommand"' },
    ],
    tools: ['EDR Console', 'Memory Forensic Tools', 'SIEM'],
    escalation: 'Escalate immediately, as fileless attacks indicate a sophisticated and active threat actor.',
  },
  {
    id: 'suspicious-process-lolbas',
    name: 'Suspicious Process Execution (LOLBAS)',
    category: 'Endpoint & Malware',
    description: 'Detection of a legitimate system utility (e.g., certutil, bitsadmin, mshta) being executed with suspicious command-line arguments, often used for downloading malware or persistence.',
    causes: [
      'Attacker using Living Off the Land Binaries (LOLBAS) to evade detection.',
      'Malware payload executing via a trusted process.',
    ],
    actions: [
      'Step 1: **Identify Process and Arguments.** Determine the exact utility used (e.g., `certutil.exe`) and the full command line arguments, looking for external URLs or unusual file paths.',
      'Step 2: **Isolate Host.** Immediately isolate the affected endpoint from the network.',
      'Step 3: **Check Parent Process.** Review the process tree to identify the parent process that launched the suspicious utility (e.g., a browser, a document reader).',
      'Step 4: **Analyze Network Connections.** Check network logs for connections made by the utility to external IPs/domains mentioned in the arguments.',
      'Step 5: **IOC Extraction.** Extract any downloaded files or scripts for sandbox analysis.',
      'Step 6: **Remediation.** If malicious, follow the Malware Eradication playbook, focusing on persistence removal and re-imaging.',
    ],
    queries: [
      { tool: 'EDR', query: 'process_name IN ("certutil.exe", "bitsadmin.exe") AND command_line CONTAINS "urlcache"' },
    ],
    tools: ['EDR Console', 'Network Logs', 'Sandbox Analysis'],
    escalation: 'Escalate if the process was used to download and execute a secondary payload.',
  },
  {
    id: 'persistence-mechanism-detected',
    name: 'Persistence Mechanism Detected',
    category: 'Endpoint & Malware',
    description: 'Detection of unauthorized modifications to system startup locations, such as new registry Run keys, WMI event subscriptions, or scheduled tasks.',
    causes: [
      'Malware attempting to survive a reboot.',
      'Attacker establishing long-term access.',
      'Misconfigured legitimate application (False Positive).',
    ],
    actions: [
      'Step 1: **Identify Mechanism.** Determine the exact persistence method (e.g., specific registry key, scheduled task name, WMI filter).',
      'Step 2: **Isolate Host.** Immediately isolate the affected endpoint.',
      'Step 3: **Remove Persistence.** Delete the unauthorized registry key, scheduled task, or WMI subscription.',
      'Step 4: **Identify Payload.** Determine the file or command being executed by the persistence mechanism and analyze it for malicious intent.',
      'Step 5: **Root Cause Analysis.** Investigate how the persistence was created (e.g., which process, user, or vulnerability was exploited).',
      'Step 6: **Remediation.** If malicious, follow the Malware Eradication playbook and re-image the host.',
    ],
    queries: [
      { tool: 'EDR', query: 'event_type="Registry_Modification" AND key_path CONTAINS "Run" AND process_name NOT IN (approved_list)' },
    ],
    tools: ['EDR Console', 'Registry Editor (Forensic)', 'SIEM'],
    escalation: 'Escalate if the persistence mechanism is tied to a high-privilege account or critical server.',
  },
  {
    id: 'unauthorized-powershell',
    name: 'Unauthorized PowerShell Command',
    category: 'Endpoint & Malware',
    description: 'Execution of a highly suspicious or encoded PowerShell command, often used for reconnaissance, downloading payloads, or lateral movement.',
    causes: [
      'Attacker using PowerShell for post-exploitation.',
      'Malware executing via a script.',
      'Legitimate administrative script running outside of approved parameters (False Positive).',
    ],
    actions: [
      'Step 1: **Capture Command Line.** Capture the full, decoded command line arguments.',
      'Step 2: **Isolate Host.** Immediately isolate the affected endpoint.',
      'Step 3: **Analyze Script.** Decode and analyze the script content for malicious functions (e.g., network connections, credential dumping).',
      'Step 4: **Check Parent Process.** Determine the parent process that launched PowerShell (e.g., a browser, a document).',
      'Step 5: **IOC Extraction.** Extract any external IPs, domains, or file hashes mentioned in the script.',
      'Step 6: **Remediation.** If malicious, follow the Malware Eradication playbook and enforce stricter PowerShell logging policies.',
    ],
    queries: [
      { tool: 'EDR', query: 'process_name="powershell.exe" AND command_line CONTAINS ("-EncodedCommand" OR "IEX")' },
    ],
    tools: ['EDR Console', 'PowerShell Transcription Logs', 'Sandbox Analysis'],
    escalation: 'Escalate if the command was used for credential theft or lateral movement.',
  },

  // --- 4. Email & Phishing Alerts (Total: 3) ---
  {
    id: 'malicious-attachment',
    name: 'Malicious Attachment Detected',
    category: 'Email & Phishing',
    description: 'An email containing an attachment identified as malware (e.g., executable, macro-enabled document) was delivered to a user inbox.',
    causes: [
      'Email gateway failed to detect the malicious payload.',
      'Zero-day malware variant.',
    ],
    actions: [
      'Step 1: **Identify IOCs.** Extract the file hash and file name of the malicious attachment.',
      'Step 2: **Containment (Email).** Use the Email Security Gateway (ESG) to search for and immediately remove the email from all user inboxes.',
      'Step 3: **Check Execution.** Search EDR/SIEM logs for the file hash to see if the attachment was downloaded or executed by any user.',
      'Step 4: **Containment (Endpoint).** If execution is confirmed, immediately isolate the affected endpoint and follow the Malware playbook.',
      'Step 5: **Block Indicators.** Add the file hash and sender domain to perimeter block lists.',
      'Step 6: **User Notification.** Notify the affected user(s) and provide targeted training.',
    ],
    queries: [
      { tool: 'ESG', query: 'attachment_hash="[MALICIOUS_HASH]" AND delivery_status="Delivered"' },
      { tool: 'EDR', query: 'file_hash="[MALICIOUS_HASH]" AND event_type="Process_Creation"' },
    ],
    tools: ['Email Security Gateway (ESG)', 'EDR', 'SIEM'],
    escalation: 'Escalate if execution is confirmed or if the attachment bypassed multiple security layers.',
  },
  {
    id: 'phishing-email-detected',
    name: 'Phishing Email Detected',
    category: 'Email & Phishing',
    description: 'An email reported by a user or flagged by the system containing suspicious links, requests for credentials, or social engineering tactics.',
    causes: [
      'Targeted spear phishing campaign.',
      'Mass phishing attempt.',
      'User error in reporting (False Positive).',
    ],
    actions: [
      'Step 1: **Analyze Headers.** Review email headers to verify the true sender and origin IP.',
      'Step 2: **Containment (Email).** Immediately remove the email from all user inboxes using the ESG.',
      'Step 3: **Analyze Links/Attachments.** Sandbox any links or attachments to determine malicious intent and extract IOCs.',
      'Step 4: **Check for User Interaction.** Determine if the recipient clicked the link, opened the attachment, or replied with sensitive information.',
      'Step 5: **Remediation.** If credentials were entered, force an immediate password reset and check for signs of account compromise (Impossible Travel, mailbox rules).',
      'Step 6: **Block Indicators.** Block the sender domain, sender IP, and any malicious URLs at the perimeter.',
    ],
    queries: [
      { tool: 'ESG', query: 'subject="[PHISHING_SUBJECT]" OR sender_ip="[PHISHING_IP]"' },
    ],
    tools: ['Email Security Gateway (ESG)', 'Sandbox Analysis', 'Identity Provider'],
    escalation: 'Escalate if the email is part of a targeted campaign or if a high-privilege user interacted with it.',
  },
  {
    id: 'compromised-mailbox-detected',
    name: 'Compromised Mailbox Detected',
    category: 'Email & Phishing',
    description: 'Detection of suspicious activity within a user\'s mailbox, such as mass email sending, creation of forwarding rules, or unusual access patterns.',
    causes: [
      'Stolen credentials used by an attacker.',
      'Session token theft.',
      'Internal user abusing access.',
    ],
    actions: [
      'Step 1: **Immediate Suspension.** Immediately suspend the user account and invalidate all active sessions.',
      'Step 2: **Identify Malicious Rules.** Check the mailbox for unauthorized forwarding rules, delegation changes, or retention policy modifications and remove them.',
      'Step 3: **Audit Sent Items.** Review the Sent Items folder for unauthorized emails, especially those sent internally or containing sensitive data.',
      'Step 4: **Identify Source.** Determine the source IP and client used for the malicious access.',
      'Step 5: **Remediation.** Force a password reset, ensure MFA is enabled, and notify all recipients of the malicious emails.',
    ],
    queries: [
      { tool: 'Mail Audit Logs', query: 'operation="New-InboxRule" AND rule_name NOT IN (approved_rules)' },
    ],
    tools: ['Mail Server Audit Logs', 'Identity Provider', 'SIEM'],
    escalation: 'Escalate if the mailbox belongs to an executive or if the account was used to launch a widespread internal phishing campaign.',
  },

  // --- 5. Cloud Security Alerts (Total: 3) ---
  {
    id: 'unusual-cloud-api-calls',
    name: 'Unusual Cloud API Calls',
    category: 'Cloud Security',
    description: 'A user or service role is making API calls that are highly unusual for their baseline behavior (e.g., creating keys, modifying security groups, accessing resources in a new region).',
    causes: [
      'Compromised cloud credentials/access key.',
      'Insider threat abusing legitimate access.',
      'New automation script deployed without baseline update (False Positive).',
    ],
    actions: [
      'Step 1: **Identify Identity.** Determine the IAM user or role making the suspicious calls and the source IP.',
      'Step 2: **Containment.** If unauthorized, immediately revoke the session token or access key used for the calls.',
      'Step 3: **Verify Legitimacy.** Contact the owner of the identity out-of-band to verify the activity. Check change management records.',
      'Step 4: **Audit Changes.** Review the specific API calls made (e.g., `CreateUser`, `AuthorizeSecurityGroupIngress`) and revert any unauthorized changes.',
      'Step 5: **Remediation.** If compromised, force a password rotation for the user and delete/rotate the compromised access key.',
    ],
    queries: [
      { tool: 'CloudTrail/Activity Log', query: 'eventName IN ("CreateAccessKey", "RunInstances") AND userAgent NOT IN ("Approved_Automation")' },
    ],
    tools: ['Cloud Provider Console (IAM)', 'Cloud Audit Logs', 'SIEM'],
    escalation: 'Escalate if the activity involves creating new administrative users or modifying network security to allow external access.',
  },
  {
    id: 'public-s3-bucket-exposure',
    name: 'Public S3 Bucket Exposure',
    category: 'Cloud Security',
    description: 'Detection of a cloud storage bucket configured for public read or write access, potentially exposing sensitive data.',
    causes: [
      'Misconfiguration during deployment (e.g., "Everyone" access granted).',
      'Automated script error or manual oversight.',
      'Lack of continuous cloud security posture management (CSPM).',
    ],
    actions: [
      'Step 1: **Verify Public Access.** Immediately confirm the public access status of the identified bucket using the cloud provider console.',
      'Step 2: **Containment.** Change the bucket policy immediately to restrict access to internal users only (or specific roles/IPs).',
      'Step 3: **Scope Assessment.** Determine what data was stored in the bucket and if it contained sensitive information (PII, IP).',
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
    id: 'new-root-user-login',
    name: 'New Root User Login',
    category: 'Cloud Security',
    description: 'A successful login by the cloud provider\'s root account, which should rarely, if ever, be used.',
    causes: [
      'Unauthorized access to the most privileged account.',
      'Legitimate, but unapproved, maintenance activity.',
    ],
    actions: [
      'Step 1: **Immediate Suspension.** Immediately invalidate the root user session and rotate the root user password and access keys.',
      'Step 2: **Identify Source.** Determine the source IP and user agent of the login.',
      'Step 3: **Verify Legitimacy.** Contact the designated owner of the root account out-of-band to verify the activity.',
      'Step 4: **Audit Activity.** Review all API calls made by the root user during the session for unauthorized changes (e.g., creating new IAM users, modifying billing).',
      'Step 5: **Remediation.** Ensure the root account is protected by strong MFA (preferably hardware) and stored securely. Document the policy violation.',
    ],
    queries: [
      { tool: 'CloudTrail/Activity Log', query: 'userIdentity.type="Root" AND eventName="ConsoleLogin" AND responseElements.ConsoleLogin="Success"' },
    ],
    tools: ['Cloud Provider Console (IAM)', 'Cloud Audit Logs'],
    escalation: 'CRITICAL. Escalate immediately. Root account compromise is the highest risk cloud incident.',
  },

  // --- 6. Data & Insider Threat Alerts (Total: 2) ---
  {
    id: 'unauthorized-usb',
    name: 'Unauthorized USB Device Connected',
    category: 'Data & Insider Threat',
    description: 'A non-approved external storage device (USB drive) was connected to an endpoint, posing a risk of data exfiltration or malware introduction.',
    causes: [
      'Insider threat attempting to copy data.',
      'User negligence (using personal USB drive).',
      'Malware delivered via USB (e.g., BadUSB).',
    ],
    actions: [
      'Step 1: **Identify Host and User.** Determine the endpoint hostname and the logged-in user.',
      'Step 2: **Containment.** Use EDR to immediately block all read/write access to the connected USB device.',
      'Step 3: **Contact User.** Contact the user out-of-band to determine the purpose and nature of the device.',
      'Step 4: **Scan Device/Host.** If the device is unapproved, initiate a full malware scan on the host. If possible, scan the contents of the USB drive remotely.',
      'Step 5: **DLP Review.** Check DLP logs for any file copy attempts to the USB device during the connection window.',
      'Step 6: **Policy Enforcement.** If policy violation, document the incident and enforce disciplinary action/retraining.',
    ],
    queries: [
      { tool: 'EDR', query: 'event_type="Device_Connection" AND device_type="USB_Storage" AND device_status="Unapproved"' },
    ],
    tools: ['EDR Console', 'DLP System', 'Asset Inventory'],
    escalation: 'Escalate if the user refuses to cooperate or if sensitive data transfer is confirmed.',
  },
  {
    id: 'privileged-user-data-access',
    name: 'Privileged User Data Access',
    category: 'Data & Insider Threat',
    description: 'A highly privileged user (e.g., system administrator) accessed a sensitive data repository (e.g., HR files, financial records) outside of their normal operational duties.',
    causes: [
      'Insider threat abusing legitimate access.',
      'Compromised privileged account.',
      'Legitimate, but undocumented, troubleshooting (False Positive).',
    ],
    actions: [
      'Step 1: **Identify User and Resource.** Determine the user, the time of access, and the specific sensitive resource accessed.',
      'Step 2: **Verify Legitimacy.** Contact the user\'s manager or the data owner out-of-band to verify if the access was authorized or necessary.',
      'Step 3: **Audit Access.** Review the full audit trail of the user\'s activity during the session, looking for data modification, deletion, or copying.',
      'Step 4: **Containment (If Malicious).** If unauthorized, immediately suspend the user\'s privileged access and investigate the account for compromise.',
      'Step 5: **Policy Enforcement.** If unauthorized but not malicious (e.g., curiosity), document the incident and initiate disciplinary action.',
    ],
    queries: [
      { tool: 'File/Share Audit Logs', query: 'user_group="Privileged_Admins" AND resource_path CONTAINS "Sensitive_Data"' },
    ],
    tools: ['File Audit Logs', 'DLP System', 'Identity Provider'],
    escalation: 'Escalate immediately if the user is confirmed to be acting maliciously or if the account is compromised.',
  },

  // --- 7. Threat Intelligence & External Alerts (Total: 2) ---
  {
    id: 'c2-communication',
    name: 'Communication with C2 Server',
    category: 'Threat Intelligence & External',
    description: 'An internal host is communicating with an external IP or domain identified as a known Command and Control (C2) server by threat intelligence feeds.',
    causes: [
      'Active malware infection on the internal host.',
      'Compromised system receiving instructions from an attacker.',
    ],
    actions: [
      'Step 1: **Validate IOC.** Confirm the external IP/domain is still listed as a high-confidence C2 server in multiple threat feeds.',
      'Step 2: **Identify Source.** Determine the internal source host (IP and hostname) and the specific process initiating the connection.',
      'Step 3: **Containment.** Immediately isolate the source host from the network.',
      'Step 4: **Perimeter Block.** Block the C2 IP/domain at the firewall/proxy.',
      'Step 5: **Forensic Analysis.** Perform a deep forensic analysis on the isolated host to identify the malware, persistence, and data collected.',
      'Step 6: **IOC Search.** Search the entire environment (SIEM, EDR) for the C2 IP, domain, and any associated file hashes.',
    ],
    queries: [
      { tool: 'SIEM', query: 'index=network dest_ip="[C2_IP]" AND action="Allowed"' },
    ],
    tools: ['Threat Intelligence Platform', 'SIEM', 'EDR', 'Firewall'],
    escalation: 'High priority. Escalate immediately, as this confirms an active, post-exploitation phase.',
  },

  // --- 8. SIEM & System Alerts (Total: 2) ---
  {
    id: 'detection-rule-modified',
    name: 'Detection Rule Modified or Disabled',
    category: 'SIEM & System Alerts',
    description: 'A critical security detection rule (e.g., in SIEM, EDR, or Firewall) was modified, deleted, or disabled, potentially blinding the security team.',
    causes: [
      'Malicious actor attempting to cover their tracks (Attack on Logging).',
      'Unauthorized administrative action.',
      'Legitimate maintenance or tuning without proper change control (False Positive).',
    ],
    actions: [
      'Step 1: **Identify Change.** Determine the specific rule modified, the user/account that made the change, and the time.',
      'Step 2: **Revert Change.** Immediately revert the rule to its previous, secure state.',
      'Step 3: **Verify Change Control.** Check the change management system for an approved ticket.',
      'Step 4: **Audit Activity.** If unauthorized, review the activity of the user/account that made the change immediately before and after the modification for signs of compromise.',
      'Step 5: **Backfill Logs.** If the rule was disabled for a period, ensure logs for that period are reviewed manually for missed threats.',
    ],
    queries: [
      { tool: 'SIEM Audit Logs', query: 'operation="Rule_Modification" OR operation="Rule_Deletion" AND rule_name="[CRITICAL_RULE]"' },
    ],
    tools: ['SIEM Audit Logs', 'Change Management System', 'Identity Provider'],
    escalation: 'Escalate if the change was unauthorized and performed by a compromised account.',
  },

  // --- 9. Incident Response / Automation Triggers (Total: 1) ---
  {
    id: 'automated-containment-triggered',
    name: 'Automated Containment Triggered',
    category: 'Incident Response / Automation Triggers',
    description: 'A Security Orchestration, Automation, and Response (SOAR) playbook successfully executed an automated containment action (e.g., host isolation, account suspension).',
    causes: [
      'High-confidence alert triggered the SOAR playbook.',
      'Misconfigured SOAR rule leading to unnecessary containment (False Positive).',
    ],
    actions: [
      'Step 1: **Verify Trigger.** Review the original alert that triggered the automation (e.g., Ransomware Behavior, C2 Communication).',
      'Step 2: **Confirm Containment.** Verify that the automated action (e.g., host isolation) was successful and complete.',
      'Step 3: **Manual Triage.** Perform manual triage on the contained asset to confirm the threat and prevent false positives from escalating.',
      'Step 4: **Proceed with Playbook.** If confirmed malicious, continue with the manual steps of the original alert\'s playbook (e.g., forensic analysis, eradication).',
      'Step 5: **Document and Tune.** Document the success/failure of the automation and tune the SOAR rule if necessary.',
    ],
    queries: [
      { tool: 'SOAR Logs', query: 'playbook_name="Containment_Host_Isolation" AND status="Success"' },
    ],
    tools: ['SOAR Platform', 'SIEM', 'EDR Console'],
    escalation: 'Escalate if the automated containment failed or if the contained asset is a critical production system.',
  },
];

export const categories: AlertCategory[] = [
  'Authentication & Access', 
  'Network & Firewall', 
  'Endpoint & Malware', 
  'Email & Phishing', 
  'Cloud Security', 
  'Data & Insider Threat', 
  'Threat Intelligence & External', 
  'SIEM & System Alerts', 
  'Incident Response / Automation Triggers'
];