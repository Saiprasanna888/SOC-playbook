import { AlertPlaybook, AlertCategory } from "@/types/alert";

export const mockAlerts: AlertPlaybook[] = [
  {
    id: 'brute-force',
    name: 'Brute Force Attack',
    category: 'Authentication',
    description: 'A high volume of failed login attempts targeting a single or multiple accounts over a short period.',
    causes: [
      'Weak passwords being targeted.',
      'Automated scripts or bots attempting credential stuffing.',
      'Misconfigured rate limiting on login endpoints.',
    ],
    actions: [
      'Identify the source IP and user account(s) being targeted.',
      'Check if any login attempts were successful.',
      'Temporarily block the malicious source IP using firewall/WAF.',
      'Force password reset for affected user accounts.',
      'Review authentication logs for signs of lateral movement.',
    ],
    queries: [
      { tool: 'Splunk', query: 'index=auth sourcetype=login status=failure | stats count by src_ip, user | where count > 50' },
      { tool: 'Wazuh', query: 'rule.groups:authentication_failure AND srcip != "internal_network"' },
    ],
    tools: ['Firewall/WAF', 'Identity Provider Logs', 'SIEM'],
    escalation: 'Escalate to Incident Response Team if successful login or lateral movement is detected.',
  },
  {
    id: 'phishing-email',
    name: 'Phishing Email Detected',
    category: 'Data Security',
    description: 'An email flagged by security tools or reported by a user containing malicious links, attachments, or impersonation attempts.',
    causes: [
      'User clicked a malicious link or opened an attachment.',
      'Lack of robust email filtering/DMARC/SPF/DKIM configuration.',
    ],
    actions: [
      'Isolate the email and analyze headers for origin and authenticity.',
      'Check if the email was delivered to other users and remove it from their inboxes.',
      'Scan the affected user endpoint for malware if an attachment was opened.',
      'Notify the user and provide immediate security awareness training.',
    ],
    queries: [
      { tool: 'Microsoft Defender', query: 'EmailEvents | where ThreatTypes contains "Phish"' },
    ],
    tools: ['Email Security Gateway', 'Sandbox Analysis', 'Endpoint Detection and Response (EDR)'],
    escalation: 'Escalate if credentials were entered or malware infection is confirmed.',
  },
  {
    id: 'malware-outbreak',
    name: 'Malware Outbreak',
    category: 'Endpoint',
    description: 'Multiple endpoints reporting detection of the same or related malware strain simultaneously.',
    causes: [
      'Successful phishing campaign.',
      'Exploitation of a vulnerability in a common software.',
      'Uncontrolled external media usage (USB drives).',
    ],
    actions: [
      'Immediately isolate all affected endpoints from the network.',
      'Identify the initial point of compromise (patient zero).',
      'Deploy updated signatures/patches across the environment.',
      'Perform forensic analysis on a sample infected machine.',
    ],
    queries: [
      { tool: 'EDR', query: 'Process: Create, File: Write, Network: Connect | where MalwareName = "RansomwareX"' },
    ],
    tools: ['EDR', 'Network Access Control (NAC)', 'Vulnerability Scanner'],
    escalation: 'High priority. Engage Crisis Management Team immediately.',
  },
  {
    id: 'suspicious-network-traffic',
    name: 'Suspicious Outbound Network Traffic',
    category: 'Network',
    description: 'Unusual high volume or connections to known malicious IPs or non-standard ports.',
    causes: [
      'Command and Control (C2) communication from compromised internal host.',
      'Data exfiltration attempt.',
      'Misconfigured application or service.',
    ],
    actions: [
      'Identify the source host and process generating the traffic.',
      'Block the destination IP/domain at the perimeter firewall.',
      'Isolate the source host for deeper inspection.',
      'Analyze packet captures (PCAPs) if available.',
    ],
    queries: [
      { tool: 'SIEM/Log Analytics', query: 'index=network traffic_outbound | where dest_ip IN (malicious_ip_list)' },
    ],
    tools: ['Network Monitoring Tools', 'Firewall Logs', 'IDS/IPS'],
    escalation: 'Escalate if data exfiltration is confirmed or traffic persists after blocking.',
  },
];

export const categories: AlertCategory[] = ['Authentication', 'Network', 'Endpoint', 'Data Security', 'Cloud', 'Other'];