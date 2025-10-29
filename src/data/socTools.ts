import { AlertTriangle, BookOpen, Brain, Cloud, Database, Flame, Globe, Mail, Search, Settings, Shield, Terminal, User, Zap } from 'lucide-react';
import React from 'react';

export interface ToolDetail {
  name: string;
  purpose: string;
  keyFeatures: string[];
  advantages: string[];
  usage: string;
  architecture: string[];
  workflow: string[];
  icon: React.ElementType;
  iconColor: string;
}

export interface ToolCategory {
  title: string;
  icon: React.ElementType;
  description: string;
  color: string;
  details: ToolDetail[];
}

// --- EDR Tools ---
const edrTools: ToolDetail[] = [
  {
    name: 'CrowdStrike Falcon',
    purpose: 'In a SOC, CrowdStrike Falcon acts as an Endpoint Detection and Response (EDR) + Threat Intelligence tool, enabling analysts to detect, investigate, respond, and hunt for threats on endpoints in real time.',
    keyFeatures: [
      'EDR Telemetry – Continuous endpoint monitoring for all processes, connections, and file activities.',
      'Real-Time Alerting – Instant alerts for suspicious or confirmed threats in the SOC dashboard.',
      'Threat Hunting Tools – Falcon’s Query Language (FQL) to find hidden threats.',
      'Integration with SIEM/SOAR – Sends logs to tools like Splunk, QRadar, or Azure Sentinel.',
      'Automated Response Playbooks – SOC can execute predefined actions (isolate host, kill process) automatically.',
    ],
    advantages: [
      'Reduces Detection Time – Speeds up the SOC’s MTTD (Mean Time to Detect).',
      'Accelerates Response – Remote isolation prevents lateral movement during attacks.',
      'Comprehensive Visibility – Full endpoint activity timeline for investigations.',
      'Global Threat Intel – Access to CrowdStrike’s intelligence database for faster IOC verification.',
      'Cloud Scalability – SOC can monitor thousands of devices without managing on-prem infrastructure.',
    ],
    usage: 'Incident Detection (L1), Incident Investigation (L2/3), Threat Hunting, Automated Response, and Integration with SOC Tools (SIEM/SOAR).',
    architecture: [
      'Endpoints (Workstations, Servers, Cloud Workloads): Falcon sensor installed, collecting telemetry.',
      'CrowdStrike Cloud: Processes EDR data using AI/ML, enriches alerts with global threat intel.',
      'Falcon Console: SOC analysts log in to view, investigate, and respond.',
      'SIEM/SOAR Integration: Falcon sends logs to SOC’s SIEM for correlation; SOAR platforms trigger automated responses.',
    ],
    workflow: [
      'Step 1 – Data Collection: Falcon sensors record endpoint activity continuously and send data to the CrowdStrike cloud.',
      'Step 2 – Detection: Falcon’s analytics detect suspicious behavior, generating alerts in the Falcon Console and SIEM.',
      'Step 3 – Triage: L1 SOC analysts review alerts and escalate confirmed threats.',
      'Step 4 – Investigation: L2 SOC analysts investigate endpoint activity via Falcon’s EDR timeline, searching for IOCs and attack patterns.',
      'Step 5 – Response: Analysts isolate infected hosts remotely, kill malicious processes, and delete malware.',
      'Step 6 – Threat Hunting & Intelligence: Threat hunters proactively search for hidden threats using Falcon data, and new intel is shared across the SOC team.',
    ],
    icon: Shield,
    iconColor: 'text-green-500',
  },
  {
    name: 'SentinelOne Singularity',
    purpose: 'SentinelOne is an AI-powered EDR/XDR that autonomously detects and responds to fileless, zero-day, and ransomware attacks, focusing on minimizing human intervention and providing automated remediation.',
    keyFeatures: [
      'Behavioral AI Detection – Uses machine learning to identify malicious behavior, not just signatures.',
      'ActiveEDR Storyline – Automatically correlates related events into a single, easy-to-read attack narrative.',
      'Automated Remediation & Rollback – Can autonomously kill processes, quarantine files, and roll back the endpoint to a pre-infection state.',
      'Deep Visibility Console – Powerful threat hunting console for searching raw endpoint data.',
      'XDR Correlation – Integrates data across endpoint, network, and cloud for holistic visibility.',
    ],
    advantages: [
      'Autonomous Response – Reduces analyst load and speeds up MTTR (Mean Time to Respond).',
      'Storyline Correlation – Minimizes alert fatigue by grouping related events.',
      'Windows Rollback – Unique feature for rapid recovery from ransomware/destructive attacks.',
      'High Accuracy AI – Effective against fileless and zero-day threats.',
      'Fast Root-Cause Analysis – Provides clear MITRE mapping for every incident.',
    ],
    usage: 'Prevention, real-time detection, automated containment, forensic investigation, and cross-platform threat hunting.',
    architecture: [
      'SentinelOne Agent: Installed on endpoints, continuously monitors and enforces policies locally.',
      'Singularity Platform (Cloud): Central management, AI analysis, threat intelligence, and data correlation.',
      'Deep Visibility Data Lake: Stores raw and correlated telemetry for threat hunting and forensics.',
      'Management Console: SOC analysts use this for incident review, policy management, and manual response actions.',
    ],
    workflow: [
      'Step 1 – Detection & Autonomous Response: SentinelOne detects a threat and automatically initiates "Storyline Remediation" (e.g., killing processes, rolling back files).',
      'Step 2 – Triage & Validation: L1/L2 analysts review the "ActiveEDR Storyline" to validate the autonomous actions and confirm the threat is neutralized.',
      'Step 3 – Investigation: Analysts use the Deep Visibility console to search for the initial infection vector or related IOCs across the fleet.',
      'Step 4 – Containment Confirmation: Confirm the threat is eradicated and release the host from quarantine if necessary.',
      'Step 5 – Documentation: Document the incident, focusing on the success of the automated rollback feature and the root cause.',
    ],
    icon: Zap,
    iconColor: 'text-indigo-500',
  },
  {
    name: 'Microsoft Defender for Endpoint (MDE)',
    purpose: 'MDE is an enterprise-grade EDR and EPP solution deeply integrated with the Microsoft 365 and Azure ecosystem, providing unified security operations and automated investigation capabilities.',
    keyFeatures: [
      'Next-Gen AV – Cloud-backed antivirus protection with behavioral monitoring.',
      'Attack Surface Reduction (ASR) – Policies to block common attack vectors (e.g., macro execution).',
      'Automated Investigation & Remediation (AIR) – AI-driven playbooks that automatically investigate alerts and apply remediation actions.',
      'Advanced Hunting (KQL) – Powerful Kusto Query Language (KQL) for deep threat hunting across endpoint data.',
      'Threat & Vulnerability Management (TVM) – Continuous discovery and prioritization of endpoint vulnerabilities.',
    ],
    advantages: [
      'Native Integration – Seamlessly works with Azure Sentinel, Microsoft 365, and Intune.',
      'Unified Portal – Centralized security management via the Microsoft 365 Defender portal.',
      'Automated Response – Reduces manual effort for common, high-volume threats.',
      'Rich Telemetry – Provides deep visibility into Windows OS events and processes.',
      'KQL Hunting – Enables highly flexible and powerful custom detection rules.',
    ],
    usage: 'Continuous monitoring, automated incident response, vulnerability management, and advanced threat hunting using KQL.',
    architecture: [
      'MDE Sensor: Built into Windows 10/11 and available for macOS/Linux, collects and streams telemetry.',
      'Microsoft 365 Defender Cloud: Processes data, runs AIR, and correlates alerts across email, identity, and endpoint.',
      'Advanced Hunting Data Store: Stores raw telemetry accessible via KQL.',
      'Live Response: Allows SOC analysts to remotely connect to the endpoint for manual investigation and command execution.',
    ],
    workflow: [
      'Step 1 – Alert Generation: MDE generates an alert, which triggers an Automated Investigation (AIR).',
      'Step 2 – Automated Investigation: AIR collects evidence, analyzes the attack chain, and attempts to neutralize the threat (e.g., quarantine file).',
      'Step 3 – Analyst Review: L1/L2 analysts review the incident graph in the Microsoft 365 Defender portal and check the AIR status.',
      'Step 4 – Advanced Hunting: If the threat is complex, analysts use KQL in Advanced Hunting to search for related entities (files, IPs) across the entire environment.',
      'Step 5 – Manual Response: Analysts use "Live Response" to manually execute commands, collect forensic artifacts, or apply "Containment" to isolate the host.',
    ],
    icon: Terminal,
    iconColor: 'text-sky-500',
  },
  {
    name: 'Cortex XDR (Palo Alto Networks)',
    purpose: 'Cortex XDR is a unified Extended Detection and Response platform that combines endpoint, network, and cloud telemetry into a single data lake, providing holistic visibility and faster, correlated incident response.',
    keyFeatures: [
      'Unified Data Lake – Ingests and correlates data from endpoints, firewalls (Palo Alto), cloud, and identity sources.',
      'Behavioral Analytics (UEBA) – Detects anomalies in user and entity behavior.',
      'Incident Visualization – Provides a comprehensive, timeline-based view of the entire attack chain.',
      'Cortex XSOAR Integration – Native integration for advanced security orchestration and automated playbooks.',
      'Built-in Endpoint Protection – Includes prevention capabilities alongside detection and response.',
    ],
    advantages: [
      'Holistic Context – Analysts see the full attack story across all domains (endpoint to cloud).',
      'Reduced Alert Fatigue – AI correlation minimizes the number of individual alerts the SOC must handle.',
      'Rapid Response – Enables quick, multi-domain response actions (e.g., block IP on firewall and isolate host).',
      'Scalable Architecture – Cloud-based data lake supports massive data ingestion and hunting.',
    ],
    usage: 'Advanced threat detection, cross-domain investigation, proactive threat hunting, and automated response orchestration.',
    architecture: [
      'Cortex Agents: Installed on endpoints, collecting EDR telemetry.',
      'Palo Alto Network Devices: Firewalls and network sensors feed network traffic logs.',
      'Cortex Data Lake (Cloud): Central repository for all telemetry data, where correlation and analytics occur.',
      'Cortex XDR Console: Unified interface for incident management, hunting, and response actions.',
    ],
    workflow: [
      'Step 1 – Data Ingestion: Agents and network devices stream data to the Cortex Data Lake.',
      'Step 2 – Correlation: XDR analytics correlate endpoint events with network and cloud logs to form a unified incident story.',
      'Step 3 – Triage: Analysts review the correlated incident story, which includes MITRE mapping and root cause analysis.',
      'Step 4 – Investigation & Hunting: Analysts use the built-in query language to hunt for the malicious process or file hash across all correlated data sources.',
      'Step 5 – Response Orchestration: Analysts initiate a response action (e.g., kill process, quarantine file) or trigger a complex, multi-step XSOAR playbook for automated remediation.',
    ],
    icon: Search,
    iconColor: 'text-orange-500',
  },
  {
    name: 'VMware Carbon Black Cloud',
    purpose: 'Carbon Black Cloud is a cloud-native EDR and Next-Gen Antivirus solution that provides continuous endpoint visibility, behavioral detection, and proactive threat hunting capabilities for SOC operations.',
    keyFeatures: [
      'Streaming Prevention – Uses behavioral analysis to stop attacks before they execute.',
      'Continuous Endpoint Visibility – Records all endpoint activity for deep forensic analysis.',
      'Threat Hunting Queries – Allows analysts to search the event stream using custom queries.',
      'Live Response – Provides remote shell access to endpoints for manual investigation and remediation.',
      'Consolidated Cloud Console – Centralized management for all security modules (NGAV, EDR, Audit/Remediation).',
    ],
    advantages: [
      'Real-Time Telemetry – Provides granular data necessary for deep forensics and root-cause analysis.',
      'Cloud-Native Scalability – Easily scales to monitor large enterprise environments.',
      'Proactive Hunting – Enables SOC teams to reduce dwell time by actively searching for threats.',
      'Behavioral Detection – Strong capability against fileless and custom malware.',
    ],
    usage: 'Continuous monitoring, incident response, root-cause analysis, and proactive threat hunting with integration into SIEM/SOAR ecosystems.',
    architecture: [
      'Carbon Black Sensor: Lightweight agent installed on endpoints, continuously streaming data to the cloud.',
      'Carbon Black Cloud: Central platform for data processing, behavioral analysis, and threat intelligence correlation.',
      'Event Stream: The continuous flow of endpoint telemetry data used for real-time detection and hunting.',
      'Live Response Module: Facilitates secure, remote shell access to endpoints for manual intervention.',
    ],
    workflow: [
      'Step 1 – Detection: Carbon Black detects suspicious activity and generates an alert in the cloud console.',
      'Step 2 – Triage: Analysts review the alert and the process chain visualization to understand the attack context.',
      'Step 3 – Investigation: Analysts use custom queries to search the event stream for related activity or the initial access vector.',
      'Step 4 – Manual Response: Analysts use the Live Response feature to connect to the endpoint, gather volatile data, or execute remediation commands (e.g., kill process, delete file).',
      'Step 5 – Containment: If malicious, analysts quarantine the host and blacklist the file hash globally.',
      'Step 6 – Reporting: Generate a report detailing the root cause, the steps taken for eradication, and lessons learned.',
    ],
    icon: Cloud,
    iconColor: 'text-gray-400',
  },
  {
    name: 'LimaCharlie',
    purpose: 'LimaCharlie is a security infrastructure platform offering modular, cloud-native EDR capabilities, focusing on flexibility, low-level visibility, and custom detection rules (D&R) for advanced threat hunting and automation.',
    keyFeatures: [
      'Highly Granular Telemetry – Provides deep visibility into raw endpoint events (processes, network, registry).',
      'Custom Detection & Response (D&R) Rules – Allows analysts to write and deploy highly specific detection logic instantly.',
      'Modular Architecture – Users can enable only the necessary security features (e.g., EDR, network sensor, cloud logs).',
      'Built-in Automation – Strong support for security automation and integration with external tools via APIs.',
      'Artifact Collection – Easy remote collection of forensic artifacts and memory dumps.',
    ],
    advantages: [
      'Extreme Flexibility – Highly customizable for specific use cases and niche threats.',
      'Deep Visibility – Access to low-level data often missed by traditional EDRs.',
      'Cost-Effective – Pay-as-you-go model suitable for smaller teams or specific projects.',
      'Rapid Rule Deployment – Analysts can deploy new detection logic across the fleet instantly.',
      'Community Support – Strong community for sharing custom D&R rules.',
    ],
    usage: 'Advanced threat hunting, building highly specific custom detections, integrating low-level endpoint data into SOAR/SIEM pipelines, and forensic artifact collection.',
    architecture: [
      'LimaCharlie Sensor: Lightweight agent that streams raw endpoint events.',
      'Cloud Platform: Processes and stores the raw telemetry data, runs D&R rules, and manages response modules.',
      'Detection & Response (D&R) Engine: Executes custom rules written in the platform’s query language.',
      'Response Modules: API-driven modules for actions like host isolation, remote command execution, and artifact collection.',
    ],
    workflow: [
      'Step 1 – Custom Detection: A high-fidelity alert triggers based on a custom D&R rule (e.g., suspicious registry modification).',
      'Step 2 – Review Raw Events: Analysts review the raw event stream associated with the detection to understand the context and verify the alert.',
      'Step 3 – Remote Command: Analysts use the `response` module to execute a remote command (e.g., check registry keys or file contents) on the affected host for immediate verification.',
      'Step 4 – Containment: If confirmed malicious, analysts apply a global D&R rule to block the specific behavior across the entire fleet instantly, or isolate the host.',
      'Step 5 – Forensics: Export the raw event data and collect forensic artifacts (e.g., memory dump) for deep, offline analysis.',
    ],
    icon: Settings,
    iconColor: 'text-purple-500',
  },
];

// --- Main Tool Categories Structure ---
export const socToolCategories: ToolCategory[] = [
  { title: 'SIEM Tools', icon: Brain, description: 'Security Information and Event Management platforms for centralized log analysis and alerting.', color: 'text-cyan-400', details: [] },
  { title: 'SOAR Tools', icon: Settings, description: 'Security Orchestration, Automation, and Response platforms for automating incident handling.', color: 'text-indigo-400', details: [] },
  { title: 'EDR Tools', icon: Shield, description: 'Endpoint Detection and Response solutions for monitoring and responding to threats on endpoints.', color: 'text-green-400', details: edrTools },
  { title: 'IDS / IPS Tools', icon: AlertTriangle, description: 'Intrusion Detection and Prevention Systems for monitoring network traffic for malicious activity.', color: 'text-red-400', details: [] },
  { title: 'Firewalls', icon: Flame, description: 'Network security systems that monitor and control incoming and outgoing network traffic.', color: 'text-orange-400', details: [] },
  { title: 'Network Models', icon: Globe, description: 'Conceptual models and frameworks used to understand network architecture and security zones.', color: 'text-blue-400', details: [] },
  { title: 'Frameworks & Standards', icon: BookOpen, description: 'Industry standards and frameworks like MITRE ATT&CK, NIST, and CIS Controls.', color: 'text-yellow-400', details: [] },
];