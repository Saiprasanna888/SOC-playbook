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
  dailyLifeExample: string;
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
      'Step 1 – Data Collection: Falcon sensors record everything happening on the computer (processes, files, network) and send this data to the cloud in real time.',
      'Step 2 – Detection: The system\'s AI analyzes the data and flags suspicious actions, creating an alert for the security team.',
      'Step 3 – Triage: A Level 1 analyst quickly checks the alert to confirm if it\'s a real threat or a false alarm.',
      'Step 4 – Investigation: A Level 2 analyst reviews the full timeline of events (the "video recording") to understand exactly how the attack started and what the attacker did.',
      'Step 5 – Response: The analyst remotely isolates the infected computer from the network and kills the malicious program to stop the attack from spreading.',
      'Step 6 – Threat Hunting & Intelligence: Security experts actively search the data for hidden threats that haven\'t triggered an alarm yet.',
    ],
    dailyLifeExample: 'CrowdStrike is like a high-tech security system in a large office building. It records everything, instantly alerts the security guard (analyst) if a window is broken, and allows the guard to remotely lock down the floor where the breach occurred.',
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
      'Step 1 – Detection & Autonomous Response: The system detects a threat and immediately starts fixing it automatically (killing the bad program, cleaning files).',
      'Step 2 – Triage & Validation: Analysts check the "Storyline" to confirm the threat was real and see exactly how the attack unfolded.',
      'Step 3 – Investigation & Rollback: If files were encrypted or damaged, the analyst uses the rollback feature to restore the computer to its state before the attack.',
      'Step 4 – Scope Check: Analysts search the data to ensure no other computers were affected by the same threat.',
      'Step 5 – Remediation Confirmation: The analyst confirms the threat is gone and releases the computer from quarantine.',
    ],
    dailyLifeExample: 'SentinelOne is like a self-healing computer. If a virus tries to delete your files, the system instantly stops the virus, deletes it, and then uses a backup snapshot to restore all your files automatically, all before you even notice a problem.',
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
      'Step 1 – Alert Generation & Auto-Investigate: An alert is generated, and the system\'s AI immediately starts collecting evidence and attempting to neutralize the threat (AIR).',
      'Step 2 – Analyst Review: Analysts check the incident graph to see what the AI found and if it successfully neutralized the threat.',
      'Step 3 – Deep Search: If the threat is complex, analysts use KQL (a powerful search language) to hunt for specific files or IPs across all Microsoft data (email, identity, endpoint).',
      'Step 4 – Manual Response: Analysts use "Live Response" to remotely connect to the computer and run manual commands to gather more evidence or clean up.',
      'Step 5 – Containment: The analyst isolates the host if the automated steps were not enough to stop the threat.',
    ],
    dailyLifeExample: 'MDE is like having a smart assistant integrated into your entire digital life (email, phone, computer). If a suspicious email arrives, the assistant automatically checks your computer activity and locks down the suspicious file, then gives the security team a full report on what happened.',
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
      'Step 1 – Unified Data Ingestion: The system collects data from the computer, the network firewall, and the cloud, sending it all to one central data lake.',
      'Step 2 – Correlation: XDR stitches all the data together into one single attack timeline, showing the full story.',
      'Step 3 – Triage & Review: Analysts review the single, correlated incident story, which clearly shows the root cause and attack steps.',
      'Step 4 – Cross-Domain Response: The analyst triggers a response that affects multiple systems (e.g., isolate the computer AND block the attacker\'s IP on the firewall automatically).',
      'Step 5 – Documentation: The full, unified story is saved for reporting and future training.',
    ],
    dailyLifeExample: 'Cortex XDR is like a central command center for a city\'s security. It combines data from traffic cameras (network), police body cams (endpoint), and building access logs (cloud) to create one complete, minute-by-minute report of a crime, allowing the chief to coordinate police, fire, and traffic response simultaneously.',
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
    usage: 'Continuous monitoring, incident response, root-cause analysis, and proactive threat hunting with SOC-tool integration.',
    architecture: [
      'Carbon Black Sensor: Lightweight agent installed on endpoints, continuously streaming data to the cloud.',
      'Carbon Black Cloud: Central platform for data processing, behavioral analysis, and threat intelligence correlation.',
      'Event Stream: The continuous flow of endpoint telemetry data used for real-time detection and hunting.',
      'Live Response Module: Facilitates secure, remote shell access to endpoints for manual intervention.',
    ],
    workflow: [
      'Step 1 – Detection & Alert: Carbon Black detects suspicious activity and generates an alert, along with a visual process chain.',
      'Step 2 – Triage & Review: Analysts review the alert and the visual process chain to understand the attack context.',
      'Step 3 – Investigation: Analysts use custom queries to search the continuous stream of endpoint events for the initial point of entry or related activity.',
      'Step 4 – Manual Response: Analysts use the "Live Response" feature to securely connect to the infected computer and run manual commands (like checking a specific file).',
      'Step 5 – Containment: If malicious, the analyst quarantines the host and globally blocks the malicious file across all computers.',
      'Step 6 – Reporting: A detailed report is generated, focusing on the forensic evidence gathered from the endpoint.',
    ],
    dailyLifeExample: 'Carbon Black is like a security guard who constantly watches every door and window (endpoint activity). If a suspicious person enters, the guard can instantly connect to the room\'s intercom (Live Response) to ask questions or lock the door, and they have a perfect record of every step the person took inside.',
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
      'Step 1 – Custom Detection: A very specific alert triggers based on a rule the analyst wrote (e.g., "Alert if Notepad tries to access the password file").',
      'Step 2 – Review Raw Events: Analysts look at the raw, low-level event data to confirm the context of the alert.',
      'Step 3 – Remote Verification: Analysts use a remote command to check the affected computer for immediate verification (e.g., "Show me the contents of that suspicious file").',
      'Step 4 – Global Response: If confirmed malicious, the analyst instantly deploys a new rule to block that specific behavior across all computers, or isolates the host.',
      'Step 5 – Forensics: The analyst exports the raw event data and collects forensic artifacts (like a memory dump) for deep, offline analysis.',
    ],
    dailyLifeExample: 'LimaCharlie is like a customizable smart home security system. Instead of relying on pre-set alarms, you can write your own rules (e.g., "If the kitchen light turns on AND the front door opens, sound the siren"). This allows for extremely precise and rapid responses to unique situations.',
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