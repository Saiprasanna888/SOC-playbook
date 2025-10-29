import { AlertTriangle, BookOpen, Brain, Cloud, Database, Flame, Globe, Mail, Search, Settings, Shield, Terminal, User, Zap } from 'lucide-react';
import React from 'react';

export interface ToolDetail {
  name: string;
  purpose: string;
  keyFeatures: string[];
  advantages: string[];
  usageInSOC: string;
  conceptualWorkflow: string[];
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
    purpose: 'CrowdStrike Falcon is a leading EDR + Threat Intelligence platform used by most SOCs worldwide. It detects malicious activity in real time, enables deep forensic investigation, and allows analysts to isolate or remediate endpoints instantly.',
    keyFeatures: [
      'Continuous endpoint telemetry for processes, connections, and files',
      'AI-driven real-time alerting',
      'Falcon Query Language (FQL) for threat hunting',
      'Native SIEM/SOAR integration',
      'Automated playbooks (isolate host, kill process)',
    ],
    advantages: [
      'Rapid detection & response (MTTD / MTTR reduction)',
      'Full visibility into endpoint activity timeline',
      'Global Threat Intel enrichment',
      'Scalable cloud architecture for large SOCs',
    ],
    usageInSOC: 'Incident detection, forensic investigation, proactive threat hunting, and automated response via Falcon Console or SIEM.',
    conceptualWorkflow: [
      'Step 1: Receive alert notification from SIEM/Falcon Console.',
      'Step 2: Review the "Detection Details" timeline to understand the attack chain.',
      'Step 3: Use FQL to search for related activity across other endpoints (Threat Hunting).',
      'Step 4: Initiate "Host Isolation" via the console.',
      'Step 5: Remotely collect forensic artifacts (e.g., memory dump) for deep analysis.',
    ],
    icon: Shield,
    iconColor: 'text-green-500',
  },
  {
    name: 'SentinelOne Singularity',
    purpose: 'An AI-powered EDR/XDR that autonomously detects and responds to fileless, zero-day, and ransomware attacks without human intervention.',
    keyFeatures: [
      'Behavioral AI detection & ActiveEDR storyline',
      'Automated remediation and Windows rollback',
      'Deep Visibility threat hunting console',
      'XDR data correlation across endpoint, network, cloud',
    ],
    advantages: [
      'Autonomous response reduces analyst load',
      'Storyline correlation minimizes alert fatigue',
      'High accuracy AI models',
      'Fast root-cause analysis with MITRE mapping',
    ],
    usageInSOC: 'For prevention, real-time detection, automated containment, and threat hunting with SIEM/SOAR integration.',
    conceptualWorkflow: [
      'Step 1: Alert triggers, and the tool automatically initiates "Storyline Remediation" (e.g., killing processes, rolling back files).',
      'Step 2: Analyst reviews the "ActiveEDR Storyline" to validate the autonomous actions.',
      'Step 3: If necessary, use the Deep Visibility console to search for the initial infection vector.',
      'Step 4: Confirm the threat is eradicated and release the host from quarantine.',
      'Step 5: Document the incident and the success of the automated rollback feature.',
    ],
    icon: Zap,
    iconColor: 'text-indigo-500',
  },
  {
    name: 'Microsoft Defender for Endpoint (MDE)',
    purpose: 'MDE is an enterprise-grade EDR and EPP solution that integrates deeply with Microsoft 365 and Azure Sentinel for centralized SOC operations.',
    keyFeatures: [
      'Next-Gen AV with cloud AI protection',
      'Attack Surface Reduction (ASR) policies',
      'Threat & Vulnerability Management (TVM)',
      'Automated Investigation & Remediation (AIR)',
      'KQL-based threat hunting',
    ],
    advantages: [
      'Native Microsoft ecosystem integration',
      'Real-time endpoint telemetry & AI detection',
      'Cross-platform coverage (Windows, macOS, Linux, mobile)',
      'Auto-remediation reduces manual effort',
    ],
    usageInSOC: 'Used for continuous monitoring, threat hunting with KQL, automated response, and vulnerability management.',
    conceptualWorkflow: [
      'Step 1: Review the incident graph in the Microsoft 365 Defender portal.',
      'Step 2: Check the "Automated Investigation & Remediation (AIR)" status to see if the threat was neutralized.',
      'Step 3: Use KQL (Kusto Query Language) in Advanced Hunting to search for related entities (files, IPs).',
      'Step 4: Apply "Live Response" to the endpoint to manually execute commands or collect files.',
      'Step 5: If necessary, use the "Containment" feature to isolate the host from the network.',
    ],
    icon: Terminal,
    iconColor: 'text-sky-500',
  },
  {
    name: 'Cortex XDR (Palo Alto Networks)',
    purpose: 'A unified XDR platform combining endpoint, network, and cloud telemetry to provide holistic SOC visibility and faster response.',
    keyFeatures: [
      'Unified data correlation across multiple sources',
      'Behavioral analytics with UEBA',
      'Built-in endpoint protection',
      'Timeline-based incident visualization',
      'Tight SOAR integration via Cortex XSOAR',
    ],
    advantages: [
      'Complete attack context in one console',
      'AI reduces false positives',
      'Scalable cloud data lake architecture',
      'Rapid automated response playbooks',
    ],
    usageInSOC: 'Advanced threat detection, investigation, and hunting across endpoint, network, and cloud infrastructure.',
    conceptualWorkflow: [
      'Step 1: Review the incident alert and the correlated XDR story in the console.',
      'Step 2: Use the built-in query language to hunt for the malicious process or file hash across all endpoints and network logs.',
      'Step 3: Initiate a response action (e.g., kill process, quarantine file) via the XDR console.',
      'Step 4: If the threat is complex, trigger a Cortex XSOAR playbook for multi-step automated remediation.',
      'Step 5: Document the incident and update the behavioral analytics model if a new TTP was observed.',
    ],
    icon: Search,
    iconColor: 'text-orange-500',
  },
  {
    name: 'VMware Carbon Black Cloud',
    purpose: 'A cloud-native EDR and Next-Gen Antivirus that provides continuous endpoint visibility and behavioral detection for SOC operations.',
    keyFeatures: [
      'Streaming prevention & detection engine',
      'Behavioral heuristics for fileless attacks',
      'Central cloud console for alerting and response',
      'Advanced threat hunting queries',
      'Integration with SIEM/SOAR ecosystems',
    ],
    advantages: [
      'Real-time telemetry for deep forensics',
      'Cloud-native scalability for large enterprises',
      'Proactive hunting reduces dwell time',
      'Strong behavioral detection accuracy',
    ],
    usageInSOC: 'Continuous monitoring, incident response, root-cause analysis, and threat hunting with SOC-tool integration.',
    conceptualWorkflow: [
      'Step 1: Review the alert and the process chain visualization in the Carbon Black console.',
      'Step 2: Use the Live Response feature to connect to the endpoint and gather volatile data or execute commands.',
      'Step 3: Search the event stream using custom queries to identify the initial access vector.',
      'Step 4: If malicious, quarantine the host and blacklist the file hash globally.',
      'Step 5: Generate a report detailing the root cause and the steps taken for eradication.',
    ],
    icon: Cloud,
    iconColor: 'text-gray-400',
  },
  {
    name: 'LimaCharlie',
    purpose: 'A security infrastructure platform offering modular, cloud-native EDR capabilities, focusing on flexibility, low-level visibility, and custom detection rules (D&R).',
    keyFeatures: [
      'Highly granular endpoint telemetry for processes, network, and registry events.',
      'Custom Detection & Response (D&R) rules using a powerful query language.',
      'Modular architecture allowing users to enable only needed features (e.g., only EDR, only network sensor).',
      'Built-in support for security automation and integration with external tools.',
    ],
    advantages: [
      'Extreme flexibility and customization for specific use cases.',
      'Deep visibility into raw endpoint events (low-level data).',
      'Cost-effective for specific use cases and smaller teams.',
      'Strong community support for custom rules and integrations.',
    ],
    usageInSOC: 'Used primarily for advanced threat hunting, building highly specific custom detections, and integrating low-level endpoint data into SOAR/SIEM pipelines.',
    conceptualWorkflow: [
      'Step 1: Receive a high-fidelity alert based on a custom D&R rule (e.g., suspicious registry modification).',
      'Step 2: Review the raw event stream associated with the detection to understand the context.',
      'Step 3: Use the `response` module to execute a remote command (e.g., check registry keys or file contents) on the affected host.',
      'Step 4: If confirmed malicious, apply a global D&R rule to block the specific behavior across the entire fleet instantly.',
      'Step 5: Export the raw event data for offline forensic analysis if required.',
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