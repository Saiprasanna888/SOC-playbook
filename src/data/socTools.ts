import { AlertTriangle, BookOpen, Brain, Cloud, Database, Flame, Globe, Mail, Search, Settings, Shield, Terminal, User, Zap } from 'lucide-react';
import React from 'react';

export interface ToolDetail {
  name: string;
  purpose: string;
  keyFeatures: string[];
  advantages: string[];
  usageInSOC: string;
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
    icon: Cloud,
    iconColor: 'text-gray-400',
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