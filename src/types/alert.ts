export interface AlertPlaybook {
  id: string;
  name: string;
  category: 'Authentication & Access' | 'Network & Firewall' | 'Endpoint & Malware' | 'Email & Phishing' | 'Cloud Security' | 'Data & Insider Threat' | 'Threat Intelligence & External' | 'SIEM & System Alerts' | 'Incident Response / Automation Triggers' | 'SOC Frameworks & Core Security Tools';
  description: string;
  causes: string[];
  actions: string[];
  queries: { tool: string; query: string }[];
  tools: string[];
  escalation: string;
}

export type AlertCategory = AlertPlaybook['category'];