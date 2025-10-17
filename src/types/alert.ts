export interface AlertPlaybook {
  id: string;
  name: string;
  category: 'Authentication' | 'Network' | 'Endpoint' | 'Data Security' | 'Cloud' | 'Other';
  description: string;
  causes: string[];
  actions: string[];
  queries: { tool: string; query: string }[];
  tools: string[];
  escalation: string;
}

export type AlertCategory = AlertPlaybook['category'];