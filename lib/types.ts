export type Gate = 'pass' | 'fail' | 'incomplete';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Role = 'owner' | 'maintainer' | 'viewer';
export type FindingStatus = 'open' | 'confirmed' | 'false_positive' | 'accepted' | 'resolved';
export interface FindingInput {
  fingerprint: string; rule: string; engine: string; engine_version: string;
  severity: Severity; confidence: 'high' | 'medium' | 'low';
  category: 'security' | 'quality' | 'architecture' | 'suspicious';
  title: string; path?: string; line?: number; endpoint?: string;
  evidence?: string; impact: string; remediation: string; cwe?: string[];
  standards?: string[]; patch?: string; limitation?: string; source_revision?: string; environment?: 'local'|'staging';
  dependency?: {name:string;version:string;fixed_version?:string;purl?:string;ecosystem?:string};
  vulnerability_id?:string; cvss?:number;
}
export interface ExecutionInput {
  engine: string; version: string; status: 'completed' | 'unavailable' | 'failed' | 'skipped';
  duration_ms: number; coverage: string[]; limitations: string[]; error?: string;
  database_updated_at?: string;
}
export interface ScanReport {
  schema_version: 1; revision: string; inventory: Record<string, unknown>;
  findings: FindingInput[]; executions: ExecutionInput[];
  metrics: Record<string, unknown>; policy?: Policy;
}
export interface Policy {
  version: 1; mode: 'advisory' | 'enforce';
  checks: string[]; exclusions: string[];
  gate: {severities: Severity[]; new_only: boolean; rules: string[]};
  architecture: {from: string; forbidden: string[]}[];
  unsafe_apis: string[]; compiler_analysis: boolean;
  monitoring: {window_seconds: number; auth_failure_threshold: number; denied_threshold: number};
}
export const DEFAULT_POLICY: Policy = {
  version: 1, mode: 'advisory',
  checks: ['guardrails', 'quality', 'opengrep', 'gitleaks', 'trivy', 'lint'],
  exclusions: ['node_modules/**', '.git/**', 'dist/**', 'vendor/**', '.next/**'],
  gate: {severities: ['critical', 'high'], new_only: true, rules: []},
  architecture: [], unsafe_apis: [], compiler_analysis: false,
  monitoring: {window_seconds: 300, auth_failure_threshold: 10, denied_threshold: 30}
};
