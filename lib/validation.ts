import { z } from 'zod';
import { parseDocument } from 'yaml';
import { DEFAULT_POLICY, type Policy } from './types';
import { HttpError } from './security';

export const severity = z.enum(['critical','high','medium','low','info']);
export const policySchema = z.object({
  version: z.literal(1), mode: z.enum(['advisory','enforce']),
  checks: z.array(z.enum(['guardrails','quality','opengrep','gitleaks','trivy','lint','dast'])).min(1).max(7),
  exclusions: z.array(z.string().min(1).max(200)).max(100),
  gate: z.object({severities: z.array(severity), new_only: z.boolean(), rules: z.array(z.string().max(200)).max(100),min_imported_coverage:z.number().min(0).max(100).optional(),max_python_function_complexity:z.number().int().min(1).max(1000).optional()}).strict(),
  architecture: z.array(z.object({from: z.string().max(200), forbidden: z.array(z.string().max(200)).max(50)}).strict()).max(50),
  unsafe_apis: z.array(z.string().max(200)).max(100), compiler_analysis: z.boolean(),
  monitoring: z.object({window_seconds: z.number().int().min(30).max(3600), auth_failure_threshold: z.number().int().min(2).max(1000), denied_threshold: z.number().int().min(2).max(10000)}).strict()
}).strict();
export function parsePolicy(text: string): Policy {
  if (text.length > 30000) throw new HttpError(400, 'Policy is too large.');
  const doc = parseDocument(text, {uniqueKeys: true});
  if (doc.errors.length) throw new HttpError(400, doc.errors[0].message);
  try {return policySchema.parse(doc.toJS({maxAliasCount: 0}));} catch (e) {throw new HttpError(400, e instanceof Error ? e.message : 'Invalid policy');}
}
const relativePath = z.string().max(200).refine(x => !x.includes('..') && !x.startsWith('/') && !x.includes('\\') && !x.includes(':'), 'Use a relative component path without traversal.');
export const targetSchema = z.object({
  url: z.string().url().max(1000).refine(s => {const u = new URL(s); return ['http:','https:'].includes(u.protocol) && !u.username && !u.password && !u.search && !u.hash;}, 'Use an HTTP URL without credentials, query, or fragment.'),
  environment: z.enum(['local','staging']), active: z.boolean().default(false),
  authorized: z.literal(true), exclusions: z.array(z.string().max(300)).max(50).default([]),
  openapi: relativePath.optional(), credential_ref: z.string().regex(/^[A-Z0-9_]{1,80}$/).optional()
  ,credential_type:z.enum(['authorization','cookie']).optional(),verify_path:z.string().max(300).refine(p=>p.startsWith('/')&&!p.startsWith('//')&&!p.includes('..')&&!p.includes('\\')&&!p.includes('?')&&!p.includes('#'),'Use an in-scope absolute path without traversal or query.').optional(),success_marker:z.string().min(1).max(200).optional()
}).strict();
export const projectSchema = z.object({
  name: z.string().trim().min(2).max(100), source_type: z.enum(['local','github']),
  source_ref: z.string().regex(/^[A-Za-z0-9_./-]{1,200}$/),
  github_installation_id: z.number().int().positive().optional(), default_branch: z.string().regex(/^[A-Za-z0-9_./-]{1,120}$/).default('main'),
  components: z.array(z.object({name: z.string().min(1).max(100), root: relativePath, framework: z.string().max(100).optional()}).strict()).max(30).default([]),
  target: targetSchema.nullable().default(null), metadata_only: z.boolean().default(false), ai_enabled: z.boolean().default(false)
}).strict().superRefine((p,ctx) => {
  if (p.source_type === 'local' && !/^[A-Za-z0-9_-]+$/.test(p.source_ref)) ctx.addIssue({code:'custom',message:'Local source must be a registered alias, not a path.'});
  if (p.source_type === 'github' && (!/^[\w.-]+\/[\w.-]+$/.test(p.source_ref) || !p.github_installation_id)) ctx.addIssue({code:'custom',message:'GitHub sources require owner/repo and installation ID.'});
});
export const findingSchema = z.object({
  fingerprint: z.string().min(16).max(200), rule: z.string().max(200), engine: z.string().max(80), engine_version: z.string().max(100),
  severity, confidence: z.enum(['high','medium','low']), category: z.enum(['security','quality','architecture','suspicious']),
  title: z.string().max(500), path: z.string().max(500).optional(), line: z.number().int().positive().optional(), endpoint: targetSchema.shape.url.transform(value=>new URL(value).href).optional(),
  evidence: z.string().max(12000).optional(), impact: z.string().max(5000), remediation: z.string().max(10000),
  source_context:z.string().max(6000).optional(),
  cwe: z.array(z.string().max(50)).max(20).optional(), standards: z.array(z.string().max(100)).max(20).optional(),
  source_revision:z.string().regex(/^[a-f0-9]{40}$/).optional(),
  environment:z.enum(['local','staging']).optional(),
  vulnerability_id:z.string().regex(/^(CVE-\d{4}-\d{4,}|GHSA-[\w-]+)$/).optional(),
  cvss:z.number().min(0).max(10).optional(),
  dependency:z.object({name:z.string().min(1).max(300),version:z.string().max(200),fixed_version:z.string().max(500).optional(),purl:z.string().max(1000).optional(),ecosystem:z.string().max(100).optional()}).strict().optional(),
  patch: z.string().max(20000).optional(), limitation: z.string().max(2000).optional()
}).strict();
export const reportSchema = z.object({
  schema_version: z.literal(1), revision: z.string().min(1).max(200), inventory: z.record(z.string(), z.unknown()),
  metrics: z.record(z.string(),z.unknown()), findings: z.array(findingSchema).max(10000),
  executions: z.array(z.object({engine:z.string().max(80), version:z.string().max(100), status:z.enum(['completed','failed','unavailable','skipped']),
    duration_ms:z.number().int().nonnegative().max(86400000), coverage:z.array(z.string().max(200)).max(100), limitations:z.array(z.string().max(2000)).max(100),
    error:z.string().max(2000).optional(), database_updated_at:z.string().datetime({offset:true}).optional()}).strict()).max(50),
  policy: policySchema.optional()
}).strict();
export async function rawBody(request: Request, max = 2_000_000): Promise<Buffer> {
  const reader = request.body?.getReader(); if (!reader) throw new HttpError(400,'JSON body required.');
  let length = 0; const chunks: Uint8Array[] = [];
  while (true) {const {done,value} = await reader.read(); if (done) break; length += value.length; if (length > max) {await reader.cancel(); throw new HttpError(413,'Request is too large.');} chunks.push(value);}
  return Buffer.concat(chunks);
}
export async function body(request: Request, max = 2_000_000): Promise<any> {
  const bytes=await rawBody(request,max);
  try {return JSON.parse(bytes.toString('utf8'));} catch {throw new HttpError(400,'Invalid JSON.');}
}
export const defaultPolicy = () => structuredClone(DEFAULT_POLICY);
