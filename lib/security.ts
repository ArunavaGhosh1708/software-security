import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import { db, transaction, type Database } from './db';
import type { Role } from './types';

export class HttpError extends Error {constructor(public status: number, message: string) {super(message);}}
export function check(condition: unknown, status: number, message: string): asserts condition {if (!condition) throw new HttpError(status, message);}
export const hashToken = (token: string) => createHash('sha256').update(token).digest('hex');
export function equal(a: string, b: string) {const aa = Buffer.from(a), bb = Buffer.from(b); return aa.length === bb.length && timingSafeEqual(aa, bb);}
export function redact(text: string): string {
  return text.replace(/-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----/g,'[REDACTED PRIVATE KEY]').replace(/(?:gh[pousr]_[A-Za-z0-9]{15,}|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9_-]{16,})/g, '[REDACTED]')
    .replace(/((?:authorization|proxy-authorization)["']?\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\r\n]+)/gi, '$1[REDACTED]')
    .replace(/eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}/g, '[REDACTED JWT]')
    .replace(/((?:password|passwd|secret|credential|api[_-]?key|token|authorization|cookie)["']?\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s,;}]+)/gi, '$1[REDACTED]')
    .replace(/([a-z][a-z0-9+.-]{1,20}:\/\/)[^\s/@:]+:[^\s/@]+@/gi, '$1[REDACTED]@')
    .replace(/Bearer\s+[\w.\-]+/gi, 'Bearer [REDACTED]').slice(0, 12000);
}
export function actorHash(actor: string, org: string) {
  check(process.env.SESSION_SECRET && process.env.SESSION_SECRET.length >= 32, 503, 'SESSION_SECRET must have at least 32 characters.');
  return createHmac('sha256', process.env.SESSION_SECRET).update(`${org}:${actor}`).digest('hex').slice(0, 24);
}
function sessionKey() {const key = process.env.SESSION_SECRET; check(key && key.length >= 32, 503, 'Configure SESSION_SECRET.'); return new TextEncoder().encode(key);}
export function localAuthAllowed() {return process.env.LOCAL_AUTH === 'true' && !process.env.VERCEL && process.env.NODE_ENV !== 'production';}
export async function signSession(user: string) {return new SignJWT({}).setProtectedHeader({alg: 'HS256'}).setSubject(user).setIssuer('sentinel-local').setAudience('sentinel').setIssuedAt().setExpirationTime('8h').sign(sessionKey());}
async function userId(request: Request) {
  const token = request.headers.get('authorization')?.match(/^Bearer (.+)$/)?.[1];
  const cookie = request.headers.get('cookie')?.split(';').map(x => x.trim()).find(x => x.startsWith('sentinel-session='))?.split('=').slice(1).join('=');
  // An explicitly supplied OAuth identity takes precedence over an old local cookie.
  if (!token && cookie && localAuthAllowed()) {
    try {return (await jwtVerify(cookie, sessionKey(), {issuer: 'sentinel-local', audience: 'sentinel', algorithms: ['HS256']})).payload.sub!;} catch {throw new HttpError(401, 'Session expired. Sign in again.');}
  }
  check(token, 401, 'Sign in to continue.');
  const url = process.env.SUPABASE_URL, key = process.env.SUPABASE_ANON_KEY;
  check(url && key, 503, 'Supabase authentication is not configured.');
  const response = await fetch(`${url}/auth/v1/user`, {headers: {authorization: `Bearer ${token}`, apikey: key}, signal: AbortSignal.timeout(10000)});
  check(response.ok, 401, 'Invalid or expired session.');
  const user = await response.json(); check(typeof user.id === 'string', 401, 'Invalid identity.'); return user.id as string;
}
export async function verifiedEmail(request:Request,user:string) {
  const token=request.headers.get('authorization')?.match(/^Bearer (.+)$/)?.[1];
  check(token&&process.env.SUPABASE_URL&&process.env.SUPABASE_ANON_KEY,403,'Invitations require a verified Supabase email identity.');
  const response=await fetch(`${process.env.SUPABASE_URL}/auth/v1/user`,{headers:{authorization:`Bearer ${token}`,apikey:process.env.SUPABASE_ANON_KEY},redirect:'error',signal:AbortSignal.timeout(10000)});
  check(response.ok,401,'Identity verification failed.');const identity=await response.json();
  check(identity.id===user&&typeof identity.email==='string'&&identity.email_confirmed_at,403,'Verify your email before accepting a workspace invitation.');
  return identity.email.trim().toLowerCase() as string;
}
export interface Session {user: string; org: string; role: Role}
export async function session(request: Request): Promise<Session> {
  const user = await userId(request);
  const requested = request.headers.get('x-organization-id');
  const memberships = await db.query('SELECT organization_id,role FROM memberships WHERE user_id=$1 ORDER BY organization_id', [user]);
  if (!memberships.length && !requested) {
    await transaction(async t => {
      await t.query('SELECT pg_advisory_xact_lock(hashtext($1))', [user]);
      const existing = await t.query('SELECT 1 FROM memberships WHERE user_id=$1', [user]);
      if (!existing.length) {const org = randomUUID(); await t.query('INSERT INTO organizations(id,name) VALUES($1,$2)', [org, 'My workspace']); await t.query('INSERT INTO memberships VALUES($1,$2,$3)', [org,user,'owner']);}
    });
    return session(request);
  }
  const member = requested ? memberships.find(m => m.organization_id === requested) : memberships[0];
  check(member, 403, 'Organization access denied.');
  return {user, org: member.organization_id, role: member.role};
}
export function canWrite(s: Session) {check(s.role !== 'viewer', 403, 'Maintainer access required.');}
export function canOwn(s: Session) {check(s.role === 'owner', 403, 'Owner access required.');}
export function verifyOrigin(request: Request) {
  const origin = request.headers.get('origin');
  if (request.headers.get('cookie')?.includes('sentinel-session=')) check(origin === process.env.APP_ORIGIN, 403, 'Request origin rejected.');
}
export async function rateLimit(key: string, limit: number, seconds = 60) {
  const rows = await db.query(`INSERT INTO rate_limits(key,count,resets_at) VALUES($1,1,now()+$2*interval '1 second')
    ON CONFLICT(key) DO UPDATE SET count=CASE WHEN rate_limits.resets_at<now() THEN 1 ELSE rate_limits.count+1 END,
    resets_at=CASE WHEN rate_limits.resets_at<now() THEN now()+$2*interval '1 second' ELSE rate_limits.resets_at END RETURNING count`, [key,seconds]);
  check(rows[0].count <= limit, 429, 'Rate limit reached. Try again shortly.');
}
export async function runnerAuth(request: Request) {
  const token = request.headers.get('authorization')?.match(/^Bearer (sgr_[A-Za-z0-9_-]+)$/)?.[1];
  check(token, 401, 'Runner credential required.');
  const rows = await db.query('SELECT * FROM runners WHERE token_hash=$1 AND revoked_at IS NULL', [hashToken(token)]);
  check(rows.length, 401, 'Runner credential invalid or revoked.');
  await db.query('UPDATE runners SET last_seen=now() WHERE id=$1', [rows[0].id]);
  return rows[0];
}
export async function audit(s: {org: string; user: string}, action: string, resource?: string, t: Database = db) {
  await t.query('INSERT INTO audit_events(id,organization_id,actor,action,resource) VALUES($1,$2,$3,$4,$5)', [randomUUID(),s.org,s.user,action,resource ?? null]);
}
