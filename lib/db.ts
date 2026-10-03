import { Pool, type PoolClient } from 'pg';
import { PGlite } from '@electric-sql/pglite';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

export interface Database {
  query<T extends Record<string, any> = Record<string, any>>(sql: string, params?: unknown[]): Promise<T[]>;
}
type State = {pool?: Pool; embedded?: PGlite; ready?: Promise<void>; tail: Promise<void>};
const globalDb = globalThis as typeof globalThis & {sentinelDb?: State};
const state = globalDb.sentinelDb ??= {tail: Promise.resolve()};
async function initialize() {
  if (process.env.DATABASE_MODE === 'embedded') {
    if (process.env.VERCEL) throw new Error('Embedded database cannot be deployed to Vercel. Configure DATABASE_URL.');
    state.embedded = new PGlite(process.env.TEST_DATABASE === 'true' ? 'memory://' : path.join(process.cwd(), '.data/postgres'));
    await state.embedded.waitReady;
  } else {
    if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required. Run npm run setup for embedded local development.');
    state.pool = new Pool({connectionString: process.env.DATABASE_URL, max: 5});
  }
  const schema = await readFile(path.join(process.cwd(), 'db/schema.sql'), 'utf8');
  if (state.embedded) await state.embedded.exec(schema);
  else { const c = await state.pool!.connect(); try {await c.query('SELECT pg_advisory_lock(733901)'); await c.query(schema);} finally {await c.query('SELECT pg_advisory_unlock(733901)'); c.release();} }
}
async function ready() { await (state.ready ??= initialize()); }
function clientDb(client: PoolClient | PGlite): Database {
  return {async query<T extends Record<string, any>>(sql: string, params: unknown[] = []) {
    if (client instanceof PGlite) return (await client.query<T>(sql, params)).rows;
    return (await client.query(sql, params)).rows as T[];
  }};
}
async function serial<T>(fn: () => Promise<T>): Promise<T> {
  const previous = state.tail; let release!: () => void;
  state.tail = new Promise<void>(resolve => {release = resolve;});
  await previous; try {return await fn();} finally {release();}
}
export const db: Database = {async query<T extends Record<string, any>>(sql: string, params: unknown[] = []) {
  await ready();
  if (state.embedded) return serial(() => clientDb(state.embedded!).query<T>(sql, params));
  return (await state.pool!.query(sql, params)).rows as T[];
}};
export async function transaction<T>(fn: (db: Database) => Promise<T>): Promise<T> {
  await ready();
  if (state.embedded) return serial(async () => {
    await state.embedded!.exec('BEGIN');
    try {const result = await fn(clientDb(state.embedded!)); await state.embedded!.exec('COMMIT'); return result;}
    catch (error) {await state.embedded!.exec('ROLLBACK'); throw error;}
  });
  const client = await state.pool!.connect();
  try {await client.query('BEGIN'); const value = await fn(clientDb(client)); await client.query('COMMIT'); return value;}
  catch (error) {await client.query('ROLLBACK'); throw error;} finally {client.release();}
}
export async function closeDatabase() {if (state.embedded) await state.embedded.close(); if (state.pool) await state.pool.end();}
