import {loadEnvConfig} from '@next/env';
loadEnvConfig(process.cwd());
const {db,closeDatabase}=await import('../lib/db');
console.log(await db.query('SELECT version,applied_at FROM schema_versions'));
await closeDatabase();
