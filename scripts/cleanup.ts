import {loadEnvConfig} from '@next/env';
loadEnvConfig(process.cwd());
const {closeDatabase}=await import('../lib/db');
const {cleanup}=await import('../lib/retention');
await cleanup(true);
console.log('Retention cleanup completed.');await closeDatabase();
