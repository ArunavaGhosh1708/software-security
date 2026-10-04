import {test} from 'node:test';
import assert from 'node:assert/strict';
import {postgresConnectionString, postgresPoolConfig} from '../lib/db';

test('Supabase integration connection works without DATABASE_URL', () => {
  const integrated = 'postgres://test:fixture@localhost:5432/sentinel?sslmode=require';
  assert.equal(postgresConnectionString({POSTGRES_URL:integrated}), integrated);
  assert.equal(postgresConnectionString({DATABASE_URL:'  ', POSTGRES_URL:integrated}), integrated);
});

test('an explicit database connection overrides the integration connection', () => {
  const explicit = 'postgres://test:fixture@localhost:5433/isolated';
  assert.equal(postgresConnectionString({DATABASE_URL:explicit, POSTGRES_URL:'postgres://localhost:5432/default'}), explicit);
});

test('missing database configuration names both supported variables without revealing credentials', () => {
  assert.throws(() => postgresConnectionString({DATABASE_URL:' ', POSTGRES_URL:''}), /DATABASE_URL or POSTGRES_URL is required/);
});

test('a supplied CA cannot be replaced by SSL query parameters from the integration', () => {
  const config = postgresPoolConfig({POSTGRES_URL:'postgres://test:fixture@localhost:6543/sentinel?sslmode=require&sslcert=other&sslrootcert=other&application_name=sentinel', DATABASE_SSL_CA:'certificate\\nfixture'});
  const url = new URL(config.connectionString!);
  assert.equal(url.searchParams.has('sslmode'), false);
  assert.equal(url.searchParams.has('sslcert'), false);
  assert.equal(url.searchParams.has('sslrootcert'), false);
  assert.equal(url.searchParams.get('application_name'), 'sentinel');
  assert.deepEqual(config.ssl, {ca:'certificate\nfixture', rejectUnauthorized:true});
  assert.equal(config.connectionTimeoutMillis, 10000);
});

test('connections without a custom CA preserve their SSL connection options', () => {
  const connectionString = 'postgres://localhost:6543/sentinel?sslmode=verify-full';
  const config = postgresPoolConfig({DATABASE_URL:connectionString});
  assert.equal(config.connectionString, connectionString);
  assert.equal(config.ssl, undefined);
});
