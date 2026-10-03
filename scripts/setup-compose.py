"""Generate credentials for the minimal Supabase Auth + PostgreSQL Compose profile."""
import base64
import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path
root=Path(__file__).resolve().parents[1]
env=root/'.env.compose'
if env.exists():raise SystemExit('.env.compose already exists; no credentials changed.')
secret=secrets.token_hex(32);password=secrets.token_hex(24)
def jwt(role):
    encode=lambda x:base64.urlsafe_b64encode(x).rstrip(b'=')
    header=encode(json.dumps({'alg':'HS256','typ':'JWT'}).encode())
    payload=encode(json.dumps({'role':role,'iss':'supabase','iat':int(time.time()),'exp':int(time.time())+315360000}).encode())
    token=header+b'.'+payload
    return (token+b'.'+encode(hmac.new(secret.encode(),token,hashlib.sha256).digest())).decode()
anon=jwt('anon')
env.write_text(f'POSTGRES_PASSWORD={password}\nJWT_SECRET={secret}\nANON_KEY={anon}\n')
generated=root/'.env.supabase.local'
generated.write_text(f'DATABASE_MODE=postgres\nDATABASE_URL=postgres://postgres:{password}@127.0.0.1:15432/sentinel\nLOCAL_AUTH=false\nSESSION_SECRET={secrets.token_hex(32)}\nAPP_ORIGIN=http://127.0.0.1:3000\nSUPABASE_URL=http://127.0.0.1:8000\nSUPABASE_ANON_KEY={anon}\nNEXT_PUBLIC_SUPABASE_URL=http://127.0.0.1:8000\nNEXT_PUBLIC_SUPABASE_ANON_KEY={anon}\n')
print('Generated .env.compose and .env.supabase.local. See README for selecting this profile.')
