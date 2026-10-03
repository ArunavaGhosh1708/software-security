"""Create local development credentials without overwriting existing settings."""
from pathlib import Path
import secrets

root = Path(__file__).resolve().parents[1]
target = root / '.env.local'
if target.exists():
    print('.env.local already exists; no credentials changed.')
else:
    text = (root / '.env.example').read_text()
    text = text.replace('LOCAL_PASSWORD=\n', f'LOCAL_PASSWORD={secrets.token_urlsafe(20)}\n')
    text = text.replace('SESSION_SECRET=\n', f'SESSION_SECRET={secrets.token_hex(32)}\n')
    target.write_text(text)
    print('Created .env.local. Read LOCAL_PASSWORD there to sign in. Keep this file private.')
