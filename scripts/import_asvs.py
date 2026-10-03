"""Import the upstream v5.0.0 requirement catalog with attribution; no invented IDs."""
import hashlib
import json
import re
from pathlib import Path
import requests
FILES=[
 '0x10-V1-Encoding-and-Sanitization.md','0x11-V2-Validation-and-Business-Logic.md',
 '0x12-V3-Web-Frontend-Security.md','0x13-V4-API-and-Web-Service.md','0x14-V5-File-Handling.md',
 '0x15-V6-Authentication.md','0x16-V7-Session-Management.md','0x17-V8-Authorization.md',
 '0x18-V9-Self-contained-Tokens.md','0x19-V10-OAuth-and-OIDC.md','0x20-V11-Cryptography.md',
 '0x21-V12-Secure-Communication.md','0x22-V13-Configuration.md','0x23-V14-Data-Protection.md',
 '0x24-V15-Secure-Coding-and-Architecture.md','0x25-V16-Security-Logging-and-Error-Handling.md','0x26-V17-WebRTC.md']
root=Path(__file__).resolve().parents[1];requirements=[];provenance=[]
for filename in FILES:
    url='https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/'+filename
    response=requests.get(url,timeout=30);response.raise_for_status();text=response.text
    title=re.search(r'^#\s+(.+)',text,re.M).group(1).strip()
    provenance.append({'url':url,'sha256':hashlib.sha256(response.content).hexdigest()})
    for line in text.splitlines():
        cells=[s.strip() for s in line.strip().strip('|').split('|')]
        if len(cells)<3:continue
        match=re.fullmatch(r'\*?\*?(\d+\.\d+\.\d+)\*?\*?',cells[0])
        if match:requirements.append({'id':match.group(1),'chapter':title,'description':cells[1],
          'level':cells[2],'source':url})
if len(requirements)<300:raise SystemExit('Unexpected upstream format; catalog not written.')
data={'version':'5.0.0','attribution':'OWASP Application Security Verification Standard, OWASP Foundation and contributors',
 'license':'CC-BY-SA-4.0','license_url':'https://creativecommons.org/licenses/by-sa/4.0/',
 'source':'https://github.com/OWASP/ASVS/tree/v5.0.0','provenance':provenance,'requirements':requirements}
out=root/'data';out.mkdir(exist_ok=True);(out/'asvs-5.0.json').write_text(json.dumps(data,indent=2,ensure_ascii=False),encoding='utf-8')
print(f'Imported {len(requirements)} ASVS requirements with source hashes and attribution.')
