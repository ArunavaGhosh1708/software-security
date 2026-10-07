import {randomBytes,randomUUID} from 'node:crypto';
import {z} from 'zod';
import {db,transaction} from './db';
import {audit,canOwn,check,hashToken,rateLimit,verifiedEmail,type Session} from './security';
import {body} from './validation';
const json=(data:unknown,status=200)=>Response.json(data,{status,headers:{'Cache-Control':'no-store'}});
export async function acceptInvitation(s:Session,token:string,email:string) {
  return transaction(async t=>{
    const rows=await t.query('SELECT * FROM invitations WHERE token_hash=$1 AND revoked_at IS NULL AND accepted_at IS NULL AND expires_at>now() FOR UPDATE',[hashToken(token)]);
    check(rows.length&&rows[0].email===email,404,'Invitation unavailable for this verified email.');const invitation=rows[0];
    // An invitation cannot downgrade an existing owner or maintainer.
    await t.query('INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',[invitation.organization_id,s.user,invitation.role]);
    await t.query('UPDATE invitations SET accepted_at=now(),accepted_by=$1 WHERE id=$2',[s.user,invitation.id]);
    await audit({org:invitation.organization_id,user:s.user},'invitation.accepted',invitation.id,t);
    return {organization_id:invitation.organization_id};
  });
}
export async function invitationsApi(request:Request,path:string[],s:Session):Promise<Response|null> {
  if(path[0]!=='invitations')return null;
  if(path.length===1&&request.method==='GET') {
    canOwn(s);return json(await db.query('SELECT id,email,role,expires_at,accepted_at,revoked_at FROM invitations WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100',[s.org]));
  }
  if(path.length===1&&request.method==='POST') {
    canOwn(s);await rateLimit(`invitations:${s.org}`,20,3600);
    const b=z.object({email:z.string().email().max(254).transform(x=>x.trim().toLowerCase()),role:z.enum(['maintainer','viewer'])}).strict().parse(await body(request,1000));
    const token='sit_'+randomBytes(32).toString('base64url'),id=randomUUID();
    await db.query(`INSERT INTO invitations(id,organization_id,email,role,token_hash,created_by,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+interval '7 days')`,[id,s.org,b.email,b.role,hashToken(token),s.user]);
    await audit(s,'invitation.created',id);return json({id,token,expires_in_days:7,message:'Share privately with this email address. No email has been sent.'},201);
  }
  if(path.length===2&&path[1]==='accept'&&request.method==='POST') {
    const b=z.object({token:z.string().regex(/^sit_[A-Za-z0-9_-]{43}$/)}).strict().parse(await body(request,1000));
    await rateLimit(`invitation-accept:${s.user}`,20,3600);
    return json(await acceptInvitation(s,b.token,await verifiedEmail(request,s.user)));
  }
  if(path.length===2&&request.method==='DELETE') {
    canOwn(s);const id=z.string().uuid().parse(path[1]);
    const rows=await db.query('UPDATE invitations SET revoked_at=now() WHERE id=$1 AND organization_id=$2 AND accepted_at IS NULL RETURNING id',[id,s.org]);
    check(rows.length,404,'Pending invitation not found.');await audit(s,'invitation.revoked',id);return json({revoked:true});
  }
  return null;
}
