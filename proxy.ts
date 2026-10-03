import {NextRequest,NextResponse} from 'next/server';
export function proxy(request:NextRequest) {
  const nonce=Buffer.from(crypto.randomUUID()).toString('base64');
  const dev=process.env.NODE_ENV==='development';
  const authOrigin=process.env.NEXT_PUBLIC_SUPABASE_URL ? new URL(process.env.NEXT_PUBLIC_SUPABASE_URL).origin : '';
  const csp=`default-src 'self'; script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev?" 'unsafe-eval'":''}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ${authOrigin}${dev?' ws:':''}; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`;
  const headers=new Headers(request.headers);headers.set('x-nonce',nonce);headers.set('Content-Security-Policy',csp);
  const response=NextResponse.next({request:{headers}});response.headers.set('Content-Security-Policy',csp);
  if(process.env.APP_ORIGIN?.startsWith('https:'))response.headers.set('Strict-Transport-Security','max-age=31536000');
  return response;
}
export const config={matcher:['/((?!_next/static|_next/image|favicon.ico).*)']};
