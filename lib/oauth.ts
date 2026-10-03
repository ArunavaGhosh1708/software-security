// Never use callback query parameters as navigation destinations.
export const OAUTH_CALLBACK_PATH='/auth/callback';
export const AUTHENTICATED_PATH='/dashboard';
export function oauthCallbackUrl(origin:string) {
  const url=new URL(origin);
  if(url.username||url.password||url.search||url.hash||url.pathname!=='/'||!['http:','https:'].includes(url.protocol))throw new Error('Invalid application origin.');
  if(url.protocol!=='https:'&&!['localhost','127.0.0.1','[::1]'].includes(url.hostname))throw new Error('OAuth requires HTTPS outside local development.');
  return new URL(OAUTH_CALLBACK_PATH,url.origin).href;
}
export function oauthCallbackCode(url:string) {
  const params=new URL(url).searchParams;
  if(params.has('error')||params.has('error_description'))throw new Error('Google sign-in was cancelled or could not be completed. Please try again.');
  const codes=params.getAll('code');
  if(codes.length!==1||!codes[0]||codes[0].length>2048)throw new Error('This sign-in link is missing or invalid. Start Google sign-in again from the sign-in page.');
  return codes[0];
}
