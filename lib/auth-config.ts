export function authOptions() {
  const supabase=!!(process.env.NEXT_PUBLIC_SUPABASE_URL&&process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY&&process.env.SUPABASE_URL&&process.env.SUPABASE_ANON_KEY);
  return {
    local:process.env.LOCAL_AUTH==='true'&&!process.env.VERCEL&&process.env.NODE_ENV!=='production',
    password:supabase,
    google:supabase&&process.env.GOOGLE_AUTH_ENABLED==='true'
  };
}
