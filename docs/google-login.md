# Home page and Google sign-in

`/` is the public feature overview with Google and password sign-in. `/signin` is the dedicated sign-in page, and `/dashboard` opens the assessment workspace. Existing local password login is preserved. A sign-in is still required for assessment APIs.

Google uses Supabase Auth with PKCE. The browser exchanges a one-use authorization code using the locally stored verifier. The API verifies the resulting access token with Supabase before resolving organization membership. The callback always goes to `/dashboard`; it ignores user-supplied redirect destinations and does not render provider error details. Google Client Secrets belong in the authentication service, never in a `NEXT_PUBLIC_` variable.

## Hosted Supabase setup

1. In [Google Auth Platform](https://console.cloud.google.com/auth/overview), configure your application's branding, audience and test users if required. Create an OAuth client with application type **Web application**.
2. Add your application origin to Authorized JavaScript origins. For development this is `http://127.0.0.1:3000`; use the exact hostname you browse.
3. Add the Supabase callback URL shown in **Authentication → Sign-in / Providers → Google** to Google's Authorized redirect URIs, typically `https://YOUR_PROJECT.supabase.co/auth/v1/callback`.
4. Enable Google in Supabase and save the Google Client ID and Client Secret there. Use only the identity scopes required by Supabase (`openid`, email, profile).
5. Set Supabase's Site URL to your application origin and add the exact app callback `http://127.0.0.1:3000/auth/callback` (or its production HTTPS equivalent) to its redirect allow list.
6. In `.env.local`, configure the following using your Supabase project URL and public/publishable key:

```dotenv
SUPABASE_URL=https://YOUR_PROJECT.supabase.co
SUPABASE_ANON_KEY=YOUR_PUBLIC_SUPABASE_KEY
NEXT_PUBLIC_SUPABASE_URL=https://YOUR_PROJECT.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=YOUR_PUBLIC_SUPABASE_KEY
GOOGLE_AUTH_ENABLED=true
```

Restart `npm run dev` after editing environment variables. Public variables must be set before a production build. Keep `LOCAL_AUTH=true` to retain the existing development password login; use `LOCAL_AUTH=false` with Supabase email/password authentication in production.

## Self-hosted local authentication

The existing Compose profile exposes Supabase Auth at `http://127.0.0.1:8000`. Add these values to `.env.compose` after creating the Google Web OAuth client:

```dotenv
GOOGLE_AUTH_ENABLED=true
GOOGLE_CLIENT_ID=YOUR_GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET=YOUR_GOOGLE_CLIENT_SECRET
```

For Google, the authorized redirect URI is **`http://127.0.0.1:8000/auth/v1/callback`**. The application callback is **`http://127.0.0.1:3000/auth/callback`**; these serve different purposes. The Compose file supplies the latter redirect allow list and Google provider settings to the Auth service.

```powershell
docker compose --env-file .env.compose up -d auth auth-gateway
```

In `.env.local`, use `http://127.0.0.1:8000` for both Supabase URL variables, copy the public `ANON_KEY` from your local Compose settings into both Supabase key variables, and set `GOOGLE_AUTH_ENABLED=true`. Preserve the current database mode and URL if you want to keep your existing assessment records. Restart the dashboard.

## Workspaces and account access

A newly verified Google identity gets its own workspace unless an owner has explicitly added its Supabase user ID to an existing organization. Google sign-in does not automatically grant access to the local development account's WalletAce project. Existing owners can add members through the authenticated members API; email similarity is never used to merge authorization.

## Verification limits

Automated checks cover provider availability, fixed redirects, malformed/cancelled callbacks, server identity verification, identity precedence and organization isolation. Local password login, page rendering, navigation and responsive layouts are checked separately. Completing Google's consent and callback against a real client still requires configured Google/Supabase credentials; no account or credentials are fabricated for that test.

Reference: [Supabase Google sign-in](https://supabase.com/docs/guides/auth/social-login/auth-google) and [PKCE flow](https://supabase.com/docs/guides/auth/sessions/pkce-flow).
