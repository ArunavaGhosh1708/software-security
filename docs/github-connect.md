# GitHub connections

Workspace owners click **Integrations → Connect GitHub**, select an account and repositories on GitHub, and authorize their GitHub identity. After returning to Sentinel, **Connect project → GitHub repository** lists authorized repositories and supplies installation IDs and default branches automatically. Local scanning works without a GitHub connection.

## One-time setup for the host

Register a GitHub App that can be installed on the accounts your users need. Configure:

- Repository permissions: **Contents: read**, **Checks: write**. Metadata read access is implicit. No contents write permission is needed.
- Subscribe to **Pull request** events and enable installation lifecycle deliveries.
- Webhook URL: `https://YOUR_SENTINEL_HOST/api/github/webhook`, with a generated webhook secret.
- Setup URL and user authorization callback URL: `https://YOUR_SENTINEL_HOST/integrations/github/callback`.
- Leave **Request user authorization (OAuth) during installation** unchecked. Sentinel starts a separate authorization step with PKCE after the installation callback.
- Enable **Redirect on update** so changing an existing installation can return to Sentinel.

Configure these server-only environment variables, then restart the app:

```dotenv
APP_ORIGIN=https://YOUR_SENTINEL_HOST
GITHUB_APP_ID=your-app-numeric-id
GITHUB_APP_SLUG=your-app-url-slug
GITHUB_APP_PRIVATE_KEY="your-PKCS8-private-key"
GITHUB_WEBHOOK_SECRET=your-webhook-secret
GITHUB_CLIENT_ID=your-app-client-id
GITHUB_CLIENT_SECRET=your-app-client-secret
```

The client ID differs from the numeric app ID. Convert a downloaded RSA key to PKCS#8 if necessary; literal `\n` escapes are supported. Keep all secrets private; none belong in browser configuration or a user's connection form. The host configures the credentials once. Use HTTPS outside localhost development. GitHub needs a reachable HTTPS webhook to trigger automatic PR scans.

The schema applies automatically on server initialization (or via `npm run migrate`). Legacy `GITHUB_ORGANIZATION_INSTALLATIONS` mappings are replaced by verified database connections; reconnect existing installations through Integrations after upgrading.

## Access and verification

Connection attempts expire after 15 minutes and are bound to the signed-in Sentinel owner and workspace. The OAuth code uses PKCE and single-use state. Sentinel verifies the installation using the authorizing user's GitHub access token; the callback's installation ID alone grants no access. Only the intersection of user-accessible and installation-accessible repositories is saved. OAuth access/refresh tokens are never persisted or returned to the browser.

Connections support up to 500 selected repositories per installation. The picker checks current installation access and filters it to the saved authorization. Added repositories require reconnecting. A workspace owner who authorizes repository access shares that access with their Sentinel workspace; maintainers and viewers continue to follow Sentinel's existing role rules. Removing or suspending the GitHub installation disables new scan credentials and webhook scans. Restore the installation and reconnect to resume access.

If authorization is cancelled or the session expires, sign in and start Connect GitHub again. Organization installations may require owner approval and an active SAML session before authorization succeeds. No installation is linked until GitHub verifies access.

GitHub references: [setup URL security](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/about-the-setup-url) and [user access tokens / PKCE](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app).
