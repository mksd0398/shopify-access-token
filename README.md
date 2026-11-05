# shopify-access-token

Get a Shopify Admin API access token for any store with OAuth. Python standard library only.

## Use it in a new project

```bash
gh repo clone mksd0398/shopify-access-token .
git remote rename origin scaffold
cp .env.example .env
```

1. In the app's settings (Partner or Dev Dashboard), add `http://localhost:3000/callback` to **Allowed redirection URLs**.
2. In `.env`, fill in `SHOPIFY_CLIENT_ID`, `SHOPIFY_CLIENT_SECRET` and `SHOPIFY_STORE_PROD` (plus `SHOPIFY_STORE_STAGE` if you have a staging store).
3. Run `python get_access_token.py` (or `python get_access_token.py prod`).
4. Approve the install in the browser. The script writes the token to `.env` as `SHOPIFY_ACCESS_TOKEN_<ENV>`, and also sets `SHOPIFY_STORE` and `SHOPIFY_ACCESS_TOKEN` to the store you just authorized.

The script asks for a common set of read/write scopes. To change them, set `SHOPIFY_SCOPES` in `.env`. Gated scopes such as `read_all_orders` only work after Shopify approves the app for them.

Run the self-check with `python test_get_access_token.py`.
