# YIM CLOUD STORAGE
Flask + Neon Postgres (MANUSTORE) + S3-compatible bucket. Deploy on Vercel.

1. Push this folder to a PRIVATE GitHub repo and import it in Vercel.
2. Add the variables from `.env.example` (DATABASE_URL, SECRET_KEY, APP_URL, NEON_AUTH_URL, S3_*).
3. Files are stored in the private Neon bucket `yim-files`. If browser uploads fail with a network/CORS error, tell the developer.
4. Deploy. Tables are already created in Neon (`schema.sql` re-runs safely).

Emails (verification code, password reset) are sent by Neon Auth. Add your Vercel domain under Neon Auth > Trusted domains.

Payments: Techland M-Pesa STK. In Admin paste the API key (tl_live_…) and webhook secret, then set the Webhook URL shown there in the Techland dashboard.
