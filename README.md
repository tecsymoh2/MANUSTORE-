# YIM CLOUD STORAGE
Flask + Neon Postgres (project MANUSTORE). Deploy on Vercel.

1. Tables already created in Neon (`schema.sql` if you need to re-run).
2. Push this folder to GitHub, import in Vercel.
3. Add env vars from `.env.example` (DATABASE_URL, SECRET_KEY, APP_URL, SMTP_*).
4. Deploy.

Limit: Vercel functions accept ~4.5 MB per request, so uploads are capped at 4 MB.
For larger videos, move storage to Vercel Blob / S3 with direct client uploads.
