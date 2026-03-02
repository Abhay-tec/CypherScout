# CypherScout

CypherScout is a Flask-based URL and file security analysis platform with:
- URL risk analysis (VirusTotal + heuristics + ML score)
- File deep scan heuristics
- Google OAuth and local credential login
- Forgot password via email OTP code
- Login and threat notification emails
- Dashboard metrics and history
- Feedback loop for ML retraining

## Project Structure

```text
CypherScout/
  app/
    __init__.py          # App factory + OAuth setup
    config.py            # Environment-driven configuration
    db.py                # SQLite connection + schema init
    ml.py                # ML training/prediction engine
    routes/
      web.py             # HTML routes
      api.py             # JSON API routes
    services/
      intel.py           # URL/file scanning and enrichment logic
  templates/             # HTML templates
  main.py                # Local run entrypoint
  wsgi.py                # Production WSGI entrypoint
  requirements.txt
  Procfile
  runtime.txt
  .env.example
```

## Quick Start (Local)

1. Create and activate virtual env
   - Windows (PowerShell):
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
2. Install dependencies
   ```powershell
   pip install -r requirements.txt
   ```
3. Create `.env` from `.env.example` and set required secrets:
   - `SECRET_KEY`
   - `GOOGLE_CLIENT_ID`
   - `GOOGLE_CLIENT_SECRET`
   - `VT_API_KEY`
4. Run app
   ```powershell
   python main.py
   ```
5. Open:
   - `http://localhost:5000`

## Production Deployment

Use a WSGI server (Gunicorn) with `wsgi:app`.

### Example (Render / Railway / Fly / similar)

1. Set environment variables from `.env.example`.
2. Build command:
   ```bash
   pip install -r requirements.txt
   ```
3. Start command:
   ```bash
   gunicorn --bind 0.0.0.0:$PORT wsgi:app
   ```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | Yes | Flask session signing key |
| `DATABASE_PATH` | No | SQLite DB path (default `cypher.db`) |
| `SESSION_DAYS` | No | Session lifetime in days (default `7`) |
| `ALLOW_INSECURE_OAUTH` | No | `true` for local non-HTTPS OAuth only |
| `VT_API_KEY` | Recommended | VirusTotal API key |
| `GOOGLE_CLIENT_ID` | Yes (for Google login) | OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Yes (for Google login) | OAuth client secret |
| `OAUTH_REDIRECT_URI` | Recommended | Explicit OAuth callback URL (e.g. `https://your-domain.com/auth`) |
| `MAX_UPLOAD_BYTES` | No | Max file upload size (default 20MB) |
| `MAIL_ENABLED` | No | Enable email notifications (default `true`) |
| `SMTP_HOST` | Yes (for mail) | SMTP server host (Gmail: `smtp.gmail.com`) |
| `SMTP_PORT` | No | SMTP port (default `587`) |
| `SMTP_USE_TLS` | No | Enable STARTTLS (default `true`) |
| `SMTP_USER` | Yes (for mail) | SMTP username/email |
| `SMTP_PASSWORD` | Yes (for mail) | SMTP password / Gmail App Password |
| `MAIL_FROM` | No | Sender email identity |

## Security Notes

- Do not commit `.env` or real secrets.
- Keep `ALLOW_INSECURE_OAUTH=false` in production.
- Use HTTPS in production for OAuth callbacks.
- Rotate `SECRET_KEY` and API keys before going live.
- For Gmail SMTP, use App Passwords instead of regular account password.
