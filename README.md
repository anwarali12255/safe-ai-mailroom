# Safe AI Mailroom — beginner setup

This project provides `POST /propose` and `POST /commit` for profile
`ga5-mailroom-action-gate/v2`. It uses Groq-hosted inference (no local model
needed), validates the fixed action shapes, stores proposals/evaluations, and
verifies Ed25519 receipt signatures before accepting a commit.

## Important before submitting

This is a starter implementation based on the contract details available in the
assignment conversation. The grader's exact schema is authoritative. Test with
the supplied assignment examples before using a check. In particular, compare
the exact expected `commit` response shape and receipt signature encoding.
The service never sends email or performs the proposed external action; it only
records a verified receipt as `executed` or `rejected`.

The AI is a decision helper, not the authority source. Source mail and
attachments are treated as untrusted. If the model is unavailable or its output
fails validation, the service falls back to `request_confirmation` (or
`no_action` if confirmation is not an allowed action).

## 1. Create a free hosted model key

1. Open https://console.groq.com/ and create/sign in to an account.
2. Create an API key in the API keys section.
3. Keep the key private. Do not paste it into source code or commit it to GitHub.
4. The free plan has usage limits; requests may fail with rate-limit errors.

Model catalog and rate limits can change. The default model is
`openai/gpt-oss-20b`; if Groq's console says it is unavailable for your account,
choose a currently available model in the console and set `GROQ_MODEL` to its
exact model ID.

## 2. Run locally on Windows

Install Python 3.11 or 3.12 if available. In PowerShell, go into this folder:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env
```

Put your real key after `GROQ_API_KEY=` in `.env`. For local testing, install
python-dotenv and load `.env`, or set the environment variable in the same
PowerShell session:

```powershell
$env:GROQ_API_KEY="your-real-key-here"
$env:GROQ_MODEL="openai/gpt-oss-20b"
uvicorn main:app --reload
```

Open http://127.0.0.1:8000/health. It should return `{"ok":true}`.
The app reads environment variables directly; the `.env` file is an example
template and is not automatically loaded.

## 3. Set up persistent PostgreSQL storage

The Render free web service filesystem is ephemeral, so SQLite alone is not
sufficient for durable storage after restarts/redeploys. Create a free PostgreSQL
database with a provider such as Neon or Supabase. Copy its connection URL and
make sure it is a PostgreSQL URL. If the provider gives a URL starting with
`postgresql://`, this app converts it to `postgresql+psycopg://`.

## 4. Push to GitHub

Create a new repository named `safe-ai-mailroom`. In PowerShell from this folder:

```powershell
git init
git add .
git commit -m "Build Safe AI Mailroom"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/safe-ai-mailroom.git
git push -u origin main
```

Replace `YOUR-USERNAME` with your GitHub username.

## 5. Deploy on Render

1. Open https://render.com/ and connect your GitHub account.
2. Choose **New + → Web Service** and select this repository.
3. Use the settings from `render.yaml`, or enter:
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - Health check path: `/health`
4. In Environment, add `GROQ_API_KEY`, `GROQ_MODEL`, and `DATABASE_URL`.
5. Deploy and wait for the service to become Live.
6. Test `https://YOUR-SERVICE.onrender.com/health`.
7. Use the base service URL as the assignment endpoint URL, unless the assignment explicitly requests a path.

## 6. Routes

- `GET /` — basic service info
- `GET /health` — health check
- `POST /propose` — evaluates dossiers and returns proposals awaiting receipts
- `POST /commit` — validates all receipt signatures and then records terminal outcomes

## Security notes

- Do not put API keys in source code.
- Keep the evaluation verifier public key from `propose` associated with that evaluation.
- All receipt signatures are checked before a commit is stored.
- The app does not execute email sending or record updates; it only acknowledges a verified signed receipt.
- For production, add request authentication/rate limiting and a concurrency queue appropriate to the assignment environment.
