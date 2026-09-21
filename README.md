# mail-thoondil

A phishing email detection tool. Upload a `.eml` file and get a risk score, a verdict, and a plain-language explanation of why the email looks safe or dangerous.

mail-thoondil works by parsing the email and running it through a pipeline of analyzers that inspect headers, URLs, content, HTML, attachments, and sender identity. It then combines all findings into a single risk score between 0 and 100.

---

## What It Does

1. You upload an `.eml` email file.
2. The tool parses the email and breaks it into components (headers, body, links, attachments).
3. Each component is analyzed separately for known phishing patterns.
4. A rules engine and a machine learning model evaluate the findings.
5. Everything is combined into a risk score and a human-readable verdict.

### Risk Levels

| Score | Verdict | What It Means |
|-------|---------|---------------|
| 0-24 | Safe | The email looks normal. No action needed. |
| 25-49 | Suspicious | Something looks off. Review before trusting it. |
| 50-74 | High Risk | Likely malicious. Do not interact with it. |
| 75-100 | Phishing | Almost certainly a phishing email. Quarantine it. |

---

## Getting Started

You can run this project in two ways: with Docker (recommended) or manually.

### Option 1: Docker (Recommended)

This runs everything for you in containers.

```bash
git clone <repo-url>
cd mail-thoondil
docker compose up --build
```

Once running:

- **Web dashboard:** http://localhost:3000
- **API:** http://localhost:8000

Open the dashboard in your browser, upload a `.eml` file, and see the results.

### Option 2: Manual Setup

**Requirements:** Python 3.12+, Node.js 18+, PostgreSQL

1. **Set up the database**

   Create a PostgreSQL database. You can use the following defaults or your own:

   ```
   Database: phishing_detector
   User:     phishing
   Password: phishing
   ```

2. **Start the backend**

   ```bash
   cd backend
   python -m venv .venv
   source .venv/bin/activate   # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt

   # Set the database connection (adjust if needed)
   export DATABASE_URL="postgresql+asyncpg://phishing:phishing@localhost:5432/phishing_detector"

   uvicorn app.main:app --reload
   ```

   The API is now running at http://localhost:8000.

3. **Start the frontend**

   ```bash
   cd frontend
   npm install
   npm run dev
   ```

   The dashboard is now running at http://localhost:5173.

---

## Using the API

### Analyze an email

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -F "email=@path/to/email.eml"
```

The response includes:

- A risk score (0-100)
- A verdict (Safe, Suspicious, High Risk, Phishing)
- A list of findings with details
- A plain-language explanation of the result

### Other Endpoints

| Method | Path | What It Does |
|--------|------|-------------|
| GET | `/api/v1/analyses` | List recent analyses |
| GET | `/api/v1/analyses/{id}` | Get a specific analysis |
| POST | `/api/v1/analyses/{id}/feedback` | Submit feedback on a result |
| GET | `/api/v1/stats` | View system statistics |
| GET | `/health` | Check if the API is running |

---

## Running Tests

```bash
cd backend
SKIP_DB=1 python -m pytest tests/ -v
```

---

## How the Detection Works

The tool goes through these steps when analyzing an email:

1. **Parse** -- Reads the `.eml` file and extracts headers, body text, links, and attachments.
2. **Header Analysis** -- Checks SPF, DKIM, and DMARC authentication. Looks for reply-to mismatches and routing oddities.
3. **Sender Analysis** -- Detects brand impersonation and inconsistent display names.
4. **URL Analysis** -- Flags IP-based links, punycode domains, URL shorteners, and other suspicious patterns.
5. **Domain Analysis** -- Checks for suspicious top-level domains and lookalike characters.
6. **Content Analysis** -- Looks for urgency language, credential harvesting requests, threats, and authority impersonation.
7. **HTML Analysis** -- Detects hidden forms, iframes, and mismatched link text vs. actual URLs.
8. **Attachment Analysis** -- Flags executables, macros, double extensions, and suspicious archives.
9. **Rule Engine** -- Runs 25+ configurable rules to generate findings.
10. **Machine Learning** -- A TF-IDF + Logistic Regression model provides a baseline probability.
11. **Combine Results** -- All findings are merged, deduplicated, and weighted to produce the final score.
12. **Explain** -- Generates a plain-language summary of what was found and what to do about it.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://phishing:phishing@localhost:5432/phishing_detector` | Database connection string |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis cache address |
| `CORS_ORIGINS` | `http://localhost:3000` | Allowed frontend origins |
| `ML_MODEL_DIR` | `models` | Where ML model files are stored |
| `SKIP_DB` | `0` | Set to `1` to run without a database (useful for testing) |

---

## Project Structure

```
mail-thoondil/
  backend/
    app/
      api/              -- API route definitions
      core/             -- Configuration, security, database setup
      analyzers/        -- Individual analysis modules (headers, URLs, content, etc.)
      ml/               -- Machine learning model training and inference
      models/           -- Database table definitions
      schemas/          -- Request and response data shapes
      services/         -- Pipeline orchestration, rules, scoring, explanations
    tests/              -- Automated tests
    requirements.txt    -- Python dependencies
  frontend/
    src/                -- React application source code
    package.json        -- JavaScript dependencies
  rules/                -- Configurable detection rules (YAML files)
  models/               -- Saved ML model files
  datasets/             -- Training data
  docker-compose.yml    -- Docker setup for all services
```

---

## License

See the repository for license details.
