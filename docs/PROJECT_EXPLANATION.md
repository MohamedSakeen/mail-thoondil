# Phishing Mail Detector — Complete Project Explanation

> A beginner-friendly, deep-dive into the entire project: what it is,
> why it matters, how it works, every file explained, and what makes
> it novel.

---

## Table of Contents

1. [What Is This Project?](#1-what-is-this-project)
2. [The Problem](#2-the-problem)
3. [The Solution](#3-the-solution)
4. [Why This Approach Is Different (Novelty)](#4-why-this-approach-is-different-novelty)
5. [How It Works — The Big Picture](#5-how-it-works--the-big-picture)
6. [The Complete Detection Pipeline (Step by Step)](#6-the-complete-detection-pipeline-step-by-step)
7. [Every File Explained](#7-every-file-explained)
8. [The API — How Software Talks to This System](#8-the-api--how-software-talks-to-this-system)
9. [The Frontend — What the Analyst Sees](#9-the-frontend--what-the-analyst-sees)
10. [Security — How We Protect Against Malicious Emails](#10-security--how-we-protect-against-malicious-emails)
11. [The Test Suite — How We Know It Works](#11-the-test-suite--how-we-know-it-works)
12. [Docker — How to Run Everything](#12-docker--how-to-run-everything)
13. [What Makes This "Enterprise-Grade"](#13-what-makes-this-enterprise-grade)
14. [Glossary of Terms](#14-glossary-of-terms)

---

## 1. What Is This Project?

This is a **Phishing Mail Detector** — a software system that reads an
email and tells you: *"Is this email trying to scam someone?"*

It doesn't just say "yes" or "no." It gives you:

- A **risk score** from 0 to 100
- A **classification** (Benign, Suspicious, or Phishing)
- A list of **specific reasons** why it thinks that
- A human-readable **attack narrative** explaining the story
- A **recommended action** (Allow, Review, Alert, or Quarantine)

Think of it like a security guard for your inbox. It inspects every
piece of an email — the headers, the links, the words, the
attachments — and builds a case for whether it's legitimate or a scam.

---

## 2. The Problem

### What Is Phishing?

Phishing is when someone sends you a fake email that **looks real** but
is actually trying to steal your password, credit card number, or
other sensitive information.

**Example:** You get an email that says:

```
From: Microsoft Security <security@microsoft.com>
Subject: Urgent: Your account has been compromised!

Dear user,
Your Microsoft account will be suspended within 24 hours.
Please verify your password immediately:
https://login-microsoft-secure.example.com/verify
```

This email **looks** like it's from Microsoft. But let's look closer:

- The sender domain is `microsoft.com` — but the Reply-To is
  `attacker@evil.example` (hidden from view)
- The link goes to `login-microsoft-secure.example.com` — NOT
  `microsoft.com`
- It uses urgency ("within 24 hours") to make you panic
- It asks for your password — Microsoft would never do that

### Why Is This Hard to Detect?

1. **Attackers are clever.** They study real emails and copy their
   format exactly.
2. **No single signal is enough.** A URL shortener isn't inherently
   bad. Urgency alone isn't proof. You need to combine many signals.
3. **Legitimate emails can look suspicious.** A company might use a
   URL shortener in a marketing email. You need context.
4. **Scale.** Enterprises receive millions of emails. A human can't
   read them all.

### What Existing Solutions Get Wrong

- Many tools just check one thing (like a URL blacklist)
- They give a verdict but don't explain **why**
- They can't distinguish between "this looks weird" and "this is
  definitely an attack"
- They're black boxes — a security analyst can't understand the
  reasoning

---

## 3. The Solution

Our system attacks this problem from **every angle simultaneously**.

Instead of looking at just one thing, it extracts features from
**7 different dimensions** of an email:

| Dimension | What It Looks At | Example |
|-----------|-----------------|---------|
| **Headers** | Email routing, authentication | Did SPF/DKIM/DMARC pass? |
| **Sender** | Who sent it, display name | Does the name match the domain? |
| **URLs** | Every link in the email | Is it an IP address? A shortener? |
| **Domains** | Sender + URL domains | Suspicious TLD? Homoglyphs? |
| **Content** | The actual words | Urgency? Credential requests? |
| **HTML** | Page structure | Hidden elements? Forms? Iframes? |
| **Attachments** | Files attached | Executables? Macros? Double extensions? |

Then it **cross-correlates** these dimensions. If the display name
says "Microsoft" but the domain isn't Microsoft, AND the URL goes to
a suspicious domain, AND the content asks for a password — that's a
much stronger signal than any single indicator alone.

Finally, it combines everything into a **single risk score** and
explains its reasoning in plain English.

---

## 4. Why This Approach Is Different (Novelty)

Most phishing detectors are either:

- **Simple rule checkers** — "Does the URL contain 'login'? → suspicious"
- **Black-box ML models** — "Here's a number, trust us"

Our system is neither. It's an **explainable multi-signal detection
engine**. Here's what makes it novel:

### 1. Separation of Concerns

```
Extraction ≠ Detection ≠ Scoring ≠ Decision
```

These are four completely separate stages. This means:

- You can **test** each stage independently
- You can **swap out** the ML model without changing the rules
- You can **explain** exactly which stage contributed what
- You can **tune** thresholds without retraining the model

### 2. Relationship Analysis

The system doesn't just check each dimension in isolation. It asks:
*"Do these dimensions agree with each other?"*

If the sender claims to be from Microsoft, but the authentication
failed, the URL goes somewhere else, and the content asks for
passwords — that's a **correlated deception pattern**. The system
detects this and produces a stronger combined signal.

### 3. Attack Narrative Generation

Instead of just saying "PHISHING — 89/100", the system generates:

```
CRITICAL — LIKELY PHISHING

An email claiming to be from "Microsoft Security" was sent from
micros0ft.example. Authentication checks failed: SPF, DMARC. This
suggests the sender is not authorized to send from this domain.
The Reply-To address redirects to attacker.example, which differs
from the sender domain. The email contains 1 suspicious URL(s).
The message urges the recipient to provide credentials or verify
their account. The message uses urgency tactics to pressure
immediate action.
```

This is what a **security analyst** actually needs to make a decision.

### 4. Category Caps

No single dimension can dominate the score. Even if a URL is
extremely suspicious, the URL category is capped at 30 points. This
prevents one screaming indicator from drowning out quieter but
equally important signals.

---

## 5. How It Works — The Big Picture

Here's the entire system as a flowchart:

```
                  📧 EMAIL FILE (.eml)
                         │
                         ▼
               ┌─────────────────┐
               │  SECURE INGEST  │  Check size, validate format
               └────────┬────────┘
                        │
                        ▼
               ┌─────────────────┐
               │  EMAIL PARSER   │  Extract headers, bodies,
               │                 │  URLs, attachments
               └────────┬────────┘
                        │
         ┌──────────────┼──────────────┐
         │              │              │
         ▼              ▼              ▼
   ┌──────────┐  ┌──────────┐  ┌──────────┐
   │ HEADER   │  │   URL    │  │ CONTENT  │
   │ ANALYZER │  │ ANALYZER │  │ ANALYZER │
   └────┬─────┘  └────┬─────┘  └────┬─────┘
        │              │              │
        ▼              ▼              ▼
   ┌──────────┐  ┌──────────┐  ┌──────────┐
   │ SENDER   │  │ DOMAIN   │  │   HTML   │
   │ ANALYZER │  │ ANALYZER │  │ ANALYZER │
   └────┬─────┘  └────┬─────┘  └────┬─────┘
        │              │              │
        └──────────────┼──────────────┘
                       │
                       ▼
              ┌────────────────┐
              │  ATTACHMENT    │
              │  ANALYZER      │
              └───────┬────────┘
                      │
                      ▼
              ┌────────────────┐
              │  RELATIONSHIP  │  Cross-correlate all signals
              │  ANALYZER      │
              └───────┬────────┘
                      │
           ┌──────────┴──────────┐
           │                     │
           ▼                     ▼
   ┌──────────────┐     ┌──────────────┐
   │ RULE ENGINE  │     │  ML MODEL    │
   │ (25+ rules)  │     │  (TF-IDF +   │
   │              │     │  Log. Reg.)  │
   └──────┬───────┘     └──────┬───────┘
          │                     │
          └──────────┬──────────┘
                     │
                     ▼
            ┌────────────────┐
            │  SIGNAL FUSION │  Deduplicate, apply category caps
            └───────┬────────┘
                    │
                    ▼
            ┌────────────────┐
            │  RISK SCORING  │  Compute 0-100 score + confidence
            └───────┬────────┘
                    │
                    ▼
            ┌────────────────┐
            │  EXPLANATION   │  Generate attack narrative
            │  ENGINE        │
            └───────┬────────┘
                    │
                    ▼
            ┌────────────────┐
            │  VERDICT +     │  Benign / Suspicious / Phishing
            │  EVIDENCE      │  + reasons + recommended action
            └────────────────┘
```

---

## 6. The Complete Detection Pipeline (Step by Step)

Let's walk through exactly what happens when you upload an email.

### Step 1: Secure Ingestion

The email file arrives. We immediately:

- Check it's not empty
- Check it's under 10 MB
- Reject anything that fails

**Why?** Attackers send huge files to crash systems (denial of
service). We prevent that.

### Step 2: RFC/MIME Parsing

We use Python's built-in `email` library to parse the raw bytes into
a structured object. We extract:

- **Headers:** From, To, Reply-To, Return-Path, Subject, Date,
  Message-ID, Authentication-Results, Received
- **Body parts:** Plain text and HTML
- **URLs:** Every link in both plain text and HTML
- **Attachments:** Filename, MIME type, size (but we NEVER execute them)

### Step 3: Header Analysis (`analyzers/header.py`)

We examine the email headers for anomalies:

- **Reply-To mismatch:** The sender says they're from `bank.com` but
  the Reply-To is `attacker.com`. Why would a bank reply from a
  different domain?
- **Return-Path mismatch:** Similar check for the return path.
- **Message-ID domain mismatch:** The Message-ID says `@fake.com`
  but the From says `@bank.com`.
- **Received hop count:** How many servers did this email pass through?
  Legitimate emails usually have 2-5 hops. 20+ hops is suspicious.
- **Display name mismatch:** The name says "Microsoft" but the
  domain isn't Microsoft's.

### Step 4: Authentication Analysis (part of `header.py`)

We check three email authentication protocols:

- **SPF (Sender Policy Framework):** Is this server allowed to send
  email for this domain? → `pass` / `fail` / `softfail`
- **DKIM (DomainKeys Identified Mail):** Is the email digitally
  signed by the claimed domain? → `pass` / `fail`
- **DMARC (Domain-based Message Authentication):** Does the domain's
  policy pass? → `pass` / `fail`

A `fail` on any of these is suspicious. All three failing is very
suspicious.

### Step 5: Sender Analysis (`analyzers/sender.py`)

We check if the sender is impersonating a known brand:

- Does the display name contain "Microsoft", "Google", "PayPal", etc.?
- If so, is the sender domain actually owned by that brand?
- Example: Display name "PayPal Security" from `paypa1-support.com`
  → brand impersonation detected

### Step 6: URL Analysis (`analyzers/url.py`)

We extract every URL from the email and analyze each one:

- **IP address:** `http://1.2.3.4/login` — legit companies don't
  send you to raw IP addresses
- **Punycode:** `http://xn--e1afmapc.xn--p1ai` — encoded
  international characters can disguise domains
- **URL shorteners:** `http://bit.ly/abc123` — hiding the real
  destination
- **@ symbol:** `https://google.com@evil.com` — the part before @
  is fake, you'll actually go to `evil.com`
- **Suspicious keywords:** URLs containing "login", "verify",
  "account", "password" etc.
- **Non-standard ports:** `https://bank.com:8080` — banks use port
  443, not 8080

### Step 7: Domain Analysis (`analyzers/domain.py`)

We analyze the domains found in the email:

- **Suspicious TLDs:** `.xyz`, `.top`, `.tk` etc. are commonly used
  by attackers because they're cheap/free
- **Homoglyphs:** `аpple.com` where the 'a' is Cyrillic, not
  English — it looks identical but goes to a different site
- **Brand references:** Does the domain contain a brand name to
  look legitimate?
- **Random patterns:** `xkcd8374.xyz` — randomly generated domains
  are often malicious

### Step 8: Content/NLP Analysis (`analyzers/content.py`)

We analyze the text of the email using pattern matching:

- **Urgency score:** Words like "urgent", "immediately", "within 24
  hours", "act now"
- **Credential request score:** "verify your password", "sign in",
  "enter your credentials"
- **Threat score:** "your account will be suspended", "legal action",
  "penalty"
- **Financial request score:** "wire transfer", "invoice", "payment"
- **Authority impersonation:** "security team", "IT department",
  "administrator"
- **Call-to-action score:** "click here", "verify", "download"

Each score is 0.0 to 1.0. High scores in multiple categories is a
strong phishing indicator.

### Step 9: HTML Analysis (`analyzers/html.py`)

If the email contains HTML, we analyze the structure:

- **Forms:** Phishing pages often embed forms to capture credentials
- **Iframes:** Can load hidden malicious content
- **Scripts:** Can execute JavaScript
- **Hidden elements:** `display:none` or `visibility:hidden` — content
  you can't see but the browser loads
- **Link mismatches:** The text says "https://google.com" but the
  actual link goes to "https://evil.com"
- **Meta refresh:** Auto-redirects you to another page

### Step 10: Attachment Analysis (`analyzers/attachment.py`)

We examine every attachment (metadata only, NEVER executed):

- **Executable extensions:** `.exe`, `.scr`, `.bat`, `.js`, `.vbs`,
  `.ps1` — these run code
- **Macro documents:** `.docm`, `.xlsm` — Office files with embedded
  macros
- **Double extensions:** `invoice.pdf.exe` — looks like a PDF but is
  actually an executable
- **HTML attachments:** Can contain phishing pages
- **Archives:** `.zip`, `.rar` — might contain malware inside
- **SHA-256 hash:** For threat intelligence lookup

### Step 11: Relationship Analysis (`analyzers/relationship.py`)

This is where the magic happens. We cross-correlate findings from
all the other analyzers:

- **From ↔ Reply-To consistency:** Do they use the same domain?
- **Sender ↔ URL consistency:** Do the URLs match the sender's domain?
- **Brand ↔ Domain consistency:** If the sender claims to be Microsoft,
  is the domain actually Microsoft's?
- **Brand ↔ URL consistency:** If claiming to be PayPal, do the URLs
  go to paypal.com?
- **Authentication ↔ Identity consistency:** Do the auth results
  support the identity claim?
- **Visible ↔ Actual URL consistency:** Does the link text match
  where it actually goes?

Each relationship produces a consistency score from 0.0 (totally
inconsistent) to 1.0 (fully consistent). Low consistency = high
deception.

### Step 12: Rule Engine (`services/rules.py`)

Rules convert features into **signals**. Each rule is a simple
IF-THEN statement:

```
IF authentication.dmarc_fail == true
THEN emit signal AUTH-S001:
  category: authentication
  severity: 0.7
  risk_contribution: 10
  explanation: "DMARC authentication failed."
```

We have 25+ built-in rules covering authentication, sender, URL,
content, HTML, attachment, and relationship categories.

Rules are also configurable via YAML files in the `rules/` directory.
An administrator can add, modify, or disable rules without touching
code.

### Step 13: ML Model (`ml/model.py`)

We use a machine learning model as a second opinion:

- **TF-IDF vectorizer:** Converts email text into numerical features
  based on word importance
- **Logistic Regression:** A simple, interpretable classifier that
  outputs a probability (0.0 to 1.0) of phishing

If no trained model is available, a **fallback heuristic** uses the
NLP scores to estimate probability. This means the system works
even before you've trained it on data.

### Step 14: Signal Fusion (`services/fusion.py`)

Now we have signals from the rules, the ML model, and the
relationship analyzer. We combine them:

1. **Deduplicate:** If the same signal ID appears multiple times, keep
   only the one with the highest risk contribution
2. **Apply category caps:** No single category can contribute more
   than its cap (e.g., URLs max out at 30 points). This prevents
   one screaming indicator from dominating
3. **Produce the final signal set**

### Step 15: Risk Scoring (`services/scoring.py`)

We compute the final 0–100 risk score:

```
Base Score = Sum of all signal risk contributions
ML Component = ML probability × 25
Relationship Component = Deception score × 10 + bonus
Total = Base + ML + Relationship (clamped to 0–100)
```

We also estimate **confidence** — how sure are we about this
classification? Confidence is higher when:

- Many signals agree
- Signals come from multiple categories
- The score is far from decision boundaries

### Step 16: Explanation Engine (`services/explanation.py`)

We generate a human-readable explanation:

- **Risk label:** "LOW RISK", "MODERATE RISK", "HIGH RISK", or
  "CRITICAL — LIKELY PHISHING"
- **Primary indicators:** The top 5 most important signals
- **Attack narrative:** A paragraph explaining what's happening
- **Recommended action:** What the analyst should do

---

## 7. Every File Explained

Here's every file in the project and what it does, explained for
a beginner.

### Backend Core

```
backend/
├── app/
│   ├── main.py                    # Entry point — starts the FastAPI server
│   ├── __init__.py                # Makes this a Python package
```

**`main.py`** — This is the front door. When you start the server,
this file runs. It:
- Creates the FastAPI application
- Adds CORS middleware (so the frontend can talk to the backend)
- Initializes the database on startup
- Loads the ML model
- Includes all the API routes

### API Layer

```
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py              # All the REST endpoints
```

**`routes.py`** — Defines all the HTTP endpoints:
- `POST /api/v1/analyze` — Accepts an uploaded .eml file, runs the
  full pipeline, returns the result
- `GET /api/v1/analyses` — Lists past analyses from the database
- `GET /api/v1/analyses/{id}` — Retrieves a specific analysis
- `POST /api/v1/analyses/{id}/feedback` — Saves analyst feedback
- `GET /api/v1/stats` — Returns system info (model version, etc.)
- `GET /health` — Simple health check

### Core Infrastructure

```
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py              # All constants and settings
│   │   ├── security.py            # Security utilities
│   │   └── database.py            # Database connection
```

**`config.py`** — Every magic number, threshold, and setting lives
here. This includes:
- Version strings (schema, parser, rules, model)
- File size limits (10 MB email, 25 MB attachment)
- Risk thresholds (0–24 benign, 25–49 suspicious, etc.)
- Category caps (URL max 30, Content max 25, etc.)
- Keyword patterns for urgency, credentials, threats, etc.
- Known URL shorteners and suspicious TLDs
- Database URLs
- ML model configuration
- Policy actions (allow, review, alert, quarantine)

Having all configuration in one place means you can tune the system
without modifying any detection code.

**`security.py`** — Security utilities:
- `validate_email_size()` — Rejects oversized emails
- `is_safe_url()` — Checks if a URL is safe to fetch (prevents SSRF)
- `sanitize_html_for_display()` — Strips dangerous HTML for display
- `sanitize_filename()` — Removes path traversal from filenames
- `is_ip_address()` — Checks if a string is an IP address

**`database.py`** — Sets up the async PostgreSQL connection:
- Creates the SQLAlchemy engine and session factory
- Provides `get_db()` — a FastAPI dependency that yields a database
  session for each request
- Provides `init_db()` — creates tables on startup
- Gracefully handles when the database is unavailable (you can run
  the system without Postgres for development)

### Analyzers (The Detection Engines)

```
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── header.py              # Header and authentication analysis
│   │   ├── url.py                 # URL structural analysis
│   │   ├── content.py             # Text/NLP analysis
│   │   ├── html.py                # HTML structure analysis
│   │   ├── attachment.py          # Attachment static analysis
│   │   ├── sender.py              # Sender identity and brand analysis
│   │   ├── domain.py              # Domain reputation analysis
│   │   └── relationship.py        # Cross-component correlation
```

**`header.py`** — Analyzes email headers:
- Extracts From, Reply-To, Return-Path domains
- Checks SPF/DKIM/DMARC authentication status
- Detects Reply-To and Return-Path mismatches
- Detects Message-ID domain mismatches
- Counts Received hops
- Detects display name vs domain mismatches (brand impersonation)

**`url.py`** — Analyzes every URL found in the email:
- Structural: length, domain length, subdomain count
- Security: IP address, punycode, @ symbol, encoding
- Phishing: shortener detection, suspicious keywords, non-standard ports

**`content.py`** — Analyzes the text content:
- Basic stats: word count, sentence count, character ratios
- Phishing indicators: urgency, credential requests, financial
  requests, threats, authority impersonation, call-to-action
- Each indicator is scored 0.0–1.0

**`html.py`** — Analyzes HTML structure:
- Counts forms, iframes, scripts, hidden elements
- Detects link text vs URL mismatches
- Detects meta refresh redirects
- Detects base tags and data URIs

**`attachment.py`** — Analyzes attachments (metadata only):
- Detects executable extensions (.exe, .scr, .bat, etc.)
- Detects macro-capable documents (.docm, .xlsm)
- Detects double extensions (invoice.pdf.exe)
- Detects HTML attachments
- Computes SHA-256 hash for threat intelligence

**`sender.py`** — Analyzes sender identity:
- Detects brand references in the display name
- Checks if the domain is actually owned by that brand
- Detects display name that looks like an email address
- Checks for suspicious characters in the display name

**`domain.py`** — Analyzes domains:
- Detects suspicious TLDs (.xyz, .top, .tk, etc.)
- Detects homoglyphs (Cyrillic characters that look like Latin)
- Detects brand name references in domains
- Heuristic detection of randomly-generated domains

**`relationship.py`** — Cross-correlates all analyzers:
- From ↔ Reply-To consistency
- Sender ↔ URL domain consistency
- Brand ↔ Domain consistency
- Brand ↔ URL consistency
- Authentication ↔ Identity consistency
- Visible ↔ Actual URL domain consistency
- Produces a "deception score" (0.0–1.0)

### Services (The Brain)

```
│   ├── services/
│   │   ├── __init__.py
│   │   ├── parser.py              # Email parsing
│   │   ├── pipeline.py            # Main orchestration pipeline
│   │   ├── rules.py               # Rule engine
│   │   ├── fusion.py              # Signal fusion
│   │   ├── scoring.py             # Risk scoring
│   │   ├── explanation.py         # Explanation generation
│   │   └── crud.py                # Database operations
```

**`parser.py`** — Parses raw email bytes into a structured object:
- Validates size limits
- Parses MIME structure
- Extracts plain text and HTML bodies
- Extracts URLs
- Collects attachment metadata
- Parses dates and detects anomalies
- Collects raw headers

**`pipeline.py`** — The **orchestrator**. This file ties everything
together:
1. Calls the parser
2. Runs all 7 analyzers
3. Runs the relationship analyzer
4. Runs the rule engine
5. Runs the ML model
6. Fuses signals
7. Computes the risk score
8. Generates the explanation
9. Assembles the final result

This is the most important file — it defines the complete workflow.

**`rules.py`** — The rule engine:
- Loads YAML rules from the `rules/` directory
- Falls back to built-in Python rules if no YAML files exist
- Evaluates each rule against the extracted features
- Produces a `Signal` for each triggered rule

**`fusion.py`** — Combines signals from all sources:
- Deduplicates signals (keeps highest risk contribution per ID)
- Applies category caps (URLs max 30, Content max 25, etc.)
- Produces the final signal set

**`scoring.py`** — Computes the risk score:
- Sums signal risk contributions
- Adds ML probability component
- Adds relationship/deception component
- Clamps to 0–100
- Maps to classification (benign/suspicious/high_suspicious/phishing)
- Estimates confidence

**`explanation.py`** — Generates human-readable output:
- Risk label ("LOW RISK", "HIGH RISK", etc.)
- Primary indicators (top 5 signals)
- Attack narrative (plain English paragraph)
- Recommended action

**`crud.py`** — Database operations:
- `save_analysis()` — Persists an analysis result
- `get_analysis()` — Retrieves an analysis by ID
- `list_analyses()` — Lists recent analyses
- `save_feedback()` — Saves analyst feedback

### ML Module

```
│   ├── ml/
│   │   ├── __init__.py
│   │   ├── features.py            # Feature extraction for ML
│   │   └── model.py               # ML model (TF-IDF + Logistic Regression)
```

**`features.py`** — Extracts a flat numerical feature vector from
the analyzer outputs. This is the bridge between the modular
analyzers and the ML model. It defines 45 features covering all
dimensions.

**`model.py`** — The ML prediction pipeline:
- `MLPredictor` class: loads a persisted model or uses fallback
- `predict()`: runs TF-IDF + Logistic Regression on text + features
- `_fallback_prediction()`: heuristic when no model is trained
- `train_model()`: trains on labeled data, persists to disk

### Database Models

```
│   ├── models/
│   │   ├── __init__.py
│   │   └── analysis.py            # SQLAlchemy ORM models
```

**`analysis.py`** — Defines three database tables:
- `analyses` — Stores the top-level result (score, classification,
  full features as JSONB)
- `signals` — Stores individual signals linked to an analysis
- `feedback` — Stores analyst feedback on analyses

### Schemas

```
│   ├── schemas/
│   │   ├── __init__.py
│   │   └── analysis.py            # Pydantic request/response models
```

**`analysis.py`** — Defines the data shapes for API requests and
responses:
- `Signal` — A single detection signal
- `AnalysisResponse` — Complete analysis result
- `FeedbackRequest` / `FeedbackResponse`
- `RiskResult`, `ExplanationResult`, etc.

### Tests

```
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── test_parser.py         # 14 tests for email parsing
│   │   ├── test_analyzers.py      # 58 tests for all analyzers
│   │   ├── test_rules.py          # 12 tests for rule engine
│   │   ├── test_scoring.py        # 12 tests for scoring + fusion
│   │   ├── test_ml.py             # 8 tests for ML module
│   │   ├── test_explanation.py    # 6 tests for explanation engine
│   │   ├── test_pipeline.py       # 16 tests for full pipeline
│   │   └── test_api.py            # 11 tests for API endpoints
```

**137 tests total** covering every module in the system.

### Frontend

```
frontend/
├── src/
│   ├── main.tsx                   # React entry point
│   ├── App.tsx                    # Router + sidebar layout
│   ├── api.ts                     # TypeScript API client
│   ├── index.css                  # Dark theme styles
│   └── pages/
│       ├── UploadPage.tsx         # Drag-and-drop email upload
│       ├── ResultPage.tsx         # Full analysis display
│       └── HistoryPage.tsx        # Past analyses list
├── index.html                     # HTML shell
├── package.json                   # Dependencies
├── tsconfig.json                  # TypeScript config
└── vite.config.ts                 # Vite dev server config
```

**`UploadPage.tsx`** — The landing page. You can drag-and-drop an
.eml file or click to browse. It uploads the file to the backend
and navigates to the result page.

**`ResultPage.tsx`** — Shows the complete analysis:
- Risk score ring (color-coded)
- Classification badge
- Attack narrative
- Recommended action
- Email details (From, To, Subject, Date)
- Authentication status (SPF/DKIM/DMARC as colored circles)
- Sender analysis
- URL table
- Attachment table
- All signals ranked by risk
- ML prediction
- Score breakdown

**`HistoryPage.tsx`** — Lists past analyses with subject,
classification, score, and date.

### Rules

```
rules/
├── authentication_rules.yaml      # SPF/DKIM/DMARC rules
├── sender_rules.yaml              # Sender identity rules
└── url_rules.yaml                 # URL analysis rules
```

YAML files that define rules in a human-readable format. An
administrator can add new rules without writing Python code.

### Infrastructure

```
docker-compose.yml                 # Orchestrates all services
backend/Dockerfile                 # Backend container
frontend/Dockerfile                # Frontend container
```

**`docker-compose.yml`** — Defines four services:
1. **PostgreSQL** — Database for storing analyses
2. **Redis** — Cache (prepared for future use)
3. **Backend** — The Python API server
4. **Frontend** — The React dashboard

---

## 8. The API — How Software Talks to This System

The backend exposes a REST API. Here's how it works:

### Analyze an Email

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -F "email=@suspicious_email.eml"
```

**Response:**
```json
{
  "schema_version": "1.0",
  "analysis_id": "a1b2c3d4-...",
  "metadata": {
    "subject": "Urgent: Verify your account",
    "from": "security@micros0ft-example.com"
  },
  "sender": {
    "display_name": "Microsoft Security",
    "from_domain": "micros0ft-example.com",
    "reply_to_domain": "attacker.com"
  },
  "authentication": {
    "spf": "fail",
    "dkim": "pass",
    "dmarc": "fail"
  },
  "urls": [
    {
      "raw_url": "http://1.2.3.4/verify",
      "features": {
        "is_ip_address": true,
        "is_https": false
      }
    }
  ],
  "signals": [
    {
      "signal_id": "AUTH-S001",
      "category": "authentication",
      "severity": 0.7,
      "risk_contribution": 10.0,
      "explanation": "DMARC authentication failed."
    },
    {
      "signal_id": "SND-S001",
      "category": "sender",
      "severity": 0.8,
      "risk_contribution": 12.0,
      "explanation": "Reply-To domain differs from the sender domain."
    }
  ],
  "risk": {
    "score": 78.5,
    "confidence": 0.85,
    "classification": "phishing"
  },
  "verdict": {
    "classification": "phishing",
    "reasons": ["DMARC authentication failed.", ...],
    "recommended_action": "This email is very likely phishing. Quarantine immediately and investigate."
  },
  "explanation": {
    "risk_label": "CRITICAL — LIKELY PHISHING",
    "narrative": "An email claiming to be from 'Microsoft Security' was sent from micros0ft-example.com. Authentication checks failed: SPF, DMARC. ...",
    "recommended_action": "This email is very likely phishing. Quarantine immediately and investigate."
  }
}
```

---

## 9. The Frontend — What the Analyst Sees

The React dashboard provides a visual interface:

1. **Upload page:** Drag-and-drop zone with a description of what
   gets analyzed
2. **Result page:**
   - Large color-coded score ring (green/yellow/orange/red)
   - Classification badge
   - Plain-English narrative
   - Authentication status (three colored circles for SPF/DKIM/DMARC)
   - Email details table
   - URL table with suspicious indicators
   - Attachment table with danger flags
   - All signals ranked by risk contribution
   - ML prediction probability
   - Score breakdown bar
3. **History page:** Table of past analyses with sorting

The frontend communicates with the backend via the REST API.

---

## 10. Security — How We Protect Against Malicious Emails

Since we're analyzing **untrusted input**, the system itself could be
attacked through the emails it processes. Here's how we defend:

| Threat | Defense |
|--------|---------|
| **Oversized emails** | 10 MB limit enforced before parsing |
| **Huge attachments** | 25 MB per-attachment limit |
| **MIME bombs** | MIME depth limited to 30 levels |
| **Attachment execution** | Attachments are NEVER executed, only metadata extracted |
| **SSRF via URL fetching** | We don't fetch external URLs at all in MVP |
| **HTML injection** | HTML is sanitized before display |
| **XSS in dashboard** | React escapes content by default |
| **Credential leakage** | Email content is not logged |
| **Data persistence** | Sensitive data stored in encrypted database columns |

**Core principle:** Everything inside an email is untrusted input.
We never execute, render, or fetch anything from the email content.

---

## 11. The Test Suite — How We Know It Works

The project has **137 automated tests** across 8 test files:

| Test File | Tests | What It Covers |
|-----------|-------|----------------|
| `test_parser.py` | 14 | Email parsing, edge cases, error handling |
| `test_analyzers.py` | 58 | All 7 analyzers + relationship analyzer |
| `test_rules.py` | 12 | Rule engine with various feature combinations |
| `test_scoring.py` | 12 | Risk scoring, signal fusion, category caps |
| `test_ml.py` | 8 | ML prediction, feature extraction |
| `test_explanation.py` | 6 | Explanation generation for all classifications |
| `test_pipeline.py` | 16 | Full pipeline integration with real emails |
| `test_api.py` | 11 | API endpoints, error handling |

Run all tests with:
```bash
cd backend
SKIP_DB=1 python -m pytest tests/ -v
```

---

## 12. Docker — How to Run Everything

With Docker Compose, one command starts everything:

```bash
docker compose up --build
```

This starts:
- **PostgreSQL** on port 5432
- **Redis** on port 6379
- **Backend API** on port 8000
- **Frontend Dashboard** on port 3000

Then open http://localhost:3000 in your browser.

Without Docker:
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

---

## 13. What Makes This "Enterprise-Grade"

This isn't a toy project. It's designed for real-world use:

1. **Modularity:** Every component is independent and replaceable.
   You can swap the ML model, add new analyzers, or change the
   scoring without touching other parts.

2. **Explainability:** Every decision comes with reasons. A security
   analyst can understand and trust the output.

3. **Configurability:** Rules are in YAML. Thresholds are in config.
   No code changes needed for tuning.

4. **Reproducibility:** Every analysis stores the parser version,
   rule version, and model version. You can reproduce any past
   decision.

5. **Testability:** 137 tests cover every module. Each analyzer can
   be tested in isolation.

6. **Security-first:** Untrusted input handling, no attachment
   execution, SSRF protection, input validation.

7. **Scalable architecture:** The four-stage separation
   (Extraction → Detection → Scoring → Decision) allows independent
   scaling of each stage.

8. **Database-backed:** Analyses are persisted with full feature
   snapshots (JSONB) for later analysis and ML training.

9. **Feedback loop:** Analysts can provide feedback on classifications,
   which can be used to retrain the ML model.

10. **Docker-ready:** One command to deploy the entire stack.

---

## 14. Glossary of Terms

| Term | What It Means |
|------|---------------|
| **.eml** | A file format for saving email messages |
| **SPF** | Sender Policy Framework — checks if the sending server is authorized |
| **DKIM** | DomainKeys Identified Mail — checks if the email is digitally signed |
| **DMARC** | Domain-based Message Authentication — alignment check for SPF/DKIM |
| **Reply-To** | The address where replies go (can differ from From) |
| **Return-Path** | The address for bounce messages |
| **Punycode** | A way to encode international domain names (e.g., Cyrillic → ASCII) |
| **Homoglyph** | Characters from different scripts that look identical (а vs a) |
| **TLD** | Top-Level Domain — the .com, .org, .xyz part of a domain |
| **SSRF** | Server-Side Request Forgery — an attack that makes the server fetch internal resources |
| **TF-IDF** | Term Frequency–Inverse Document Frequency — a way to represent text as numbers |
| **Logistic Regression** | A simple ML classifier that outputs probabilities |
| **Signal** | A single security finding from a rule or ML model |
| **Risk Score** | A 0–100 number representing how likely the email is phishing |
| **Confidence** | How sure the system is about its classification |
| **Category Cap** | Maximum points a single category can contribute to the score |
| **Attack Narrative** | A plain-English explanation of the phishing attempt |
| **JSONB** | PostgreSQL's binary JSON column type for flexible storage |
| **Pydantic** | A Python library for data validation and serialization |
| **FastAPI** | A modern Python web framework for building APIs |
| **SQLAlchemy** | A Python library for working with databases |
| **React** | A JavaScript library for building user interfaces |
| **TypeScript** | JavaScript with type checking |
| **Docker** | A tool for packaging applications into containers |

---

*This document explains the Phishing Mail Detector project as of
version 1.0. The system is designed to evolve — each module can be
improved, replaced, or extended independently.*
