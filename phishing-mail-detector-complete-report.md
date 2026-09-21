# Phishing Mail Detector --- Complete Project Report

**Version:** 1.0\
**Project:** Phishing Mail Detector\
**Type:** Cybersecurity / Email Threat Detection / Machine Learning

## 1. Executive Summary

The Phishing Mail Detector is a security analysis platform that
determines whether an email is **Benign, Suspicious, or Phishing**.

It combines:

-   Email header analysis
-   SPF, DKIM and DMARC
-   Sender and domain analysis
-   URL analysis
-   HTML analysis
-   NLP/content analysis
-   Attachment static analysis
-   Deterministic rules
-   Machine learning
-   Relationship analysis
-   Explainable risk scoring

Core principle:

> **Everything inside an email is untrusted input.**

------------------------------------------------------------------------

## 2. Objectives

The system shall:

1.  Securely accept `.eml` and raw email input.
2.  Parse headers, MIME parts, text, HTML, URLs and attachments.
3.  Extract security-relevant features.
4.  Detect phishing using rules and ML.
5.  Combine signals into a 0--100 risk score.
6.  Explain why the email was classified.
7.  Provide analyst-oriented evidence and recommendations.
8.  Store versioned analysis results.
9.  Remain modular enough for enterprise expansion.

------------------------------------------------------------------------

## 3. Scope

### MVP Scope

-   `.eml` ingestion
-   Secure MIME parsing
-   Header analysis
-   SPF/DKIM/DMARC extraction
-   Sender/Reply-To analysis
-   URL extraction and structural analysis
-   Domain analysis
-   Content/NLP features
-   HTML structure analysis
-   Static attachment analysis
-   Rule engine
-   ML baseline
-   Risk scoring
-   Explainability
-   REST API
-   Analyst dashboard
-   Analysis history
-   Analyst feedback

### Out of Scope for MVP

-   Attachment execution
-   Arbitrary URL browsing
-   Malware sandboxing
-   Automatic email deletion
-   Automatic attacker response
-   Full Microsoft 365/Google Workspace integration
-   Autonomous incident response
-   Kubernetes deployment

------------------------------------------------------------------------

## 4. Functional Requirements

  ID      Requirement
  ------- --------------------------------------------
  FR-01   Accept `.eml` and raw email input
  FR-02   Parse RFC/MIME email structure
  FR-03   Analyze email headers
  FR-04   Analyze SPF, DKIM and DMARC
  FR-05   Analyze sender and Reply-To relationships
  FR-06   Extract and analyze URLs
  FR-07   Analyze sender and URL domains
  FR-08   Analyze message content
  FR-09   Analyze HTML structure
  FR-10   Analyze attachments statically
  FR-11   Execute configurable security rules
  FR-12   Run an ML classifier
  FR-13   Calculate risk score
  FR-14   Produce Benign/Suspicious/Phishing verdict
  FR-15   Generate human-readable explanations
  FR-16   Store analysis history
  FR-17   Accept analyst feedback
  FR-18   Record parser/rule/model versions

------------------------------------------------------------------------

## 5. Non-Functional Requirements

### Security

-   Treat all email content as untrusted.
-   Never execute attachments.
-   Prevent SSRF and unrestricted outbound requests.
-   Sanitize rendered HTML.
-   Enforce file and resource limits.
-   Protect secrets.
-   Apply authentication and authorization.

### Performance

Target MVP latency:

**\< 3 seconds for normal emails**, excluding optional external
intelligence lookups.

### Reliability

An unavailable optional analyzer must not cause the entire analysis to
fail.

### Maintainability

Analyzers, rules, scoring and ML components must be modular.

### Privacy

Sensitive email data must be encrypted and must not be unnecessarily
written to logs.

### Observability

Provide structured logs, metrics, error tracking and audit events.

### Reproducibility

Store:

-   schema version
-   parser version
-   feature version
-   rule version
-   model version

------------------------------------------------------------------------

# 6. System Architecture

``` text
                         USERS / SOC
                             |
                             v
                     React + TypeScript
                       Analyst Dashboard
                             |
                           HTTPS
                             |
                             v
                    FastAPI REST Backend
                 Auth / Validation / API Layer
                             |
                             v
                   Secure Email Processing
                             |
          +------------------+------------------+
          |                  |                  |
          v                  v                  v
    Header Analyzer      URL Analyzer      Content Analyzer
          |                  |                  |
          v                  v                  v
    Auth Analyzer       Domain Intel          NLP / ML
          |                  |                  |
          +------------------+------------------+
                             |
                             v
                     Feature Store / JSON
                             |
                    +--------+--------+
                    |                 |
                    v                 v
                Rule Engine       ML Classifier
                    |                 |
                    +--------+--------+
                             |
                             v
                    Signal Fusion Engine
                             |
                             v
                       Risk Scoring
                             |
                             v
                    Explanation Engine
                             |
                             v
                  Verdict + Evidence + Action
                             |
                             v
                     Analyst Dashboard
```

------------------------------------------------------------------------

# 7. Complete Detection Workflow

## Step 1 --- Ingestion

``` text
.eml / raw email
      |
      v
React
      |
      v
FastAPI
```

The API performs authentication, validation and size checks.

## Step 2 --- Secure Parsing

Extract:

``` text
From
To
CC
Reply-To
Return-Path
Subject
Date
Message-ID
Received
Authentication-Results
MIME
Text
HTML
URLs
Attachments
```

## Step 3 --- Header Analysis

Check:

-   Reply-To mismatch
-   Return-Path mismatch
-   Message-ID domain mismatch
-   routing characteristics
-   header anomalies

## Step 4 --- Authentication Analysis

Analyze:

``` text
SPF
DKIM
DMARC
```

Authentication failures are signals, not automatic phishing verdicts.

## Step 5 --- Sender Analysis

Analyze:

``` text
Display Name
From Address
From Domain
Reply-To
Return-Path
Brand Similarity
```

## Step 6 --- URL Analysis

Extract and normalize every URL.

Analyze:

``` text
URL length
Domain length
Subdomains
IP address
Punycode
Encoding
Port
Shortener
Suspicious path
Visible/actual destination mismatch
Domain similarity
Reputation
```

## Step 7 --- Content Analysis

Extract:

``` text
Word count
Sentence count
Uppercase ratio
Language
Urgency
Credential request
Financial request
Account action
Threat
Authority impersonation
Call-to-action
```

## Step 8 --- HTML Analysis

Check:

``` text
Forms
Iframes
Scripts
Hidden elements
External resources
Link mismatches
```

## Step 9 --- Attachment Analysis

Extract:

``` text
Filename
Extension
MIME type
Size
SHA-256
Archive structure
Executable indicators
Macro indicators
```

Attachments are never executed.

## Step 10 --- Relationship Analysis

Correlate:

``` text
Sender
Authentication
Brand
Domain
Reply-To
URL
Content
```

Example:

``` text
Claimed Brand -> Microsoft
Sender        -> micros0ft.example
Reply-To      -> attacker.example
URL           -> credential-login.example
Content       -> password verification
```

This produces a stronger combined signal.

## Step 11 --- Rule Detection

Rules convert features into security signals.

``` text
Feature
  |
  v
Rule
  |
  v
Signal
  |
  v
Risk Contribution
```

## Step 12 --- ML Detection

Initial baseline:

``` text
TF-IDF
   |
Logistic Regression
   |
Phishing Probability
```

Advanced models can later include:

-   XGBoost
-   PyTorch
-   Transformers

## Step 13 --- Signal Fusion

Combine:

``` text
Authentication
Sender
URL
Domain
Content
HTML
Attachment
Relationship
ML probability
```

Avoid double-counting correlated indicators by grouping and applying
category caps.

## Step 14 --- Risk Score

Produce:

``` text
0–24    Benign
25–49   Lower/Moderate Risk
50–74   Suspicious
75–100  Phishing
```

Actual thresholds should be tuned using validation data.

## Step 15 --- Explanation

Example:

``` text
HIGH RISK — 89/100

Primary indicators:
- Sender domain resembles a trusted organization.
- DMARC authentication failed.
- Reply-To domain differs from sender.
- Visible URL differs from actual destination.
- Message requests credentials.
```

## Step 16 --- Analyst Action

The policy layer can map risk to actions:

``` text
Allow
Review
Alert
Quarantine
Block
```

Policy remains configurable and separate from detection.

------------------------------------------------------------------------

# 8. Feature Taxonomy

## Header

``` text
from_domain
reply_to_domain
return_path_domain
reply_to_mismatch
return_path_mismatch
received_hop_count
header_count
message_id_domain
message_id_domain_mismatch
date_anomaly
```

## Authentication

``` text
spf_status
dkim_status
dmarc_status
spf_fail
dkim_fail
dmarc_fail
authentication_alignment
```

## Sender

``` text
display_name
sender_domain_length
sender_localpart_length
sender_domain_digit_ratio
sender_domain_hyphen_count
brand_similarity
display_name_brand_match
```

## URL

``` text
url_length
domain_length
path_length
subdomain_count
dot_count
hyphen_count
digit_ratio
is_https
is_ip_address
has_port
has_punycode
has_at_symbol
has_encoded_chars
suspicious_keywords
visible_actual_mismatch
shortener_detected
redirect_count
```

## Domain

``` text
domain_age
domain_first_seen
TLD
subdomain_depth
MX presence
brand similarity
homoglyph detection
known suspicious
known malicious
```

## NLP

``` text
word_count
sentence_count
uppercase_ratio
digit_ratio
punctuation_ratio
language
urgency_score
credential_request_score
financial_request_score
account_action_score
threat_score
authority_impersonation_score
call_to_action_score
```

## HTML

``` text
html_present
html_size
tag_count
form_count
iframe_count
script_count
hidden_element_count
external_resource_count
visible_actual_mismatch_count
```

## Attachments

``` text
attachment_count
filename
extension
mime_type
size
sha256
double_extension
executable
macro_document
archive
nested_archive
html_attachment
```

## Relationships

``` text
from_replyto_consistency
sender_url_consistency
brand_domain_consistency
brand_url_consistency
authentication_identity_consistency
visible_actual_domain_consistency
```

------------------------------------------------------------------------

# 9. Canonical Data Model

``` json
{
  "schema_version": "1.0",
  "analysis": {
    "analysis_id": "uuid",
    "timestamp": "...",
    "parser_version": "1.0.0",
    "rule_version": "1.0.0",
    "model_version": "baseline-v1"
  },
  "metadata": {},
  "sender": {},
  "authentication": {},
  "headers": {},
  "urls": [],
  "content": {},
  "html": {},
  "attachments": [],
  "relationships": {},
  "signals": [],
  "risk": {
    "score": 0,
    "confidence": 0
  },
  "verdict": {
    "classification": "benign",
    "reasons": []
  }
}
```

------------------------------------------------------------------------

# 10. Technology Stack

  Layer                      Technology
  -------------------------- ------------------------
  Frontend                   React + TypeScript
  Backend                    Python + FastAPI
  Validation                 Pydantic
  Email parsing              Python `email`
  HTML                       BeautifulSoup / lxml
  URL parsing                urllib / tldextract
  DNS                        dnspython
  ML baseline                scikit-learn
  Advanced ML                PyTorch / Transformers
  Gradient boosting          XGBoost
  Database                   PostgreSQL
  Cache                      Redis
  Object storage             Local / S3-compatible
  Containers                 Docker
  Local orchestration        Docker Compose
  Reverse proxy              Nginx
  CI/CD                      GitHub Actions
  Monitoring                 Prometheus + Grafana
  Model tracking             MLflow
  Threat intelligence        Optional external APIs
  Enterprise orchestration   Kubernetes

------------------------------------------------------------------------

# 11. Repository Architecture

``` text
phishing-mail-detector/
|
+-- backend/
|   +-- app/
|       +-- api/
|       +-- core/
|       +-- models/
|       +-- schemas/
|       +-- services/
|   +-- tests/
|
+-- detector/
|   +-- parser/
|   +-- analyzers/
|       +-- headers/
|       +-- sender/
|       +-- authentication/
|       +-- urls/
|       +-- domain/
|       +-- content/
|       +-- html/
|       +-- attachments/
|   +-- rules/
|   +-- scoring/
|   +-- explanation/
|   +-- ml/
|
+-- datasets/
+-- models/
+-- frontend/
+-- tests/
+-- docker/
+-- docs/
+-- rules/
+-- requirements.txt
+-- docker-compose.yml
+-- README.md
```

------------------------------------------------------------------------

# 12. API Design

## Analyze

``` http
POST /api/v1/analyze
```

## Retrieve result

``` http
GET /api/v1/analyses/{analysis_id}
```

## Feedback

``` http
POST /api/v1/analyses/{analysis_id}/feedback
```

## Health

``` http
GET /health
```

Example response:

``` json
{
  "analysis_id": "a123",
  "risk_score": 89,
  "confidence": 0.93,
  "classification": "phishing",
  "signals": []
}
```

------------------------------------------------------------------------

# 13. Database Design

## PostgreSQL

### analyses

``` text
id
message_id
timestamp
risk_score
confidence
classification
parser_version
feature_version
rule_version
model_version
features_json
created_at
```

### signals

``` text
id
analysis_id
signal_id
category
severity
risk_contribution
source
explanation
```

### Additional entities

``` text
users
rules
feedback
model_versions
audit_events
```

JSONB can store detailed feature structures during MVP.

------------------------------------------------------------------------

# 14. Security Architecture

The detector must defend against malicious input.

## Threats

-   malicious parser input
-   HTML injection/XSS
-   SSRF
-   malicious attachments
-   decompression bombs
-   resource exhaustion
-   credential leakage
-   sensitive-data leakage
-   unauthorized analysis access
-   model evasion
-   training-data poisoning

## Security controls

``` text
Input validation
File-size limits
MIME limits
Parsing timeouts
No attachment execution
No unrestricted URL fetching
HTML sanitization
SSRF protection
Authentication
RBAC
Encrypted storage
Encrypted transport
Audit logging
Dependency scanning
Fuzz testing
```

------------------------------------------------------------------------

# 15. Usage

## Analyst

1.  Login.
2.  Upload `.eml`.
3.  Start analysis.
4.  Review risk score.
5.  Inspect evidence.
6.  Inspect headers/URLs/attachments.
7.  Decide whether further investigation is required.
8.  Provide feedback.

## Administrator

-   manage users
-   manage rules
-   manage model versions
-   inspect system health
-   inspect audit logs
-   configure policies

------------------------------------------------------------------------

# 16. Development Roadmap

## Phase 1 --- Foundation

-   Email parser
-   Header analyzer
-   URL extractor
-   Basic content analyzer
-   Attachment analyzer
-   Rule engine
-   Risk scoring
-   FastAPI
-   Tests

## Phase 2 --- MVP

-   PostgreSQL
-   React dashboard
-   YAML rules
-   Domain analysis
-   ML baseline
-   Explanation engine
-   Docker Compose
-   Analysis history

## Phase 3 --- Advanced Detection

-   Transformer NLP
-   XGBoost feature model
-   Brand impersonation
-   Reputation intelligence
-   Relationship graph
-   Model calibration
-   Curated feedback pipeline

## Phase 4 --- Enterprise

-   RBAC
-   SIEM integration
-   SOAR integration
-   Microsoft 365 / Google Workspace
-   Message queues
-   Distributed workers
-   Kubernetes
-   Multi-tenancy
-   Advanced threat intelligence

------------------------------------------------------------------------

# 17. Evaluation

Measure:

-   Precision
-   Recall
-   F1
-   ROC-AUC
-   PR-AUC
-   False Positive Rate
-   False Negative Rate
-   Probability calibration
-   Per-category detection performance

The test set should be isolated from training data. Temporal separation
is preferred where data permits it.

------------------------------------------------------------------------

# 18. Novelty

The project should not be positioned simply as:

> "An ML model that detects phishing emails."

The stronger concept is:

> **An explainable multi-signal phishing detection engine that
> correlates email identity, authentication, domain, URL, content, HTML,
> attachment and behavioral relationships into a unified risk
> assessment.**

The output is therefore not only:

``` text
PHISHING — 89/100
```

but also:

``` text
Why?

Sender impersonation
+
Authentication anomaly
+
Credential request
+
Suspicious destination
+
Reply-To inconsistency
```

This creates an analyst-readable **attack narrative**.

------------------------------------------------------------------------

# 19. MVP Acceptance Criteria

The MVP is complete when:

-   [ ] `.eml` can be uploaded.
-   [ ] Email is securely parsed.
-   [ ] Headers are analyzed.
-   [ ] SPF/DKIM/DMARC are extracted.
-   [ ] Sender relationships are analyzed.
-   [ ] URLs are extracted and analyzed.
-   [ ] Content signals are extracted.
-   [ ] HTML is statically analyzed.
-   [ ] Attachments are statically analyzed.
-   [ ] Rules generate signals.
-   [ ] ML baseline generates a probability.
-   [ ] Signals are fused.
-   [ ] Risk score is calculated.
-   [ ] Verdict is generated.
-   [ ] Explanation is generated.
-   [ ] Results are persisted.
-   [ ] Core components have automated tests.
-   [ ] Attachments are never executed.
-   [ ] Arbitrary URLs are not automatically fetched.
-   [ ] Sensitive email contents are not unnecessarily logged.

------------------------------------------------------------------------

# 20. Final System Workflow

``` text
                EMAIL
                  |
                  v
          Secure Ingestion
                  |
                  v
            Email Parser
                  |
                  v
        Normalized Email Object
                  |
       +----------+----------+
       |          |          |
       v          v          v
    Headers      URLs      Content
       |          |          |
       v          v          v
 Authentication Domain      NLP
       |          |          |
       +----------+----------+
                  |
                  v
             HTML / Files
                  |
                  v
          Feature Extraction
                  |
                  v
         Relationship Analysis
                  |
                  v
            Feature Store
                  |
          +-------+-------+
          |               |
          v               v
      Rule Engine      ML Model
          |               |
          +-------+-------+
                  |
                  v
            Signal Fusion
                  |
                  v
             Risk Engine
                  |
                  v
          Explanation Engine
                  |
                  v
       +----------+----------+
       |                     |
       v                     v
    Verdict              Evidence
       |                     |
       +----------+----------+
                  |
                  v
          Analyst Dashboard
                  |
                  v
        Feedback / Policy Action
```

------------------------------------------------------------------------

# 21. Final Design Principle

The detector is built around four separations:

``` text
Extraction
    !=
Detection
    !=
Scoring
    !=
Decision
```

This separation makes the system easier to:

-   test
-   explain
-   debug
-   secure
-   retrain
-   scale
-   integrate with enterprise security platforms

The initial implementation should prioritize **security, correctness,
explainability, and testability** before adding enterprise-scale
infrastructure.
