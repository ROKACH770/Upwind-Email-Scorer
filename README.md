---
title: Email-Scorer
emoji: 📧
colorFrom: blue
colorTo: indigo
sdk: docker
pinned: false
---
# Email Phishing Detector:Gmail Addon

A Gmail Addon that scores emails for phishing risk. Open an email, see a score from 0 to 100, a verdict, and a short explanation of what looked suspicious all inside Gmail.

How it works
The system has three layers, and that structure was a deliberate decision to save running time:

Layer 1 is the Addon itself, built in Google Apps Script. It extracts everything from the open email and sends it to the backend.

Layer 2 is a set of fast rulebased checks that run on every email: is the sender domain a typo of a known brand, does the Reply To differ from the sender, does a link's visible text hide a different destination, was the email sent at an unusual hour. These take milliseconds and cost almost nothing.

Layer 3 is an AI model (sentencetransformer) that checks the email text for phishing intent, urgency language, and requests to click or submit something. This only runs if the rule based layer could not give a confident answer.
Most phishing is caught by basic rules. Running a transformer model on every single email would be wasteful. The AI is a fallback for the ambiguous cases, not the default path. This keeps CPU usage low and response time fast.

## The Addon UI

The Addon is the part the user actually sees. When you open an email, a panel appears on the right showing the score, the verdict in color, and a short explanation of what looked suspicious.

The explanation is not hardcoded. The backend decides which signals fired and sends back a sentence for each one, so the user sees something like "The sender's domain closely resembles a known brand" instead of just a number.

The Addon is built in Google Apps Script. It reads the email using the Gmail API, builds the payload, sends it to the backend, and displays the result.

## Scoring

Each signal produces a score between 0 and 1, multiplied by a weight, then passed through a sigmoid. I used sigmoid instead of a plain sum because one weak signal should mean almost nothing, but three weak signals together should push the score up significantly.

Outbound history has a negative weight. If you have emailed this person before, that is real evidence the relationship is legitimate and the score goes down.

If a high confidence signal fires (brand impersonation, typosquatting, deceptive link) the history trust gets zeroed out for that email, so a phishing attempt from a known address still gets caught.

## Security

I decided not to use a database at all to keep things simple and secure.

The backend gets the email data, calculates the score in memory, and returns it immediately. Nothing is saved or logged.
I made sure the Addon uses the most restrictive permissions possible (only reading the current open email)

On the Python side, I used a library called Pydantic to make sure the incoming data is exactly what we expect before we touch it. Also, when I check links, I don't just split strings I use a proper URL parser to avoid mistakes with weirdly formatted links.


One small thing: right now the backend doesn't require a password or API key to access. In a real product, I would obviously add authentication, but for this demo, I kept the endpoint open to make it easier to run and test.
Challenges & Solutions
The main difficulty was finding the right balance for the weights of each phishing signal. It was a process of tuning the system between two extremes:
Over Sensitivity: At first, the weights were too high, and legitimate emails from Google or LinkedIn were flagged as PHISHING. I fixed this by adding "Trust Signals" (like outbound communication history) that lower the risk score for known contacts.
The Trust Bias: Adding trust signals caused a new issue where phishing from a known address was marked as SAFE. To solve this, I implemented a "Strong Threat" override. If a high confidence signal is detected (like typosquatting or a deceptive link), the system ignores the history trust and flags the email anyway.
The NoReply Issue: Automated "no reply" emails are tricky because you never email them back, so the outbound history is always zero. I added a check for inbound frequency to help, but it's still a limitation that could be improved with more data.
## What I would do with more time

Calibrate the weights with a real labelled dataset instead of tuning by hand. Right now I adjusted them by testing against a small set of emails which is not the right way to do it.

Replace the hardcoded trusted domain list with a reputation API like Google Safe Browsing or VirusTotal.

Add a feedback button so users can mark a verdict as wrong. That becomes a training signal over time.

Cover attachments. The system ignores them entirely right now and malicious PDFs are a major phishing vector.

## Running locally

```bash
pip install fastapi uvicorn sentence-transformers numpy python-Levenshtein
uvicorn main:app --reload
```

Swagger UI at http://localhost:8000/docs

```bash
pytest test_main.py -v
```

Backend is live at https://rokach-email-scorer.hf.space