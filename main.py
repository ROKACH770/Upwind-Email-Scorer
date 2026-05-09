import math
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from fastapi import FastAPI,Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from typing import List, Optional
import urllib.parse

from MailScanner import*


class LinkData(BaseModel):
    text: str
    url: str


class EmailPayload(BaseModel):
    """
    Validates incoming data from the Google Addon.
    Ensures all necessary data is present before processing.
    """
    user_email: str
    sender_name: str
    sender_email: str
    reply_to: Optional[str] = None
    recipients: List[str] = []
    subject: str
    body: str
    links: List[LinkData] = []
    outbound_count: int = 0
    inbound_count: int = 0
    current_sending_hour: int
    past_sending_hours: List[int] = []



# RISK ENGINE


class RiskEngine:
    def __init__(self):
        self.weights = {
            # Deterministic weights
            "outbound_history": -90,     # Negative because it reduces risk
            "reply_to_mismatch": 60,
            "brand_whitelist_check": 60,
            "typosquatting": 60,
            "hidden_url": 50,
            "shortened_urls": 50,
            "recipient_count_anomaly": 15,
            "unusual_sending_time": 10,

            # AI weights
            "generic_provider_vs_brand": 50,
            "intent_mapping": 45,
            "urgency_threat": 37,
            "actionable_request": 60,
        }
        self.threshold = 45

    def calculate_sigmoid(self, z: float) -> float:
        return 100 / (1 + math.exp(-(z - self.threshold)))

    def get_final_score(self, detection_scores: dict) -> int:
        weighted_sum = 0.0
        for signal, score in detection_scores.items():
            if signal in self.weights:
                weighted_sum += self.weights[signal] * score
        return math.floor(self.calculate_sigmoid(weighted_sum))




#ULOAD AI MODELS AND RESOURCES
#make sure to upload only once to save time and costs
@asynccontextmanager
async def lifespan(app: FastAPI):
    load_ai_infrastructure()
    yield

app = FastAPI(title="Email Scorer API", lifespan=lifespan)
engine = RiskEngine()
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "score": 50,
            "verdict": "SUSPICIOUS",
            "reasons": ["This email could not be fully analyzed treat it carefully ."],
            "ai_used": False,
            "breakdown": {}
        }
    )


def verdict_from_score(score: int) -> str:
    """Converts a score into a verdict."""
    if score >= 75:
        return "PHISHING"
    if score >= 32:
        return "SUSPICIOUS"
    return "SAFE"



#Humanreadable reasons for signals that contributed to the score used in the Google Addon UI
# Only signals that score above this threshold will generate a reason for the user
SIGNAL_THRESHOLD = 0.75
TRUST_SIGNALS = {"outbound_history"}

# One clear sentence per signal, shown directly in the Google Addon
REASON_TEMPLATES = {
    "reply_to_mismatch":          "The Reply-To address differs from the actual sender a common trick to intercept your reply.",
    "brand_whitelist_check":      "The sender's display name impersonates a well-known brand but the domain is not official.",
    "typosquatting":              "The sender's domain closely resembles a trusted domain and may be an impersonation attempt.",
    "hidden_url":                 "A link in this email displays one address but leads to a completely different destination.",
    "shortened_urls":             "A link uses a URL shortener that hides the real destination.",
    "recipient_count_anomaly":    "You may have been added as a hidden BCC recipient, or this email was sent to an unusually large list.",
    "unusual_sending_time":       "This email arrived at an unusual hour compared to this sender's normal pattern.",
    "generic_provider_vs_brand":  "The sender uses a corporate-sounding name but sends from a free provider like Gmail or Yahoo.",
    "intent_mapping":             "AI detected language patterns consistent with account takeover or payment fraud attempts.",
    "urgency_threat":             "AI detected pressure and threat language — a common social engineering technique.",
    "actionable_request":         "AI detected a request to click a link, download a file, or submit personal information.",
}


def build_reasons(breakdown: dict) -> list[str]:
    """ convert a socre to a reason for the user"""
    reasons = []
    for signal, score in breakdown.items():
        if signal in TRUST_SIGNALS:
            continue
        if score >= SIGNAL_THRESHOLD and signal in REASON_TEMPLATES:
            reasons.append(REASON_TEMPLATES[signal])
    return reasons


@app.post("/analyze")
def analyze_email(payload: EmailPayload):
    """
    Main endpoint orchestrating data preprocessing, fast scanners,
    earlyexit logic, AI if needed"""
    sender_email_lower = payload.sender_email.strip().lower()
    sender_name_lower = payload.sender_name.strip().lower()
    reply_to_lower = payload.reply_to.strip().lower() if payload.reply_to else ""
    user_email_lower = payload.user_email.strip().lower()
    recipients_lower = [e.strip().lower() for e in payload.recipients]

    sender_domain = sender_email_lower.split("@")[1] if "@" in sender_email_lower else ""

    max_link_deception = 0.0
    max_shortener = 0.0
    for link in payload.links:
        visible_text_lower = link.text.strip().lower()
        actual_url_lower = link.url.strip().lower()
        try:
            real_domain = urllib.parse.urlparse(actual_url_lower).netloc.lstrip("www.")
            max_link_deception = max(max_link_deception, score_link_deception(visible_text_lower, real_domain))
            max_shortener = max(max_shortener, detect_url_shortener(real_domain))
        except Exception:
            pass

    #Fast Deterministic Scanners
    fast_path_scores = {
        "reply_to_mismatch": scan_reply_to_mismatch(sender_email_lower, reply_to_lower),
        "outbound_history": scan_outbound_history(payload.outbound_count, payload.inbound_count),
        "brand_whitelist_check": scan_brand_whitelist_deterministic(sender_name_lower, sender_email_lower),
        "typosquatting": scan_typos(sender_domain),
        "recipient_count_anomaly": scan_recipient_anomaly(recipients_lower, user_email_lower),
        "unusual_sending_time": scan_unusual_sending_time(payload.current_sending_hour, payload.past_sending_hours),
        "hidden_url": max_link_deception,
        "shortened_urls": max_shortener,
    }

    intermediate_score = engine.get_final_score(fast_path_scores)

    # Early Exit
    if intermediate_score >= 60:
        verdict = verdict_from_score(intermediate_score)
        return {
            "score": intermediate_score,
            "verdict": verdict,
            "breakdown": fast_path_scores,
            "reasons": build_reasons(fast_path_scores),
            "ai_used": False,
        }

    # AI Scanners
    ai_text_analysis = scan_text_with_ai(payload.body, payload.subject)
    ai_brand_score = scan_brand_ai(payload.sender_name, payload.sender_email)

    final_scores = fast_path_scores.copy()
    final_scores.update({
        "generic_provider_vs_brand": ai_brand_score,
        "intent_mapping": ai_text_analysis.intent,
        "urgency_threat": ai_text_analysis.urgency,
        "actionable_request": ai_text_analysis.action,
    })

    # Final Verdict
    final_score = engine.get_final_score(final_scores)
    verdict = verdict_from_score(final_score)

    return {
        "score": final_score,
        "verdict": verdict,
        "breakdown": final_scores,
        "reasons": build_reasons(final_scores),
        "ai_used": True,
    }