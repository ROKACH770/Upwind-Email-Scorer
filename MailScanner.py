
from typing import NamedTuple
from functools import lru_cache
import numpy as np
from sentence_transformers import SentenceTransformer

import re
from difflib import SequenceMatcher
from typing import List, Optional
import Levenshtein


#  MANUAL SCANNERS
def scan_reply_to_mismatch(sender_email_lower: str, reply_to_email_lower: str) -> float:
    if not reply_to_email_lower or sender_email_lower == reply_to_email_lower:
        return 0.0

    # Extract the domains
    sender_domain = sender_email_lower.split("@")[-1] if "@" in sender_email_lower else ""
    reply_domain = reply_to_email_lower.split("@")[-1] if "@" in reply_to_email_lower else ""

    if sender_domain and reply_domain and sender_domain != reply_domain:
        return 0.37

    return 0.0
def scan_outbound_history(outbound_count: int, inbound_count: int) -> float:
    """
    Evaluates the trust level based on previous outbound communications.
    """
    if outbound_count == 0:
        if inbound_count == 0:
            return 0.05
        return 0.0

    if outbound_count >= 5:
        return 1.0  # most likely safe

    return outbound_count / 5.0


def scan_brand_whitelist_deterministic(sender_name_lower: str, sender_email_lower: str) -> float:
    """
    Manual scanner for known brand
    """
    protected_brands = {
        "paypal": "paypal.com",
        "microsoft": "microsoft.com",
        "google": "google.com",
        "apple": "apple.com",
        "amazon": "amazon.com",
        "instagram": "instagram.com",
        "facebook": "facebook.com",
        "netflix": "netflix.com",
        "fedex": "fedex.com",
        "dropbox": "dropbox.com",
        "zoom": "zoom.us",
        "linkedin": "linkedin.com",
        "spotify": "spotify.com",
        "bank hapoalim": "bankhapoalim.co.il",
    }

    for brand, official_domain in protected_brands.items():
        if brand in sender_name_lower:
            if official_domain not in sender_email_lower:
                return 1.0

    return 0.0


def scan_typos(sender_domain: str) -> float:
    """
    Detects typos attacks using the Levenshtein distance    """
    if not sender_domain:
        return 0.3  # Suspicious if domain is missing

    protected_domains = [
        "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
        "walla.co.il", "bezeqint.net", "netvision.net.il", "013net.net"
    ]

    for protected_domain in protected_domains:
        if sender_domain == protected_domain:
            continue

        distance = Levenshtein.distance(sender_domain, protected_domain)

        if distance == 1 or distance == 2:
            return 1.0

    return 0.0


def score_link_deception(visible_text_lower: str, real_domain: str) -> float:
    """
    Evaluates links for hidden redirections and lookalike domains.
    Expects pre-lowercased visible text and the pre-parsed real domain.
    """
    if not visible_text_lower or not real_domain:
        return 0.3  # Suspicious if either is missin

    scores = []
    text_looks_like_url = "." in visible_text_lower and " " not in visible_text_lower

    if text_looks_like_url:
        text_domain = visible_text_lower.lstrip("www.").split("/")[0]  # domain from visible text

        if text_domain not in real_domain and real_domain not in text_domain:
            scores.append(0.95)
        else: # means they share some parts
            #we compre only the roots domain
            text_root = ".".join(text_domain.split(".")[-2:])
            real_root = ".".join(real_domain.split(".")[-2:])

            if text_root != real_root: #if the roots are different ,probably fisihng
                scores.append(0.85)
            else:
                scores.append(0.0) #same root domain
        # We also check the overall similarity to catch more subtle cases
        #simloarity gives us a score between 0 and 1, where 1 means identical and 0 means different and also it sure reliability + simplicity + sufficient performance
        similarity = SequenceMatcher(None, text_domain, real_domain).ratio()
        if 0.6 < similarity < 1.0:
            #Convert similarity to risk score try to avoid false positives using 1-similarity
            scores.append(min((1.0 - similarity) * 2.0, 0.8))

    structure_score = 0.0
    if re.match(r"^\d+\.\d+\.\d+\.\d+", real_domain):
        structure_score = max(structure_score, 0.7) # IP address in domain is highly suspicious

    subdomain_count = real_domain.count(".")
    if subdomain_count >= 3:
        structure_score = max(structure_score, 0.4 + 0.1 * (subdomain_count - 3))

    if ":" in real_domain:
        structure_score = max(structure_score, 0.5)

    scores.append(structure_score)
    return round(min(max(scores, default=0.0), 1.0), 3) #we use max cuz 1 strong signal is enough to flag it as phishing


def detect_url_shortener(real_domain: str) -> float:
    """
    Detects if a URL is using a shortening service."""
    if not real_domain:
        return 0.0

    shorteners = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl",
        "ow.ly", "is.gd", "buff.ly", "cutt.ly"
    ]

    if any(short in real_domain for short in shorteners):
        return 1.0 # Shortened URLs mostly used for phishing

    return 0.0


def scan_recipient_anomaly(recipients_lower: Optional[List[str]], user_email_lower: str,
                           high_recipient_threshold: int = 10) -> float:
    """BCC= Blind Carbon Copy, means the sender hides the recipient list"""
    if not recipients_lower:
        return 0.02

    score = 0.0

    def clean_email(raw_address: str) -> str:
        """Helper to extract the raw email from a formatted string."""
        match = re.search(r'<(.*?)>', raw_address)
        return match.group(1).strip().lower() if match else raw_address.strip().lower()

    clean_recipients = [clean_email(r) for r in recipients_lower]

    if user_email_lower not in clean_recipients:
        score += 0.5

    recipient_count = len(recipients_lower)
    if recipient_count >= high_recipient_threshold:
        excess_recipients = max(0, recipient_count - high_recipient_threshold)
        count_penalty = min(0.5, 0.2 + (excess_recipients * 0.02))
        score += count_penalty
    return round(min(1.0, score), 3)  #  doesn't necessarily phishing but increases risk


def analyze_sender_time_baseline(past_sending_hours: List[int]) -> bool:
    """
    Analyzes historical sending hours.
    """
    if not past_sending_hours or len(past_sending_hours) < 3:
        return False

    daytime_email_count = sum(1 for hour in past_sending_hours if 6 <= hour <= 22)
    daytime_ratio = daytime_email_count / len(past_sending_hours)
    if daytime_ratio >= 0.8:
        return True # The sender a daytime sender
    return False




def scan_unusual_sending_time(current_sending_hour: int, past_sending_hours: List[int]) -> float:
    """
    Detects if an email arrives at an unusual night hour from a daytime sender.
    """
    is_current_email_nighttime = current_sending_hour >= 23 or current_sending_hour <= 5
    is_historical_day_sender = analyze_sender_time_baseline(past_sending_hours)

    if is_historical_day_sender and is_current_email_nighttime:
        return 0.8 #Normal users have stable sending patterns

    return 0.0


def scan_brand_trust(sender_domain: str) -> float:
    """Checks if the sender email domain belongs to a trusted official brand."""
    trusted_domains = {
        "google.com", "microsoft.com", "paypal.com", "apple.com", "amazon.com",
        "netflix.com", "github.com", "linkedin.com", "zoom.us", "facebook.com",
        "instagram.com", "twitter.com", "dropbox.com", "spotify.com"
    }


    for trusted in trusted_domains:
        if sender_domain == trusted or sender_domain.endswith("." + trusted):
            return 1.0

    return 0.0

# AI INITIALIZATION runs only once when the server starts, thanks to @lru_cache

# Dictionaries for AI Intent matching
_INTENT_ANCHORS = {
    "account_takeover": [
        "Your account has been compromised and requires immediate verification",
        "Unusual login detected – confirm your identity to restore access",
        "We noticed suspicious activity on your account, please verify now",
        "Someone tried to access your account from an unknown device",
        "Confirm your identity immediately to restore access to your account",
        "We have detected an unauthorized login attempt on your account",
    ],
    "payment_fraud": [
        "Your payment method has expired, update your billing information",
        "There is an outstanding balance on your account, pay immediately",
        "Your subscription payment failed, click here to update your card",
        "A wire transfer is pending your approval, login to review",
        "Please login to approve the pending transaction before it expires",
        "Your bank account requires immediate verification to release funds",
        "Transfer of funds is on hold, confirm your identity to proceed",
        "A transaction of $3,450 requires your immediate approval",
        "Your billing information is outdated, update now to avoid interruption",
    ],
    "prize_social_engineering": [
        "You have been selected to receive a special reward",
        "Congratulations, you won a gift card, claim your prize now",
        "You have been chosen as our weekly winner, claim your prize",
        "You have unclaimed funds waiting, submit your details to receive them",
        "You are eligible for a special cashback reward, claim it now",
    ]
}

_URGENCY_ANCHORS = {
    "urgency": [
        "You must act immediately to prevent suspension",
        "This is your final warning before your account is closed",
        "Immediate response is required to resolve this security issue",
        "We will terminate your access within the next 24 hours",
        "Your account will be permanently deleted if you do not act now",
        "Failure to respond within 24 hours will result in account termination",
        "Immediate action required to secure your account",
        "Download our security tool now to fix the breach",
        "We detected suspicious activity on your device",
        "Your device has been compromised, immediate action required",
        "Failure to act now will result in permanent data loss",
        "You must verify your identity within the next hour or lose access",
        "This offer expires in 24 hours, act now before it is too late",
        "Your account will be suspended unless you respond immediately",
    ]
}

_ACTION_ANCHORS = {
    "action": [
        "Click the link below to verify your login credentials",
        "Please download the attachment to view your invoice",
        "Fill out the form and submit your personal details",
        "Login to your portal now to complete the update",
        "Download our security tool now to protect your device",
        "Click here to fix the security issue on your device",
        "Submit your bank details to receive the transfer",
        "Enter your personal information to claim your reward",
        "Click the button below to approve the pending transaction",
        "Scan the QR code to verify your identity and restore access",
    ]
}

_CORPORATE_PERSONAS = [
    "customer support team",
    "billing and invoice department",
    "security alert administration",
    "human resources desk",
    "it helpdesk",
    "account security team",
    "payment processing department",
    "fraud prevention team",
    "technical support center",
    "verification department",
]

@lru_cache(maxsize=1)
def load_ai_infrastructure():
    """
    Loads the AI model and computes all vectors.
    Thanks to @lru_cache, this function executes exactly ONCE when the server starts
    """
    model = SentenceTransformer("all-MiniLM-L6-v2")

    all_anchor_embeddings = {
        "intent": {},
        "urgency": {},
        "action": {}
    }

    anchor_set = {
        "intent": _INTENT_ANCHORS,
        "urgency": _URGENCY_ANCHORS,
        "action": _ACTION_ANCHORS
    }
    for key, anchors in anchor_set.items():
        for category, sentences in anchors.items():
            # the matrix of vectors
            all_anchor_embeddings[key][category] = model.encode(sentences, normalize_embeddings=True)

    persona_embeddings = model.encode(_CORPORATE_PERSONAS, normalize_embeddings=True)

    return model, all_anchor_embeddings, persona_embeddings



# AI SCANNERS:

def scan_brand_ai(sender_name: str, sender_email: str) -> float:
    """
    AI Scanner for Brand Spoofing.
    Checks if the display name sounds corporate, but the email domain is a free provider.
    """
    email_lower = sender_email.lower()
    name_lower = sender_name.lower()

    domain = email_lower.split('@')[-1] if '@' in email_lower else ""
    generic_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]

    # We only run the AI check if the email comes from a generic domain
    if domain in generic_domains:
        try:
            # Fetch the preloaded model and vectors
            model, all_anchor_centroids, persona_embeddings = load_ai_infrastructure()

            # Encode the incoming sender name
            name_embedding = model.encode([name_lower], normalize_embeddings=True)[0] #we get the sender vec

            # Calculate similarity
            similarities = np.dot(persona_embeddings, name_embedding)
            max_score = float(similarities.max())

            if max_score > 0.65:
                return max_score
        except Exception:
            return 0.0

    return 0.0


class ThreatScore(NamedTuple):
    urgency: float
    action: float
    intent: float


def scan_text_with_ai(body: str, subject: str = "") -> ThreatScore:
    """AI Scanner for Text Analysis"""
    try:
        model, anchor_embeddings, _ = load_ai_infrastructure()
    except Exception:
        return ThreatScore(0.0, 0.0, 0.0)

    full_text = f"{subject}\n{body}".strip()
    email_vector = model.encode([full_text], normalize_embeddings=True)[0]

    scores = {}

    # Iterate over the categories to define category_name and category_dict
    for category_name, category_dict in anchor_embeddings.items():
        max_similarity = 0.0

        for embeddings_matrix in category_dict.values():
            similarities = np.dot(embeddings_matrix, email_vector)
            current_max = float(similarities.max())

            if current_max > max_similarity:
                max_similarity = current_max

        if max_similarity > 0.4:
            score = max(0.0, (max_similarity - 0.4) / 0.55)
        else:
            score = 0.0

        scores[category_name] = score

    total = (
            scores["urgency"] * 0.25 +
            scores["action"] * 0.30 +
            scores["intent"] * 0.45
    )

    if scores["urgency"] >= 0.65 and scores["action"] >= 0.65:
        total += 0.15

    return ThreatScore(
        urgency=round(scores["urgency"], 3),
        action=round(scores["action"], 3),
        intent=round(scores["intent"], 3),
    )