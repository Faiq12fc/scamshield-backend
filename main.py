from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re
import requests
from bs4 import BeautifulSoup

app = FastAPI(title="ScamShield AI Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    type: str      # "message", "url", or "store"
    content: str

@app.get("/")
def health_check():
    return {"status": "ok", "service": "ScamShield AI Backend"}

def analyze_url_signals(text: str, score: int, red_flags: list[str]) -> tuple[int, list[str]]:
    if "hxxp://" in text or "hxxps://" in text:
        score += 30
        red_flags.append("Uses obfuscated/defanged 'hxxp' link notation commonly seen in threat lures.")
    if "http://" in text:
        score += 25
        red_flags.append("Uses unencrypted HTTP link (missing HTTPS security).")
    if re.search(r"h(tt|xx)ps?://\d{1,3}(?:\.\d{1,3}){3}", text):
        score += 45
        red_flags.append("Links directly to a raw IP address instead of a legitimate domain.")
    if re.search(r"\.(xyz|top|tk|ml|ga|cf|gq|info|click|work|vip|buzz|online|site)\b", text):
        score += 30
        red_flags.append("Uses a high-risk domain extension frequently abused in phishing.")
    if any(s in text for s in ["bit.ly", "tinyurl", "t.co", "rb.gy", "cutt.ly", "shorturl", "is.gd"]):
        score += 30
        red_flags.append("Uses a URL shortener to hide the true destination.")
    if re.search(r"(login|verify|secure|update|reset|claim|reward|kyc|auth|support|helpdesk|parcel|track)", text) and ("http" in text or "hxxp" in text or "www." in text):
        score += 25
        red_flags.append("URL contains credential-harvesting or delivery-lure keywords.")
    brands = ["meezan", "hbl", "ubl", "alfalah", "jazzcash", "easypaisa", "nayapay", "sadapay", "raast", "bisp", "daraz", "tcs", "leopards"]
    official_domains = ["meezanbank.com", "hbl.com", "ubldigital.com", "bankalfalah.com", "jazzcash.com.pk", "easypaisa.com.pk", "nayapay.com", "sadapay.pk", "daraz.pk", "tcsexpress.com", "leopardscourier.com"]
    if ("http" in text or "hxxp" in text or "www." in text) and any(b in text for b in brands):
        if not any(od in text for od in official_domains):
            score += 40
            red_flags.append("Impersonates a trusted bank, wallet, or courier on an unofficial domain.")
    return score, red_flags

@app.post("/scan")
def scan_content(req: ScanRequest):
    input_type = req.type.strip().lower()
    if input_type not in {"message", "url", "store"}:
        raise HTTPException(status_code=400, detail="type must be 'message', 'url', or 'store'")

    raw_text = req.content.strip()
    if not raw_text:
        raise HTTPException(status_code=400, detail="content cannot be empty")

    score = 0
    red_flags = []
    lower_text = raw_text.lower()

    if input_type == "url":
        target_url = raw_text.replace("hxxp://", "http://").replace("hxxps://", "https://")
        if not target_url.lower().startswith(("http://", "https://")):
            target_url = "http://" + target_url
        lower_text = target_url.lower()
        try:
            res = requests.get(target_url, timeout=4, headers={"User-Agent": "Mozilla/5.0"})
            soup = BeautifulSoup(res.text, "html.parser")
            lower_text += " " + soup.get_text(" ", strip=True).lower()
        except Exception:
            score += 25
            red_flags.append("Website could not be reached or blocked automated inspection.")

    score, red_flags = analyze_url_signals(lower_text, score, red_flags)

    if input_type == "store":
        if "cod" not in lower_text and "cash on delivery" not in lower_text:
            score += 20
            red_flags.append("No Cash on Delivery (COD) option mentioned.")
        if any(p in lower_text for p in ["dm for price", "dm to order", "inbox for price", "whatsapp to order"]):
            score += 20
            red_flags.append("Forces private DM ordering with no transparent checkout.")
        if not any(p in lower_text for p in ["return", "exchange", "refund", "address", "location"]):
            score += 15
            red_flags.append("Missing clear return/exchange policy or physical store details.")

    pattern_rules = [
        (r"\b(otp|mpin|pin\s*code|cvv|passcode|password)\b", 40, "Requests confidential authentication credentials (OTP, PIN, or password)."),
        (r"\b(cnic|id\s*card|nic\s*number)\b", 30, "Requests sensitive CNIC / national identity details."),
        (r"\b(advance\s*payment|registration\s*fee|processing\s*fee|return\s*fees?|security\s*deposit|fee\s*jama|pehle\s*payment)\b", 35, "Demands upfront payment, processing fee, or fake return fee."),
        (r"\b(parcel\s*(is\s*)?(on\s*)?hold|incomplete\s*address|delivery\s*(alert|failed|suspended)|customs\s*fee)\b", 30, "Uses fake parcel-hold or failed-delivery smishing lure."),
        (r"\b(urgent|immediately|act\s*now|abhi|foran|within\s*\d+\s*(hour|hr|minute|min)s?)\b", 20, "Uses artificial urgency or a countdown deadline to induce panic."),
        (r"\b(account\s*(blocked|suspended|restricted|closed|frozen|band)|unauthorized\s*(login|activity))\b", 35, "Uses fake account-suspension or security-alert scare tactics."),
        (r"\b(verify\s*your|confirm\s*your|update\s*your\s*(account|kyc|details)|click\s*(here|below|link))\b", 25, "Prompts you to click a link or verify sensitive details."),
        (r"\b(prize|lottery|winner|lucky\s*draw|inaam|jeeto|benazir|bisp|ehsaas|free\s*(cash|money|iphone|laptop))\b", 30, "Uses unsolicited prize, giveaway, or relief-fund bait."),
        (r"\b(no\s*return|no\s*refund|no\s*exchange|non\s*refundable)\b", 25, "Enforces a strict no-return / no-refund policy."),
        (r"\b(only\s*\d+\s*left|limited\s*slots|last\s*chance)\b", 15, "Uses artificial scarcity pressure."),
        (r"\b(easypaisa|jazzcash|nayapay|sadapay|raast|bank\s*transfer)\b", 15, "Mentions direct wallet/bank transfer—verify recipient independently."),
    ]

    for pattern, points, reason in pattern_rules:
        if re.search(pattern, lower_text):
            score += points
            red_flags.append(reason)

    letters = [c for c in raw_text if c.isalpha()]
    if len(letters) >= 20 and sum(1 for c in letters if c.isupper()) / len(letters) > 0.65:
        score += 15
        red_flags.append("Excessive ALL-CAPS formatting commonly used in spam/scam blasts.")

    score = min(score, 100)

    if score >= 55:
        verdict = "SCAM"
        advice = [
            "Do NOT click any links or reply to this message.",
            "Never share your OTP, MPIN, password, or CNIC details with anyone.",
            "Do NOT send advance payment; block and report the sender immediately."
        ]
    elif score >= 25:
        verdict = "SUSPICIOUS"
        advice = [
            "Verify the sender or store through an official website or helpline first.",
            "Avoid sending advance payments—prefer Cash on Delivery (COD) with open-parcel check.",
            "Double-check the domain spelling before entering any personal details."
        ]
    else:
        verdict = "SAFE"
        advice = [
            "No obvious scam indicators detected, though you should always stay cautious.",
            "Still avoid sharing sensitive passwords or OTPs if requested later."
        ]

    return {
        "risk_score": score,
        "verdict": verdict,
        "red_flags": red_flags,
        "advice": advice,
    }