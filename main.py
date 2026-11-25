from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
from bs4 import BeautifulSoup

app = FastAPI(title="ScamShield AI Backend")

# Allow Vercel frontend and localhost to connect
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

@app.post("/scan")
def scan_content(req: ScanRequest):
    input_type = req.type.strip().lower()
    if input_type not in {"message", "url", "store"}:
        raise HTTPException(status_code=400, detail="type must be 'message', 'url', or 'store'")

    text = req.content.strip()
    if not text:
        raise HTTPException(status_code=400, detail="content cannot be empty")

    score = 0
    red_flags = []
    lower_text = text.lower()

    # URL inspection
    if input_type == "url":
        if not lower_text.startswith(("http://", "https://")):
            text = "http://" + text
            lower_text = text.lower()
        if lower_text.startswith("http://"):
            score += 20
            red_flags.append("Insecure HTTP link (missing HTTPS encryption).")
        try:
            res = requests.get(text, timeout=5)
            soup = BeautifulSoup(res.text, "html.parser")
            lower_text += " " + soup.get_text(" ", strip=True).lower()
        except Exception:
            score += 25
            red_flags.append("Website could not be reached or blocked inspection.")

    # Store-specific checks
    if input_type == "store":
        if "cod" not in lower_text and "cash on delivery" not in lower_text:
            score += 20
            red_flags.append("No Cash on Delivery (COD) option mentioned.")
        if "dm for price" in lower_text or "dm to order" in lower_text:
            score += 15
            red_flags.append("Forces private DM ordering with no transparent checkout.")

    # Rule-based scam keyword checks
    scam_rules = {
        "otp": (35, "Asks for or mentions a One-Time Password (OTP)."),
        "advance payment": (35, "Demands advance payment before delivery."),
        "easypaisa": (15, "Mentions mobile wallet transfer—verify official sender."),
        "jazzcash": (15, "Mentions mobile wallet transfer—verify official sender."),
        "urgent": (20, "Uses artificial urgency to pressure quick action."),
        "account blocked": (30, "Uses fake account-suspension scare tactics."),
        "prize": (25, "Promises unexpected prize or lottery winnings."),
        "no return": (25, "States a strict no-return / no-refund policy."),
        "only 2 left": (15, "Uses fake scarcity pressure ('only 2 left')."),
    }

    for keyword, (points, reason) in scam_rules.items():
        if keyword in lower_text:
            score += points
            red_flags.append(reason)

    if any(s in lower_text for s in ["bit.ly", "tinyurl", "t.co", "rb.gy"]):
        score += 25
        red_flags.append("Uses a shortened URL that hides the real destination.")

    score = min(score, 100)

    if score >= 60:
        verdict = "SCAM"
        advice = [
            "Do NOT click any links or reply to this message.",
            "Never share your OTP, PIN, or CNIC details with anyone.",
            "Do NOT send advance payment; block and report the sender immediately."
        ]
    elif score >= 30:
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