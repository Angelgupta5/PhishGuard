
from unittest import result
import cv2
import joblib
from pathlib import Path
import numpy as np
from pyzbar.pyzbar import decode
import cv2
from pyzbar.pyzbar import decode
import pytesseract
from PIL import Image
from io import BytesIO
from flask import Flask, render_template, request, jsonify
import re
from urllib.parse import urlparse
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
app = Flask(__name__)
# Load PhishGuard ML Model
BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "message_model.joblib"

try:
    message_model = joblib.load(MODEL_PATH)
    print("PhishGuard ML Model loaded successfully!")
except Exception as error:
    message_model = None
    print("ML Model loading failed:", error)
    # ML Message Prediction
def predict_message_ml(message):
    if message_model is None:
        return {
            "prediction": "Unavailable",
            "confidence": None
        }

    try:
        prediction = str(message_model.predict([message])[0])

        confidence = None

        if hasattr(message_model, "predict_proba"):
            probabilities = message_model.predict_proba([message])[0]
            confidence = round(float(max(probabilities)) * 100, 2)

        return {
            "prediction": prediction,
            "confidence": confidence
        }

    except Exception as error:
        print("ML prediction error:", error)

        return {
            "prediction": "Unavailable",
            "confidence": None
        }


SCAM_PATTERNS = {
    "Urgency or threats": [
        "urgent", "immediately", "account blocked",
        "account suspended", "within 24 hours",
        "turant", "jaldi karo", "abhi karo","aaj hi account band ho jayega",
"turant action lo",
"abhi click karo",
"warna account block ho jayega",
"24 ghante mein account band",
"police ghar aa jayegi",
"abhi payment karo",
        "will be blocked", "otherwise blocked", "last warning", "account band ho jayega", "band kar diya jayega", "turant action lein", "abhi click karo"
    ],
    "KYC or banking claims": [
        "kyc expired", "update kyc", "kyc update",
        "bank account blocked", "bank account बंद",
        "pan card blocked", "account will be blocked","aapka kyc expire ho gaya hai",
"kyc update karo",
"bank account band ho jayega",
"bank account block ho gaya",
"pan card link karo",
"sim band ho jayegi",
"account unblock karne ke liye",
        "your kyc has expired", "kyc expire ho gaya", "kyc expire ho gaya hai", "kyc khatam ho gaya", "update your bank account", "bank account update", "bank account will be blocked", "account block ho jayega", "bank account band ho jayega"

    ],
    "Money or payment requests": [
        "send money", "pay now", "claim your reward",
        "prize money", "lottery winner", "upi refund",
        "refund pending", "payment required",
        "paise bhejo", "inaam jeeta", "paisa bhejo","paise bhejo",
"paisa transfer karo",
"refund lene ke liye payment",
"processing fee jama karo",
"inaam pane ke liye paise",
"payment receive karne ke liye",
    ],
    "Credential requests": [
        "share otp", "send otp", "enter your password",
        "verify your password", "share pin",
        "otp batao", "otp share karo","otp batao",
"otp share karo",
"upi pin batao",
"password bhejo",
"bank details share karo",
"otp enter karo",
"pin share karo",
        "click this link", "verify your account", "bank details", "share your details", "otp enter karo", "pin enter karo"
    ],
    "Digital arrest warning signs": [
        "digital arrest", "police case against you",
        "arrest warrant", "police will arrest",
        "video call investigation", "money to avoid arrest",
        "cbi officer", "police officer here",
        "police se bachne", "arrest kar lenge"
    ]
}
def analyze_message(message):
    text = message.lower()
    reasons = []
    score = 0


    category_points = {
        "Urgency or threats": 20,
        "KYC or banking claims": 30,
        "Money or payment requests": 25,
        "Credential requests": 40,
        "Digital arrest warning signs": 45
    }

    # Detect matching phrases in each category.
    for category, phrases in SCAM_PATTERNS.items():
        matched = [phrase for phrase in phrases if phrase in text]

        if matched:
            reasons.append({
                "category": category,
                "matches": matched
            })
            score += category_points.get(category, 0)

    # Extra points for explicit OTP requests.
    otp_phrases = [
        "share otp", "send otp", "otp batao",
        "otp share karo", "otp enter karo"
    ]

    if any(phrase in text for phrase in otp_phrases):
        score += 15

    # Extra points for digital-arrest threats.
    arrest_phrases = [
        "digital arrest", "arrest warrant",
        "cbi officer", "police will arrest",
        "arrest kar lenge"
    ]

    if any(phrase in text for phrase in arrest_phrases):
        score += 20

    # Extra points for prize claims combined with payment demands.
    prize_phrases = [
        "lottery", "lottery winner", "won a lottery",
        "congratulations", "you have won", "prize"
    ]

    payment_phrases = [
        "pay", "payment", "fee", "transfer",
        "claim", "processing fee", "paisa",
        "paise", "inaam"
    ]

    if (
        any(phrase in text for phrase in prize_phrases)
        and any(phrase in text for phrase in payment_phrases)
    ):
        score += 20

    # Limit the score to 100.
    score = min(score, 100)

    # Create more relevant safety advice.
    categories_found = {item["category"] for item in reasons}

    if "Digital arrest warning signs" in categories_found:
        next_step = (
            "Do not transfer money or follow threats from the caller. "
            "End suspicious calls, tell someone you trust, and verify "
            "the claim through official channels."
        )

    elif "Credential requests" in categories_found:
        next_step = (
            "Never share OTPs, passwords, or PINs. Do not click "
            "unverified links. Contact your bank through its official app "
            "or verified customer-care channel."
        )

    elif "KYC or banking claims" in categories_found:
        next_step = (
            "Do not use links in unexpected messages to update KYC. "
            "Check your account status through your bank's official app "
            "or website."
        )

    elif "Money or payment requests" in categories_found:
        next_step = (
            "Do not pay unexpected fees to claim a prize or refund. "
            "Verify the offer independently before sending money."
        )

    elif "Urgency or threats" in categories_found:
        next_step = (
            "Do not panic or act under pressure. Verify the claim "
            "directly through the organisation's official channel."
        )

    else:
        next_step = (
            "No major configured warning signs were detected. "
            "This does not guarantee safety. Verify unexpected requests "
            "before clicking links or sharing information."
        )

    # Assign the risk level.
    if score >= 50:
        risk = "High Risk"
    elif score >= 25:
        risk = "Suspicious"
    else:
        risk = "Safe-looking"

    return {
        "status": (
            "Potential scam indicators detected"
            if reasons
            else "No configured warning signs detected"
        ),
        "risk_score": score,
        "risk": risk,
        "reasons": reasons,
        "next_step": next_step,
        
    }


def analyze_url(value):
    """Analyze URL warning signs and calculate a rule-based risk score."""

    value = value.strip()
    reasons = []
    score = 0

    # Check for a valid URL format
    parsed = urlparse(value)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {
            "risk": "Suspicious",
            "risk_score": 50,
            "hostname": parsed.hostname or "Unknown",
            "reasons": ["Invalid URL format or missing HTTP/HTTPS scheme."],
            "next_step": "Check the URL carefully before opening it.",
            "message": "The URL format could not be validated."
        }

    hostname = parsed.hostname.lower()

    # HTTP does not encrypt the connection like HTTPS
    if parsed.scheme.lower() == "http":
        reasons.append("The URL uses HTTP instead of HTTPS.")
        score += 20

    # Check for suspicious words in the URL
    suspicious_words = [
        "login", "verify", "secure", "update",
        "kyc", "password", "free-gift", "claim-prize"
    ]

    found_words = [word for word in suspicious_words if word in value.lower()]

    if found_words:
        reasons.append(
            "Potentially suspicious words: " + ", ".join(found_words)
        )
        score += 25

    # Check for an IP address used as the hostname
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname):
        reasons.append("The hostname uses an IP address instead of a domain name.")
        score += 25

    # Check for an unusually long hostname
    if len(hostname) > 50:
        reasons.append("The hostname is unusually long.")
        score += 15

    score = min(score, 100)

    if score >= 60:
        risk = "High Risk"
        next_step = "Do not open the link unless you can independently verify it."
    elif score >= 25:
        risk = "Suspicious"
        next_step = "Verify the domain through the organisation's official website."
    else:
        risk = "Uncertain"
        next_step = (
            "No configured warning patterns were detected. "
            "This does not guarantee that the URL is safe."
        )

    return {
        "risk": risk,
        "risk_score": score,
        "hostname": hostname,
        "reasons": reasons,
        "next_step": next_step,
        "message": (
            "This is a basic rule-based URL check, not a definitive security verdict."
        )
    }


    
DIGITAL_ARREST_PATTERNS = {
    "Fake police or CBI claims": [
        "cbi officer",
        "police officer here",
        "calling from police station",
        "cyber crime officer",
        "customs officer",
        "police department"
    ],

    "Arrest threats": [
        "digital arrest",
        "arrest warrant",
        "police will arrest",
        "you will be arrested",
        "police se arrest",
        "arrest kar lenge",
        "jail bhej denge"
    ],

    "Forced video call or investigation": [
        "video call investigation",
        "stay on video call",
        "camera on rakho",
        "video call par raho",
        "online investigation",
        "under digital surveillance"
    ],

    "Secrecy or intimidation": [
        "do not tell anyone",
        "don't tell your family",
        "keep this confidential",
        "kisi ko mat batana",
        "family ko mat batana",
        "do not disconnect the call"
    ],

    "Money demands or financial threats": [
        "pay to avoid arrest",
        "money to avoid arrest",
        "transfer money for verification",
        "pay security deposit",
        "send money immediately",
        "paise transfer karo",
        "account mein paise bhejo"
    ]
}


def analyze_digital_arrest(message):
    """Check for common digital-arrest scam warning signs."""

    text = message.lower()
    reasons = []
    score = 0

    points = {
    "Fake police or CBI claims": 25,
    "Arrest threats": 35,
    "Forced video call or investigation": 20,
    "Secrecy or intimidation": 20,
    "Money demands or financial threats": 35
}
    

    for category, phrases in DIGITAL_ARREST_PATTERNS.items():
        matched = [phrase for phrase in phrases if phrase in text]

        if matched:
            reasons.append({
                "category": category,
                "matches": matched
            })

            score += points[category]

    score = min(score, 100)

    if score >= 50:
        risk = "High Risk"
        next_step = (
            "Do not transfer money or share OTPs, passwords, "
            "or banking details. End suspicious calls and verify "
            "claims through official channels. If threatened, "
            "contact a trusted person or the appropriate authorities."
        )

    elif score >= 25:
        risk = "Suspicious"
        next_step = (
            "Be cautious. Do not follow payment instructions or "
            "share personal information. Independently verify "
            "the caller's identity."
        )

    else:
        risk = "Safe-looking"
        next_step = (
            "Few configured warning signs were detected. "
            "This does not guarantee that the message is safe."
        )

    return {
        "risk_score": score,
        "risk": risk,
        "reasons": reasons,
        "next_step": next_step,
        "message": (
            "This detector identifies configured warning patterns. "
            "It cannot confirm whether a person or message is genuine."
        )
    }



@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze-message", methods=["POST"])
def message_api():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()

    if not message:
        return jsonify({
            "error": "Please enter a message."
        }), 400

    if len(message) > 10000:
        return jsonify({
            "error": "Message is too long."
        }), 400

    # Existing rule-based analysis
    result = analyze_message(message)

    # Machine Learning prediction
    ml_result = predict_message_ml(message)
    ml_prediction = ml_result["prediction"]
    ml_confidence = ml_result["confidence"]

    # Add ML results without removing existing results
    result["ml_prediction"] = str(ml_prediction).upper()
    result["ml_confidence"] = ml_confidence

    # Keep the rule-based result separate
    result["detection_method"] = "Rule-based + Machine Learning"

    return jsonify(result)


@app.route("/analyze-url", methods=["POST"])
def url_api():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Please enter a URL."}), 400

    if len(url) > 2048:
        return jsonify({"error": "URL is too long."}), 400

    return jsonify(analyze_url(url))

@app.route("/analyze-arrest", methods=["POST"])
def arrest_api():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()

    if not message:
        return jsonify({"error": "Please enter a message."}), 400

    if len(message) > 10000:
        return jsonify({"error": "Message is too long."}), 400

    return jsonify(analyze_digital_arrest(message))


@app.route("/analyze-screenshot", methods=["POST"])
def analyze_screenshot():
    if "image" not in request.files:
        return jsonify({"error": "Please upload a screenshot."}), 400

    file = request.files["image"]

    if file.filename == "":
        return jsonify({"error": "Please select an image."}), 400

    try:
        image = Image.open(file.stream).convert("RGB")
        extracted_text = pytesseract.image_to_string(image).strip()

        if not extracted_text:
            return jsonify({
            "error": "No text found. Please upload a clearer screenshot."
        }), 400

        result = analyze_message(extracted_text)
        result["extracted_text"] = extracted_text

        return jsonify(result)

    except Exception as e:
        return jsonify({
        "error": "Screenshot could not be processed. Please check the image and Tesseract installation."
    }), 400
 
def analyze_qr_image(image_file):
    try:
        image_bytes = image_file.read()

        image_array = np.frombuffer(
            image_bytes,
            dtype=np.uint8
        )

        image = cv2.imdecode(
            image_array,
            cv2.IMREAD_COLOR
        )

        if image is None:
            return {
                "error": "Invalid image. Please upload a valid QR image."
            }

        qr_codes = decode(image)

        if not qr_codes:
            return {
                "error": "No QR code found. Please upload a clear image."
            }

        results = []

        for qr in qr_codes:
            data = qr.data.decode("utf-8", errors="replace")
            lower_data = data.lower()
            reasons = []

            # HIGH RISK: Common scam-related phrases
            high_risk_patterns = [
                "share your otp",
                "send otp",
                "password",
                "account blocked",
                "account suspended",
                "urgent kyc",
                "kyc expired",
                "pay processing fee",
                "claim your prize",
                "police arrest",
                "digital arrest"
            ]

            # SUSPICIOUS: Links and payment indicators
            suspicious_patterns = [
                "login",
                "verify",
                "kyc",
                "claim-prize",
                "free-gift",
                "refund",
                "payment",
                "upi://pay"
            ]

            if any(pattern in lower_data for pattern in high_risk_patterns):
                risk = "High Risk"
                reasons.append(
                    "The QR content contains phrases commonly associated "
                    "with scams, account threats, or requests for sensitive information."
                )

            else:
                if lower_data.startswith("http://"):
                    reasons.append(
                        "This link does not use HTTPS. Check it carefully."
                    )

                if any(pattern in lower_data for pattern in suspicious_patterns):
                    reasons.append(
                        "The QR content contains suspicious link or payment indicators."
                    )

                if reasons:
                    risk = "Suspicious"
                else:
                    risk = "Uncertain"

            results.append({
                "decoded_data": data,
                "risk": risk,
                "reasons": reasons,
                "next_step": (
                    "Do not share OTPs or passwords. Verify the sender, "
                    "website, and payment details before proceeding."
                )
            })

        return {"results": results}

    except Exception as error:
        print("QR scanning error:", error)
        return {
            "error": "QR scanning failed. Please try another image."
        }
@app.route("/analyze-qr", methods=["POST"])
def analyze_qr():
    if "image" not in request.files:
        return jsonify({"error": "Please upload a QR code image."}), 400

    file = request.files["image"]

    if file.filename == "":
        return jsonify({"error": "Please select an image."}), 400

    result = analyze_qr_image(file)

    if "error" in result:
        return jsonify(result), 400

    return jsonify(result)    
@app.route("/chatbot", methods=["POST"])
def chatbot():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip().lower()

    if not message:
        return jsonify({
            "reply": "Please type your question first."
        }), 400

    if any(word in message for word in ["hello", "hi", "hey", "namaste"]):
        reply = (
            "Hello! Welcome to PhishGuard. "
            "I can help you identify scam messages, "
            "suspicious links, OTP fraud, and digital arrest scams."
        )

    elif any(word in message for word in [
        "digital arrest", "police", "cbi", "arrest"
    ]):
        reply = (
            "Digital arrest scams use threats of arrest or fake police "
            "calls to scare people. Real law enforcement does not conduct "
            "arrests through video calls or demand money to settle a case. "
            "Do not transfer money under pressure."
        )

    elif any(word in message for word in [
        "otp", "password", "pin", "cvv"
    ]):
        reply = (
            "Never share your OTP, password, UPI PIN, or CVV with anyone. "
            "Banks and legitimate services do not ask you to reveal these "
            "secret details over calls or messages."
        )

    elif any(word in message for word in [
        "upi", "payment", "refund", "money", "cash"
    ]):
        reply = (
            "Be careful with unexpected payment or refund requests. "
            "Verify the receiver before paying. You generally do not need "
            "to enter your UPI PIN to receive money."
        )

    elif any(word in message for word in [
        "link", "url", "website", "phishing", "click"
    ]):
        reply = (
            "Avoid opening suspicious links. Check the website address "
            "carefully and never enter your banking details on an "
            "unverified website. You can also use the URL Scanner "
            "on PhishGuard."
        )

    elif any(word in message for word in [
        "scam", "fraud", "fake", "cheating"
    ]):
        reply = (
            "If you suspect a scam, do not share personal details or send "
            "money. Save the message, verify the sender independently, "
            "and use PhishGuard's scanners to check suspicious content."
        )

    else:
        reply = (
            "I can help with scam messages, suspicious links, OTP fraud, "
            "UPI payment scams, and digital arrest threats. "
            "Please ask me about one of these topics."
        )

    return jsonify({"reply": reply})     

if __name__ == "__main__":
    app.run(debug=True)
