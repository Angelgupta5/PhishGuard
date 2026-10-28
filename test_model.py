import joblib
from pathlib import Path

# Load the trained model
BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "message_model.joblib"

model = joblib.load(MODEL_PATH)

# Test messages
messages = [
    "Your bank account is blocked. Share your OTP immediately",
    "Hi, are we meeting at five today?",
    "Congratulations you won a cash prize click here to claim",
    "Please send me the notes from today's lecture"
]

print("\n===== PhishGuard ML Message Test =====\n")

for message in messages:
    prediction = model.predict([message])[0]
    print("Message:", message)
    print("Prediction:", prediction.upper())
    print("-" * 60)
