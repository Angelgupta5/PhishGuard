import pandas as pd
import joblib
from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report


# Project folders
BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"
MODEL_DIR.mkdir(exist_ok=True)

# Small starter dataset for learning and initial testing
data = {
    "message": [
        "Your bank account is blocked. Share your OTP immediately",
        "Congratulations you won a cash prize click here to claim",
        "Your KYC has expired update your details immediately",
        "Send your password to verify your bank account",
        "You have won a lottery pay the processing fee",
        "Your account will be suspended click this suspicious link",
        "Police have issued an arrest warrant pay money immediately",
        "Share your OTP to receive your refund",
        "Urgent payment required to avoid account closure",
        "Click this link and enter your banking password",
        "Hi are we meeting at five today",
        "Your class starts at ten in the morning",
        "Please send me the notes from today's lecture",
        "The meeting has been moved to tomorrow",
        "Happy birthday have a wonderful day",
        "I will reach home in twenty minutes",
        "Thank you for helping me with the assignment",
        "Your appointment is confirmed for Monday",
        "Please call me when you are free",
        "The college event starts at nine tomorrow",
        "Your electricity bill is ready to view",
        "Please review the document I sent yesterday",
        "I am going to the market after class",
        "The project meeting is scheduled for Friday"
    ],
    "label": [
        "scam", "scam", "scam", "scam", "scam",
        "scam", "scam", "scam", "scam", "scam",
        "safe", "safe", "safe", "safe", "safe",
        "safe", "safe", "safe", "safe", "safe",
        "safe", "safe", "safe", "safe"
    ]
}

df = pd.DataFrame(data)

# Separate messages and labels
X = df["message"]
y = df["label"]

# Split the dataset into training and testing data
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

# Build the text classification pipeline
model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            sublinear_tf=True
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42
        )
    )
])

# Train the model
model.fit(X_train, y_train)

# Evaluate on held-out test messages
predictions = model.predict(X_test)

print("\n===== PhishGuard ML Model Results =====")
print(f"Training messages: {len(X_train)}")
print(f"Testing messages: {len(X_test)}")
print(f"Test accuracy: {accuracy_score(y_test, predictions):.2%}")
print("\nClassification Report:")
print(classification_report(y_test, predictions, zero_division=0))

# Save the trained model
model_path = MODEL_DIR / "message_model.joblib"
joblib.dump(model, model_path)

print(f"\nModel saved successfully at:\n{model_path}")
