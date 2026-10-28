from pathlib import Path
import joblib

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "message_model.joblib"

print("Checking PhishGuard ML Model...")

if not MODEL_PATH.exists():
    print("ERROR: Model file not found!")
else:
    try:
        model = joblib.load(MODEL_PATH)

        print("SUCCESS: Model loaded successfully!")
        print("Model type:", type(model).__name__)

        if hasattr(model, "classes_"):
            print("Classes:", model.classes_)

        if hasattr(model, "named_steps"):
            print("Pipeline steps:", list(model.named_steps.keys()))

        if hasattr(model, "get_params"):
            print("Model parameters:", model.get_params(deep=False))

    except Exception as error:
        print("ERROR while loading model:", error)
