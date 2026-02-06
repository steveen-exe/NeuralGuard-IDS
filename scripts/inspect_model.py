import joblib
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Inspector")

MODEL_PATH = "ids_ensemble_final.pkl"

try:
    logger.info(f"Loading model from {MODEL_PATH}...")
    data = joblib.load(MODEL_PATH)
    
    if isinstance(data, dict):
        model = data['model']
        le = data.get('label_encoder')
        
        if hasattr(model, 'classes_'):
            print(f"Model classes: {model.classes_}")
        else:
            print("Model has no classes_ attribute.")
            
        if le:
            print(f"Label Encoder classes: {le.classes_}")
            
except Exception as e:
    logger.error(f"Error inspecting model: {e}")
