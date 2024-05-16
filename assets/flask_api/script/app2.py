import sys
import os
import numpy as np
import pefile
import math
import joblib

# Function to calculate entropy of data
def calculate_entropy(data):
    """Calculate entropy of data"""
    if not data:
        return 0
    entropy = 0
    data_size = len(data)
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    for count in freq:
        if count == 0:
            continue
        p_x = float(count) / data_size
        entropy += - p_x * math.log2(p_x)
    return entropy

# Function to extract features from PE file
def extract_features(file_path):
    """Extract features from PE file"""
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        return None
    except OSError:
        return None

    features = []

    # Machine
    features.append(pe.FILE_HEADER.Machine)

    # Number of Sections
    features.append(pe.FILE_HEADER.NumberOfSections)

    # Time Date Stamp
    features.append(pe.FILE_HEADER.TimeDateStamp)

    # Entry Point
    features.append(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    # Image Base
    features.append(pe.OPTIONAL_HEADER.ImageBase)

    # Section Names
    section_names = [section.Name.decode('utf-8', errors='ignore').strip('\x00') for section in pe.sections]
    features.append(len(section_names))

    # Calculate entropy
    raw_data = pe.get_memory_mapped_image()
    entropy = calculate_entropy(raw_data)
    features.append(entropy)

    # Ensure feature vector has exactly 7 elements by padding with None
    num_features_expected = 7
    if len(features) < num_features_expected:
        features.extend([None] * (num_features_expected - len(features)))
    elif len(features) > num_features_expected:
        features = features[:num_features_expected]

    return features

# Function to predict if the file is malware (1) or benign (0) using a pre-trained SVM model
def predict_malware(file_path, model_path):
    """Predict if the file is malware (1) or benign (0) using a pre-trained SVM model"""
    extracted_features = extract_features(file_path)
    if extracted_features:
        # Convert extracted features to numpy array
        features = np.array([extracted_features]) 

        # Check if the model file exists
        if not os.path.exists(model_path):
            return "Unknown", 0.0

        # Load pre-trained SVM model for malware detection
        svm_model = joblib.load(model_path)

        # Make prediction
        prediction = svm_model.predict(features)
        probabilities = svm_model.predict_proba(features)

        # Get the probability of the predicted class
        confidence = max(probabilities[0])

        if prediction == 0:
            return "Benign", confidence
        elif prediction == 1:
            return "Malware", confidence
        else:
            return "Unknown", 0.0
    else:
        return "Unknown", 0.0

# Main function
if __name__ == "__main__":

    if len(sys.argv) != 3:
        print("Usage: python app.py <file_path> <model_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    model_path = sys.argv[2]

    if os.path.exists(file_path):
        # Predict using SVM model directly
        prediction, confidence = predict_malware(file_path, model_path)
        if prediction == "Unknown":
            print("Benign")  # Default to "Benign" in case of an error
        else:
            print(f"File scanned: {prediction} with Confidence Level: {confidence:.4f}")  # Output the result as "Benign" or "Malware" with confidence score
    else:
        print("Benign (error)")  # Default to "Benign" if file not found
        sys.exit(1)
