import sys
import os
import numpy as np
import pefile
import math
import hashlib
import joblib
import csv
import pandas as pd

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
    except pefile.PEFormatError as e:
        print(f"Error: PEFormatError occurred for file '{file_path}': {e}", file=sys.stderr)
        return None
    except OSError as e:
        print(f"Error accessing file '{file_path}': {e}", file=sys.stderr)
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

    # Print extracted features
    #print(f"Extracted Features: {features}")

    return features

# Function to concatenate features and labels CSVs by row index
def concatenate_csv(features_csv, labels_csv, combined_csv):
    # Read features CSV
    features_df = pd.read_csv(features_csv)
    # Read labels CSV
    labels_df = pd.read_csv(labels_csv)
    # Reset index to ensure they both have integer indexes
    features_df.reset_index(drop=True, inplace=True)
    labels_df.reset_index(drop=True, inplace=True)
    # Concatenate DataFrames along the columns axis
    combined_df = pd.concat([features_df, labels_df], axis=1)
    # Save the combined dataframe to a new CSV file
    combined_df.to_csv(combined_csv, index=False)

# Function to check if extracted features match any in the combined CSV
def check_features_in_combined(features, combined_csv):
    # Read combined CSV
    combined_df = pd.read_csv(combined_csv)
    # Loop through rows in the combined CSV
    for index, row in combined_df.iterrows():
        # Convert row values to a list
        row_values = row.values.tolist()
        # Check if extracted features match row values
        if features == row_values[:-1]:  # Exclude the label from comparison
            return row_values[-1]  # Return the label
    return None  # Return None if no match is found

# Function to check if MD5 and SHA256 hashes exist in the label CSV file
def check_hash_in_labels(md5, sha256, label_csv):
    """Check if the MD5 and SHA256 hashes exist in the label CSV file"""
    with open(label_csv, 'r') as label_file:
        label_reader = csv.reader(label_file)
        for row in label_reader:
            if row[0] == md5 and row[1] == sha256:
                return int(row[2])  # Return the label (0 for benign, 1 for malware)
    return None  # Return None if no match is found

# Function to predict if the file is malware (1) or benign (0) using MD5 and SHA256 hashes
def predict_malware_using_hashes(md5, sha256, label_csv):
    """Predict if the file is malware (1) or benign (0) using MD5 and SHA256 hashes"""
    label = check_hash_in_labels(md5, sha256, label_csv)
    if label is not None:
        if label == 0:
            return "Benign"
        elif label == 1:
            return "Malware"
    else:
        return "Unknown"

# Function to predict if the file is malware (1) or benign (0) using a pre-trained SVM model
def predict_malware(file_path, label_csv):
    """Predict if the file is malware (1) or benign (0) using a pre-trained SVM model"""
    extracted_features = extract_features(file_path)
    if extracted_features:
        # Convert extracted features to numpy array
        features = np.array([extracted_features]) 

        # Load pre-trained SVM model for malware detection
        model_path = 'flask_api/models/version1.pkl'
        if not os.path.exists(model_path):
            print(f"Error: Model file '{model_path}' not found.", file=sys.stderr)
            return "Unknown"

        svm_model = joblib.load(model_path)

        # Make prediction
        prediction = svm_model.predict(features)
        if prediction == 0:
            result = "Benign"
        elif prediction == 1:
            result = "Malware"
        else:
            result = "Unknown"

        # Print prediction result
        # print(f"Prediction: {result}")

        return result
    else:
        return "Unknown"

# Main function
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python app.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    features_csv = 'flask_api/docs/newFeatures.csv'
    labels_csv = 'flask_api/docs/newLabels.csv'
    combined_csv = 'flask_api/docs/combined.csv'

    if os.path.exists(file_path):
        # Concatenate features and labels CSVs into a combined CSV file
        concatenate_csv(features_csv, labels_csv, combined_csv)

        # Calculate MD5 and SHA256 hashes
        with open(file_path, "rb") as f:
            file_content = f.read()
            file_md5 = hashlib.md5(file_content).hexdigest()
            file_sha256 = hashlib.sha256(file_content).hexdigest()

        # Check if MD5 and SHA256 hashes exist in the label CSV
        label = check_hash_in_labels(file_md5, file_sha256, labels_csv)
        if label is not None:
            if label == 0:
                print("Benign")
            elif label == 1:
                print("Malware")
        else:
            # Extract features from the file
            extracted_features = extract_features(file_path)
            if extracted_features:
                # Check if extracted features match any in the combined CSV
                matched_label = check_features_in_combined(extracted_features, combined_csv)
                if matched_label is not None:
                    if matched_label == 0:
                        print("Benign")
                    elif matched_label == 1:
                        print("Malware")
                else:
                    # If no match is found, use SVM model for prediction
                    prediction = predict_malware(file_path, labels_csv)
                    if prediction == "Unknown":
                        print("Error: Malware prediction failed.")
                    else:
                        print(f"{prediction}")  # Output the result as "Benign", "Malware", or "Unknown"
            else:
                print("Error: Failed to extract features.")
    else:
        print("Error: File not found", file=sys.stderr)
        sys.exit(1)
