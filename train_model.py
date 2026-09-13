import pandas as pd
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score


# ==========================================
# LOAD DATASET
# ==========================================

data = pd.read_csv(
    "data/urls.csv"
)


# ==========================================
# SEPARATE URL AND LABEL
# ==========================================

X = data["url"]

y = data["label"]


# ==========================================
# SPLIT DATA
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,

    test_size=0.25,

    random_state=42
)


# ==========================================
# TF-IDF VECTORIZER
# ==========================================

vectorizer = TfidfVectorizer(

    analyzer="char",

    ngram_range=(2, 5)
)


# ==========================================
# CONVERT URL TO FEATURES
# ==========================================

X_train_vectorized = vectorizer.fit_transform(
    X_train
)

X_test_vectorized = vectorizer.transform(
    X_test
)


# ==========================================
# CREATE MACHINE LEARNING MODEL
# ==========================================

model = LogisticRegression()


# ==========================================
# TRAIN MODEL
# ==========================================

model.fit(

    X_train_vectorized,

    y_train
)


# ==========================================
# TEST MODEL
# ==========================================

predictions = model.predict(
    X_test_vectorized
)


# ==========================================
# CALCULATE ACCURACY
# ==========================================

accuracy = accuracy_score(

    y_test,

    predictions
)


# ==========================================
# SAVE MODEL
# ==========================================

joblib.dump(

    model,

    "model.pkl"
)


# ==========================================
# SAVE VECTORIZER
# ==========================================

joblib.dump(

    vectorizer,

    "vectorizer.pkl"
)


# ==========================================
# DISPLAY RESULTS
# ==========================================

print()
print("==========================================")
print("   PHISHING URL DETECTION MODEL")
print("==========================================")
print()

print(
    "Model trained successfully!"
)

print(
    "Accuracy:",
    round(accuracy * 100, 2),
    "%"
)

print(
    "Model saved as model.pkl"
)

print(
    "Vectorizer saved as vectorizer.pkl"
)

print()

print("==========================================")