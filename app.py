import os
import re
import joblib
import psycopg2

from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# =========================================================
# LOAD ML MODEL
# =========================================================

model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")


# =========================================================
# DATABASE CONNECTION - POSTGRESQL
# =========================================================

DATABASE_URL = os.getenv("DATABASE_URL")


def get_db_connection():
    if not DATABASE_URL:
        print("DATABASE_URL is not set.")
        return None

    try:
        connection = psycopg2.connect(DATABASE_URL)
        return connection

    except Exception as e:
        print("Database Connection Error:", e)
        return None


# =========================================================
# URL RULE-BASED ANALYSIS
# =========================================================

def analyze_url(url):

    score = 0
    reasons = []

    url_lower = url.lower()

    # HTTPS check
    if not url_lower.startswith("https://"):
        score += 15
        reasons.append("URL does not use HTTPS")

    # URL length
    if len(url) > 100:
        score += 15
        reasons.append("URL is unusually long")

    # @ symbol
    if "@" in url:
        score += 20
        reasons.append("URL contains @ symbol")

    # Extract hostname
    try:
        hostname = url.split("://", 1)[1].split("/", 1)[0]
        hostname = hostname.split("@")[-1].split(":")[0]
    except Exception:
        hostname = ""

    # IP address detection
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    if re.match(ip_pattern, hostname):
        score += 25
        reasons.append(
            "URL uses an IP address instead of a domain name"
        )

    # Many subdomains
    if hostname.count(".") >= 4:
        score += 10
        reasons.append(
            "URL contains many subdomains"
        )

    # Suspicious keywords
    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "account",
        "password",
        "secure",
        "update",
        "confirm"
    ]

    found_keywords = []

    for keyword in suspicious_keywords:

        if keyword in url_lower:
            found_keywords.append(keyword)

    if found_keywords:

        score += 10

        reasons.append(
            "Suspicious keyword detected: "
            + ", ".join(found_keywords)
        )

    # Hyphen in hostname
    if "-" in hostname:

        score += 5

        reasons.append(
            "Domain contains a hyphen"
        )

    # Suspicious file extensions
    suspicious_extensions = [
        ".exe",
        ".scr",
        ".zip",
        ".bat"
    ]

    for extension in suspicious_extensions:

        if url_lower.endswith(extension):

            score += 15

            reasons.append(
                "Suspicious file extension detected: "
                + extension
            )

            break

    # Maximum score
    score = min(score, 100)

    return score, reasons


# =========================================================
# MACHINE LEARNING PREDICTION
# =========================================================

def ml_prediction(url):

    url_vector = vectorizer.transform([url])

    prediction = model.predict(url_vector)[0]

    probabilities = model.predict_proba(url_vector)[0]

    confidence = max(probabilities) * 100

    if prediction == "phishing":

        ml_score = confidence

    else:

        ml_score = 100 - confidence

    return ml_score


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():

    return render_template("index.html")


# =========================================================
# ABOUT PAGE
# =========================================================

@app.route("/about")
def about():

    return render_template("about.html")


# =========================================================
# SCAN URL
# =========================================================

@app.route("/scan", methods=["POST"])
def scan():

    url = request.form.get("url", "").strip()

    # Empty URL
    if not url:

        return redirect(
            url_for("home")
        )

    # Rule-based analysis
    rule_score, reasons = analyze_url(url)

    # Machine learning prediction
    ml_score = ml_prediction(url)

    # Combined score
    risk_score = int(
        (rule_score * 0.40)
        +
        (ml_score * 0.60)
    )

    # Keep score between 0 and 100
    risk_score = max(
        0,
        min(risk_score, 100)
    )

    # Result classification
    if risk_score >= 70:

        result = "Likely Phishing"

    elif risk_score >= 30:

        result = "Suspicious"

    else:

        result = "Likely Safe"

    # =====================================================
    # SAVE SCAN TO POSTGRESQL
    # =====================================================

    connection = get_db_connection()

    if connection:

        try:

            cursor = connection.cursor()

            cursor.execute(
                """
                INSERT INTO scan_history
                (url, risk_score, result)
                VALUES (%s, %s, %s)
                """,
                (
                    url,
                    risk_score,
                    result
                )
            )

            connection.commit()

            cursor.close()
            connection.close()

            print(
                "Scan saved successfully."
            )

        except Exception as e:

            print(
                "Error saving scan:",
                e
            )

            try:

                connection.rollback()
                connection.close()

            except Exception:
                pass

    else:

        print(
            "Database not connected. "
            "Scan not saved."
        )

    # Show result page
    return render_template(
        "result.html",
        url=url,
        risk_score=risk_score,
        result=result,
        reasons=reasons
    )


# =========================================================
# SCAN HISTORY
# =========================================================

@app.route("/history")
def history():

    scans = []

    connection = get_db_connection()

    if connection:

        try:

            cursor = connection.cursor()

            cursor.execute(
                """
                SELECT
                    id,
                    url,
                    risk_score,
                    result,
                    scan_time
                FROM scan_history
                ORDER BY id DESC
                """
            )

            scans = cursor.fetchall()

            cursor.close()
            connection.close()

        except Exception as e:

            print(
                "History database error:",
                e
            )

            try:
                connection.close()
            except Exception:
                pass

    return render_template(
        "history.html",
        scans=scans
    )


# =========================================================
# CLEAR HISTORY
# =========================================================

@app.route(
    "/clear-history",
    methods=["POST"]
)
def clear_history():

    connection = get_db_connection()

    if connection:

        try:

            cursor = connection.cursor()

            cursor.execute(
                """
                TRUNCATE TABLE
                scan_history
                RESTART IDENTITY
                """
            )

            connection.commit()

            cursor.close()
            connection.close()

            print(
                "Scan history cleared."
            )

        except Exception as e:

            print(
                "Error clearing history:",
                e
            )

            try:

                connection.rollback()
                connection.close()

            except Exception:
                pass

    return redirect(
        url_for("history")
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    total = 0
    safe = 0
    suspicious = 0
    phishing = 0

    connection = get_db_connection()

    if connection:

        try:

            cursor = connection.cursor()

            # Total scans
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM scan_history
                """
            )

            total = cursor.fetchone()[0]

            # Safe scans
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM scan_history
                WHERE result = 'Likely Safe'
                """
            )

            safe = cursor.fetchone()[0]

            # Suspicious scans
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM scan_history
                WHERE result = 'Suspicious'
                """
            )

            suspicious = cursor.fetchone()[0]

            # Phishing scans
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM scan_history
                WHERE result = 'Likely Phishing'
                """
            )

            phishing = cursor.fetchone()[0]

            cursor.close()
            connection.close()

        except Exception as e:

            print(
                "Dashboard database error:",
                e
            )

            try:
                connection.close()
            except Exception:
                pass

    # =====================================================
    # PERCENTAGES
    # =====================================================

    if total > 0:

        safe_percentage = round(
            (safe / total) * 100,
            1
        )

        suspicious_percentage = round(
            (suspicious / total) * 100,
            1
        )

        phishing_percentage = round(
            (phishing / total) * 100,
            1
        )

    else:

        safe_percentage = 0
        suspicious_percentage = 0
        phishing_percentage = 0

    return render_template(
        "dashboard.html",
        total=total,
        safe=safe,
        suspicious=suspicious,
        phishing=phishing,
        safe_percentage=safe_percentage,
        suspicious_percentage=suspicious_percentage,
        phishing_percentage=phishing_percentage
    )


# =========================================================
# 404 ERROR
# =========================================================

@app.errorhandler(404)
def page_not_found(error):

    return """
    <h1>404 - Page Not Found</h1>

    <p>
        The page you requested does not exist.
    </p>

    <a href="/">
        Go Home
    </a>
    """, 404


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        ),
        debug=True
    )