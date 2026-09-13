# ==========================================
# PHISHING URL DETECTION SYSTEM
# Flask + Machine Learning + MySQL
# ==========================================

import os
import re
import joblib
import mysql.connector

from flask import Flask, render_template, request


# ==========================================
# FLASK APP
# ==========================================

app = Flask(__name__)


# ==========================================
# LOAD MACHINE LEARNING MODEL
# ==========================================

model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")


# ==========================================
# MYSQL CONFIGURATION
# ==========================================

MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "ananya007")
MYSQL_DATABASE = os.getenv(
    "MYSQL_DATABASE",
    "phishing_detector"
)


# ==========================================
# MYSQL CONNECTION
# ==========================================

def get_db_connection():

    try:

        db = mysql.connector.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE
        )

        return db

    except Exception as error:

        print("Database Connection Error:", error)

        return None


# ==========================================
# URL ANALYSIS
# ==========================================

def analyze_url(url):

    score = 0

    reasons = []

    features = []


    # --------------------------------------
    # HTTPS CHECK
    # --------------------------------------

    if url.startswith("https://"):

        features.append(
            ("HTTPS", "Present", "Low Risk")
        )

    else:

        score += 15

        reasons.append(
            "URL does not use HTTPS."
        )

        features.append(
            ("HTTPS", "Not Present", "Risk")
        )


    # --------------------------------------
    # URL LENGTH
    # --------------------------------------

    if len(url) > 100:

        score += 15

        reasons.append(
            "URL is unusually long."
        )

        features.append(
            ("URL Length", str(len(url)), "Risk")
        )

    else:

        features.append(
            ("URL Length", str(len(url)), "Normal")
        )


    # --------------------------------------
    # @ SYMBOL
    # --------------------------------------

    if "@" in url:

        score += 20

        reasons.append(
            "URL contains an @ symbol."
        )

        features.append(
            ("@ Symbol", "Detected", "Risk")
        )

    else:

        features.append(
            ("@ Symbol", "Not Detected", "Normal")
        )


    # --------------------------------------
    # EXTRACT HOSTNAME
    # --------------------------------------

    hostname = ""

    try:

        clean_url = url.replace(
            "https://", ""
        ).replace(
            "http://", ""
        )

        hostname = clean_url.split("/")[0]
        hostname = hostname.split("@")[-1]
        hostname = hostname.split(":")[0]

    except Exception:

        hostname = ""


    # --------------------------------------
    # IP ADDRESS CHECK
    # --------------------------------------

    ip_pattern = (
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )

    if re.match(ip_pattern, hostname):

        score += 25

        reasons.append(
            "URL uses an IP address instead of a domain name."
        )

        features.append(
            ("IP Address", "Detected", "Risk")
        )

    else:

        features.append(
            ("IP Address", "Not Detected", "Normal")
        )


    # --------------------------------------
    # SUBDOMAIN CHECK
    # --------------------------------------

    parts = hostname.split(".")

    if len(parts) >= 4:

        score += 10

        reasons.append(
            "URL contains many subdomains."
        )

        features.append(
            ("Subdomains", str(len(parts) - 2), "Risk")
        )

    else:

        features.append(
            ("Subdomains", str(max(0, len(parts) - 2)), "Normal")
        )


    # --------------------------------------
    # SUSPICIOUS KEYWORDS
    # --------------------------------------

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

    lower_url = url.lower()

    for keyword in suspicious_keywords:

        if keyword in lower_url:

            found_keywords.append(keyword)


    if found_keywords:

        score += 10

        reasons.append(
            "Suspicious keywords detected: "
            + ", ".join(found_keywords)
        )

        features.append(
            (
                "Suspicious Keywords",
                ", ".join(found_keywords),
                "Risk"
            )
        )

    else:

        features.append(
            (
                "Suspicious Keywords",
                "None",
                "Normal"
            )
        )


    # --------------------------------------
    # HYPHEN CHECK
    # --------------------------------------

    if "-" in hostname:

        score += 5

        reasons.append(
            "Domain contains a hyphen."
        )

        features.append(
            ("Hyphen", "Detected", "Risk")
        )

    else:

        features.append(
            ("Hyphen", "Not Detected", "Normal")
        )


    # --------------------------------------
    # SUSPICIOUS FILE EXTENSIONS
    # --------------------------------------

    suspicious_extensions = [
        ".exe",
        ".scr",
        ".zip",
        ".bat"
    ]

    found_extension = None

    for extension in suspicious_extensions:

        if lower_url.endswith(extension):

            found_extension = extension
            break


    if found_extension:

        score += 15

        reasons.append(
            "URL ends with a suspicious file extension."
        )

        features.append(
            (
                "File Extension",
                found_extension,
                "Risk"
            )
        )

    else:

        features.append(
            (
                "File Extension",
                "None",
                "Normal"
            )
        )


    # --------------------------------------
    # LIMIT RULE SCORE
    # --------------------------------------

    score = min(score, 100)


    return score, reasons, features


# ==========================================
# HOME PAGE
# ==========================================

@app.route("/")
def home():

    return render_template("index.html")


# ==========================================
# ABOUT PAGE
# ==========================================

@app.route("/about")
def about():

    return render_template("about.html")


# ==========================================
# SCAN URL
# ==========================================

@app.route("/scan", methods=["POST"])
def scan():

    url = request.form.get("url", "").strip()


    if not url:

        return render_template(
            "result.html",
            url="",
            risk_score=0,
            status="Likely Safe",
            reasons=["No URL was entered."],
            features=[]
        )


    # --------------------------------------
    # RULE-BASED ANALYSIS
    # --------------------------------------

    rule_score, reasons, features = analyze_url(url)


    # --------------------------------------
    # MACHINE LEARNING PREDICTION
    # --------------------------------------

    try:

        url_vector = vectorizer.transform([url])

        prediction = model.predict(url_vector)[0]

        probabilities = model.predict_proba(
            url_vector
        )[0]

        confidence = max(probabilities) * 100


        if prediction == "phishing":

            ml_score = confidence

        else:

            ml_score = 100 - confidence


    except Exception as error:

        print("ML Prediction Error:", error)

        prediction = "unknown"

        ml_score = 50


    # --------------------------------------
    # HYBRID RISK SCORE
    # --------------------------------------

    final_score = (
        (rule_score * 0.40)
        +
        (ml_score * 0.60)
    )


    final_score = round(
        min(max(final_score, 0), 100)
    )


    # --------------------------------------
    # CLASSIFICATION
    # --------------------------------------

    if final_score >= 70:

        status = "Likely Phishing"


    elif final_score >= 30:

        status = "Suspicious"


    else:

        status = "Likely Safe"


    # --------------------------------------
    # ADD ML REASON
    # --------------------------------------

    if prediction == "phishing":

        reasons.append(
            "Machine learning model detected phishing-like URL patterns."
        )

    elif prediction == "safe":

        reasons.append(
            "Machine learning model found patterns associated with safer URLs."
        )


    # --------------------------------------
    # SAVE TO MYSQL
    # --------------------------------------

    db = get_db_connection()


    if db:

        try:

            cursor = db.cursor()

            query = """
                INSERT INTO scan_history
                (url, risk_score, result)
                VALUES (%s, %s, %s)
            """

            values = (
                url,
                final_score,
                status
            )

            cursor.execute(
                query,
                values
            )

            db.commit()

            cursor.close()

            db.close()

        except Exception as error:

            print(
                "Database Insert Error:",
                error
            )

            try:
                db.close()
            except:
                pass


    # --------------------------------------
    # SHOW RESULT
    # --------------------------------------

    return render_template(
        "result.html",
        url=url,
        risk_score=final_score,
        status=status,
        reasons=reasons,
        features=features
    )


# ==========================================
# HISTORY PAGE
# ==========================================

@app.route("/history")
def history():

    scans = []

    db = get_db_connection()


    if db:

        try:

            cursor = db.cursor()

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

            db.close()

        except Exception as error:

            print(
                "History Error:",
                error
            )

            try:
                db.close()
            except:
                pass


    return render_template(
        "history.html",
        scans=scans
    )


# ==========================================
# CLEAR HISTORY
# ==========================================

@app.route(
    "/clear-history",
    methods=["POST"]
)
def clear_history():

    db = get_db_connection()


    if db:

        try:

            cursor = db.cursor()

            cursor.execute(
                "TRUNCATE TABLE scan_history"
            )

            db.commit()

            cursor.close()

            db.close()

            return render_template(
                "history.html",
                scans=[]
            )

        except Exception as error:

            print(
                "Clear History Error:",
                error
            )

            try:
                db.close()
            except:
                pass


    return render_template(
        "history.html",
        scans=[]
    )


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/dashboard")
def dashboard():

    total = 0
    safe = 0
    suspicious = 0
    phishing = 0

    db = get_db_connection()


    if db:

        try:

            cursor = db.cursor()


            # Total scans

            cursor.execute(
                "SELECT COUNT(*) FROM scan_history"
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

            db.close()


        except Exception as error:

            print(
                "Dashboard Error:",
                error
            )

            try:
                db.close()
            except:
                pass


    # --------------------------------------
    # PERCENTAGES
    # --------------------------------------

    if total > 0:

        safe_percentage = round(
            safe / total * 100,
            1
        )

        suspicious_percentage = round(
            suspicious / total * 100,
            1
        )

        phishing_percentage = round(
            phishing / total * 100,
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


# ==========================================
# ERROR HANDLER
# ==========================================

@app.errorhandler(404)
def page_not_found(error):

    return render_template(
        "error.html"
    ), 404


# ==========================================
# RUN APPLICATION
# ==========================================

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