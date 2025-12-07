from flask import Flask, request, jsonify
import base64
import urllib.parse
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  

MALICIOUS_KEYWORDS = {"alert", "script", "javascript", "onload", "onerror"}

def letters_only(text: str) -> str:
    return ''.join(ch for ch in text.lower() if 'a' <= ch <= 'z')

@app.post("/detect")
def detect():
    data = request.get_json(silent=True) or {}
    command = (data.get("command") or "").strip()
    if not command:
        return jsonify({"error": "command is required"}), 400

    lower = command.lower()

    def is_malicious_level1(s: str) -> bool:
        s = s.lower()
        if "alert" in s and ("(" in s or "=" in s or "'" in s or "`" in s):
            return True
        if "onload" in s and "=" in s:
            return True
        if "script" in s and ("<" in s or ">" in s):
            return True
        if "onerror" in s and "=" in s:
            return True
        if "javascript" in s and ("(" in s or ":" in s or "`" in s):
            return True
        return False

    def is_malicious_level2(s: str) -> bool:
        s = s.lower()
        letters = letters_only(s)
        dangerous = {"alert", "script", "javascript", "onload", "onerror", "eval", "function", "iframe"}
        if any(word in s for word in dangerous):
            return True
        if any(word in letters for word in dangerous):
            return True
        if "<" in s and ">" in s:
            return True
        if "%3c" in s:
            return True
        if "<img" in s:
            return True
        if "<svg" in s and ("onload" in s or "onerror" in s):
            return True
        return False

    def safe_b64_decode(text: str) -> str:
        t = text.strip()
        pad = (-len(t)) % 4
        if pad:
            t += "=" * pad
        try:
            return base64.b64decode(t, validate=False).decode("utf-8", errors="ignore")
        except Exception:
            return ""

    def is_malicious_level3(s: str) -> bool:

        raw = s
        lower = raw.lower()
        letters = letters_only(lower)
        url_decoded = urllib.parse.unquote(raw)
        url_lower = url_decoded.lower()
        url_letters = letters_only(url_lower)
        b64_decoded = safe_b64_decode(raw)
        b64_lower = b64_decoded.lower()
        b64_letters = letters_only(b64_lower)

        candidates = [lower, letters, url_lower, url_letters, b64_lower, b64_letters]

        dangerous = {
            "alert", "script", "javascript", "onload", "onerror",
            "eval", "function", "iframe", "document.location"
        }

        if any(any(word in c for word in dangerous) for c in candidates):
            return True

        bracket_alert_patterns = [
            "window[\"alert\"]", "window['alert']",
            "parent[\"alert\"]", "parent['alert']",
            "self[\"alert\"]", "self['alert']",
            "top[\"alert\"]", "top['alert']",
            "this[\"alert\"]", "this['alert']",
            "frames[\"alert\"]", "frames['alert']",
            "content[\"alert\"]", "content['alert']",
        ]
        if any(any(p in c for p in bracket_alert_patterns) for c in candidates):
            return True

        svg_onload_patterns = ["<svg onload=", "<svg/onload=", ">\u003csvg onload="]
        if any(any(p in c for p in svg_onload_patterns) for c in candidates):
            return True

        if any(("<" in c and ">" in c) for c in [raw, url_decoded, b64_decoded]):
            return True

        return False

    level = int(data.get("level") or 1)
    if level == 3:
        is_malicious = is_malicious_level3(command)
    elif level == 2:
        is_malicious = is_malicious_level2(lower)
    else:
        is_malicious = is_malicious_level1(lower)
    status = "malicious" if is_malicious else "normal"
    return jsonify({"status": status, "command": command})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
