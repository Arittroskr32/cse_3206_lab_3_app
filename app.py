from flask import Flask, request, jsonify
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

    level = int(data.get("level") or 1)
    if level == 2:
        is_malicious = is_malicious_level2(lower)
    else:
        is_malicious = is_malicious_level1(lower)
    status = "malicious" if is_malicious else "normal"
    return jsonify({"status": status, "command": command})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
