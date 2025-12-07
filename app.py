from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  

MALICIOUS_KEYWORDS = {"alert", "script", "javascript", "onload", "onerror"}

@app.post("/detect")
def detect():
    data = request.get_json(silent=True) or {}
    command = (data.get("command") or "").strip()
    if not command:
        return jsonify({"error": "command is required"}), 400

    lower = command.lower()


    def is_malicious_command(s: str) -> bool:
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

    is_malicious = is_malicious_command(lower)
    status = "malicious" if is_malicious else "normal"
    return jsonify({"status": status, "command": command})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
