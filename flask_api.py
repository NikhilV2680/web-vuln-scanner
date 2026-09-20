from flask import Flask, jsonify, request

from scanner import scan_website


app = Flask(__name__)


@app.get("/health")
def health_check():
    return jsonify({"status": "running"})


@app.post("/scan")
def scan():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "A URL is required"}), 400

    result = scan_website(url)

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, port=5000)