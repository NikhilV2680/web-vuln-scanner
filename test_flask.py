from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return "Hello, Flask is running!"

if __name__ == "__main__":
    print("Starting minimal Flask app...")
    app.run(debug=True, port=8000, use_reloader=False)
