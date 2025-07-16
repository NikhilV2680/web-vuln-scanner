from flask import Flask, render_template, request, redirect, send_file
import requests
from urllib.parse import urlparse
import csv
import os

app = Flask(__name__)
SCAN_HISTORY_FILE = "history.csv"

RECOMMENDED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy"
]

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    urls = request.form.get('urls', '')
    url_list = [url.strip() for url in urls.splitlines() if url.strip()]

    all_results = []
    headers_for_request = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/115.0 Safari/537.36"
    }

    for url in url_list:
        result = {"url": url}
        try:
            res = requests.get(url, headers=headers_for_request, timeout=5, allow_redirects=True)
            headers = res.headers

            final_url = res.url
            parsed_final = urlparse(final_url)
            result['https'] = parsed_final.scheme == 'https'

            present_headers = [header for header in RECOMMENDED_HEADERS if header in headers]
            server_info = headers.get("Server", "").lower()
            result["server_info"] = headers.get("Server", "Not Present")

            result.update({header: (header in headers) for header in RECOMMENDED_HEADERS})
            result["open_directory"] = "Index of /" in res.text

            robots_url = f"{parsed_final.scheme}://{parsed_final.netloc}/robots.txt"
            robots_res = requests.get(robots_url, headers=headers_for_request, timeout=3)
            result["robots_txt"] = robots_res.status_code == 200

            # Risk determination
            if not result['https']:
                result['risk_level'] = "High Risk"
            elif any(x in server_info for x in ["gws", "googlefrontend", "google frontends"]):
                result['risk_level'] = "Good"
            elif len(present_headers) < 3:
                result['risk_level'] = "High Risk"
            else:
                result['risk_level'] = "Good"

        except Exception as e:
            result['error'] = str(e)
            for header in RECOMMENDED_HEADERS:
                result[header] = False
            result["server_info"] = "Unknown"
            result["open_directory"] = False
            result["robots_txt"] = False
            result["risk_level"] = "Error"

        all_results.append(result)

    save_to_history(all_results)

    return render_template('results.html', results=all_results)

@app.route('/download', methods=['POST'])
def download_csv():
    urls = request.form.getlist('url')
    if not urls:
        return redirect('/')

    with open(SCAN_HISTORY_FILE, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows = [row for row in reader if row['url'] in urls]

    output_file = 'scan_results.csv'
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    return send_file(output_file, as_attachment=True)

def save_to_history(results):
    file_exists = os.path.exists(SCAN_HISTORY_FILE)
    with open(SCAN_HISTORY_FILE, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        if not file_exists:
            writer.writeheader()
        writer.writerows(results)

if __name__ == '__main__':
    app.run(debug=True, port=8000)
