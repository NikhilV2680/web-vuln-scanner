from flask import Flask, render_template, request, redirect, send_file
import requests
from urllib.parse import urlparse
import csv
import os

app = Flask(__name__)
SCAN_HISTORY_FILE = "history.csv"

# These are the security headers we want to check for in the responses
RECOMMENDED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy"
]

@app.route('/')
def home():
    # Serve the main page with the form
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    # Get URLs entered by the user (multiple URLs allowed, one per line)
    urls = request.form.get('urls', '')
    url_list = [url.strip() for url in urls.splitlines() if url.strip()]

    all_results = []
    headers_for_request = {
        # Mimic a browser user-agent to avoid some blocking
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/115.0 Safari/537.36"
    }

    for url in url_list:
        result = {"url": url}
        try:
            # Try to make a GET request to the URL with a timeout
            res = requests.get(url, headers=headers_for_request, timeout=5, allow_redirects=True)
            headers = res.headers

            # Check if the final URL after redirects uses HTTPS
            final_url = res.url
            parsed_final = urlparse(final_url)
            result['https'] = parsed_final.scheme == 'https'

            # See which recommended headers are present in the response
            present_headers = [header for header in RECOMMENDED_HEADERS if header in headers]
            server_info = headers.get("Server", "").lower()
            result["server_info"] = headers.get("Server", "Not Present")

            # Mark each recommended header as True/False in the results
            result.update({header: (header in headers) for header in RECOMMENDED_HEADERS})

            # Check if "Index of /" is in the page content (possible open directory listing)
            result["open_directory"] = "Index of /" in res.text

            # Check if robots.txt exists on the site
            robots_url = f"{parsed_final.scheme}://{parsed_final.netloc}/robots.txt"
            robots_res = requests.get(robots_url, headers=headers_for_request, timeout=3)
            result["robots_txt"] = robots_res.status_code == 200

            # Simple risk scoring based on HTTPS and headers
            if not result['https']:
                result['risk_level'] = "High Risk"
            elif any(x in server_info for x in ["gws", "googlefrontend", "google frontends"]):
                result['risk_level'] = "Good"
            elif len(present_headers) < 3:
                result['risk_level'] = "High Risk"
            else:
                result['risk_level'] = "Good"

        except Exception as e:
            # In case of any error, set default/failure values and log the error message
            result['error'] = str(e)
            for header in RECOMMENDED_HEADERS:
                result[header] = False
            result["server_info"] = "Unknown"
            result["open_directory"] = False
            result["robots_txt"] = False
            result["risk_level"] = "Error"

        all_results.append(result)

    # Save results to CSV history file
    save_to_history(all_results)

    # Render the results page with the scan data
    return render_template('results.html', results=all_results)

@app.route('/download', methods=['POST'])
def download_csv():
    # Allow user to download CSV file with selected URLs from history
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

    # Send the CSV file as a downloadable attachment to the user
    return send_file(output_file, as_attachment=True)

def save_to_history(results):
    # Append new scan results to the history CSV file
    file_exists = os.path.exists(SCAN_HISTORY_FILE)
    with open(SCAN_HISTORY_FILE, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        if not file_exists:
            # Write header only if file is new
            writer.writeheader()
        writer.writerows(results)

if __name__ == '__main__':
    # Run Flask app on port 8000 with debug mode on for easier troubleshooting
    app.run(debug=True, port=8000)
