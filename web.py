from flask import Flask, render_template, request, make_response
import requests
from urllib.parse import urlparse

app = Flask(__name__)

@app.route('/')
def home():
    # Show the main page with the URL input form
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    # Get the URLs entered by the user (one per line)
    urls = request.form.get('urls', '')
    url_list = [u.strip() for u in urls.splitlines() if u.strip()]  # Clean empty lines
    results = []

    headers = {"User-Agent": "Mozilla/5.0"}  # Pretend to be a browser

    for url in url_list:
        data = {"url": url}  # Store info about each URL here
        try:
            # Make the GET request to the URL, follow redirects, with a timeout
            response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
            parsed = urlparse(response.url)  # Parse the final URL after redirects

            data['reachable'] = True  # We got a response, so URL is reachable
            data['https'] = parsed.scheme == 'https'  # Check if HTTPS is used
            data['server'] = response.headers.get('Server', 'Unknown')  # Server info header

            # Now check if robots.txt exists for this domain
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            try:
                r = requests.get(robots_url, headers=headers, timeout=3)
                data['robots_txt'] = r.status_code == 200  # Found if status 200
            except:
                data['robots_txt'] = False  # Could not reach robots.txt

        except Exception as e:
            # Something went wrong (timeout, connection error, etc)
            data['reachable'] = False
            data['https'] = False
            data['server'] = 'Unknown'
            data['robots_txt'] = False
            data['error'] = str(e)  # Save error message to show later

        results.append(data)  # Add this URL’s data to results list

    # Show results page with all URLs scanned
    return render_template('results.html', results=results)

@app.route('/download_csv', methods=['POST'])
def download_csv():
    # Get URLs again from textarea for CSV download
    urls = request.form.get('urls', '')
    url_list = [u.strip() for u in urls.splitlines() if u.strip()]
    headers = {"User-Agent": "Mozilla/5.0"}

    results = []
    for url in url_list:
        data = {"url": url}
        try:
            # Same scan logic as above to get fresh data for CSV
            response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
            parsed = urlparse(response.url)

            data['reachable'] = True
            data['https'] = parsed.scheme == 'https'
            data['server'] = response.headers.get('Server', 'Unknown')

            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            try:
                r = requests.get(robots_url, headers=headers, timeout=3)
                data['robots_txt'] = r.status_code == 200
            except:
                data['robots_txt'] = False

        except Exception as e:
            data['reachable'] = False
            data['https'] = False
            data['server'] = 'Unknown'
            data['robots_txt'] = False
            data['error'] = str(e)

        results.append(data)

    # Prepare CSV content as a string
    fieldnames = ['url', 'reachable', 'https', 'server', 'robots_txt', 'error']
    output = []
    output.append(",".join(fieldnames))  # CSV header

    for res in results:
        row = []
        for field in fieldnames:
            val = res.get(field, "")
            # Convert booleans to Yes/No for readability
            if isinstance(val, bool):
                val = "Yes" if val else "No"
            row.append(str(val))
        output.append(",".join(row))

    csv_data = "\n".join(output)

    # Send CSV back to user as a downloadable file
    response = make_response(csv_data)
    response.headers['Content-Disposition'] = 'attachment; filename=scan_results.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response


if __name__ == '__main__':
    # Start the Flask development server on port 8000 with debug enabled
    app.run(debug=True, port=8000)
