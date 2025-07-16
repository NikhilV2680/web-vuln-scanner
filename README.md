Web Vulnerability Scanner

Hey! This is a simple web app I built to quickly check websites for some common security issues. You just drop in one or more URLs, and it tells you if the site is using HTTPS, has some important security headers, if it exposes directory listings, and if it has a robots.txt file. It even gives you a rough "risk level" based on what it finds.

Why did I make this?

Because sometimes you just want a quick check on websites to see if they’re doing the basics right security-wise. It’s not super deep or fancy, but it covers some key stuff and is easy to use. Plus, I wanted to practice building a Flask app that talks to the web and saves scan history.

How to get this running on your machine

1. Clone or download this repo wherever you want.

2. Open your terminal, go to the project folder.

3. Create a virtual environment (if you haven't already):
python3.11 -m venv venv

4. Activate the virtual environment:
On Mac/Linux:
source venv/bin/activate
On Windows (PowerShell):
.\venv\Scripts\Activate.ps1

5. Install the required packages:
pip install flask requests

6. Run the app:
python web.py

7. Open your browser and go to:
http://localhost:8000

How to use

- Paste one or more website URLs into the box (one URL per line).
- Click "Scan Websites."
- Wait a few seconds while it checks each site.
- You'll get a report showing the security headers found, HTTPS status, robots.txt presence, and directory listing warning.
- You can download the scan results as a CSV file if you want.

What it checks for

- HTTPS usage
- Presence of important security headers like Content-Security-Policy, Strict-Transport-Security, and others
- If the site shows a directory listing (which is bad)
- If it has a robots.txt file
- Basic "risk level" based on the findings

Limitations / What this is NOT

- This is a very simple scanner, not a full vulnerability scanner like professional tools.
- It only checks basic HTTP headers and robots.txt presence — no scanning for actual exploits or vulnerabilities.
- It depends on the site's response; if a site blocks bots or has unusual configurations, results might vary.
- The risk assessment is very simple and should NOT be used for critical security decisions.

How I built it

- Python 3.11.5
- Flask for the web server and templating
- Requests library to fetch the URLs and check headers
- Simple CSV file to save scan history locally

Want to improve it?

Feel free to fork, tweak, add new checks, or make the UI nicer. If you do, I'd love to hear about it!

Troubleshooting

- If you get errors about missing packages, double-check you're in the virtual environment and run:
pip install flask requests
- If the app says port 8000 is busy, either stop the other process using it or edit web.py to run on a different port.

Thanks for checking it out! Hope it helps you get a quick sense of website security basics.

— Nikhil
