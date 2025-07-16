import streamlit as st
import requests
from urllib.parse import urlparse

RECOMMENDED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy"
]

def scan_website(url):
    headers_for_request = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/115.0 Safari/537.36"
    }
    result = {"url": url}
    try:
        res = requests.get(url, headers=headers_for_request, timeout=5, allow_redirects=True)
        headers = res.headers

        final_url = res.url
        parsed_final = urlparse(final_url)
        result['https'] = parsed_final.scheme == 'https'

        present_headers = [header for header in RECOMMENDED_HEADERS if header in headers]
        server_info = headers.get("Server", "Not Present")
        result["server_info"] = server_info

        result.update({header: (header in headers) for header in RECOMMENDED_HEADERS})
        result["open_directory"] = "Index of /" in res.text

        robots_url = f"{parsed_final.scheme}://{parsed_final.netloc}/robots.txt"
        robots_res = requests.get(robots_url, headers=headers_for_request, timeout=3)
        result["robots_txt"] = robots_res.status_code == 200

        if not result['https']:
            result['risk_level'] = "High Risk"
        elif any(x in server_info.lower() for x in ["gws", "googlefrontend", "google frontends"]):
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
    return result

def main():
    st.title("Website Vulnerability Scanner")

    urls_input = st.text_area("Enter URLs to scan (one per line)")
    if st.button("Scan"):
        url_list = [url.strip() for url in urls_input.splitlines() if url.strip()]
        results = []
        for url in url_list:
            if not url.startswith("http"):
                url = "http://" + url  # add default sch

