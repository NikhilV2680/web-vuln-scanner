import requests
from urllib.parse import urlparse


RECOMMENDED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]


def normalize_url(url):
    """Clean up a URL and add a scheme when the user leaves it out."""
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    return url


def scan_website(url):
    """Scan one website and return the results as a dictionary."""
    url = normalize_url(url)
    result = {"url": url}

    request_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/115.0 Safari/537.36"
        )
    }

    try:
        response = requests.get(
            url,
            headers=request_headers,
            timeout=5,
            allow_redirects=True,
        )

        response_headers = response.headers
        final_url = response.url
        parsed_url = urlparse(final_url)

        result["final_url"] = final_url
        result["status_code"] = response.status_code
        result["https"] = parsed_url.scheme == "https"
        result["server_info"] = response_headers.get(
            "Server",
            "Not Present"
        )

        result["open_directory"] = "Index of /" in response.text

        present_headers = []

        for header in RECOMMENDED_HEADERS:
            is_present = header in response_headers
            result[header] = is_present

            if is_present:
                present_headers.append(header)

        robots_url = (
            f"{parsed_url.scheme}://"
            f"{parsed_url.netloc}/robots.txt"
        )

        try:
            robots_response = requests.get(
                robots_url,
                headers=request_headers,
                timeout=3,
            )

            result["robots_txt"] = (
                robots_response.status_code == 200
            )

        except requests.RequestException:
            result["robots_txt"] = False

        if not result["https"]:
            result["risk_level"] = "High Risk"

        elif len(present_headers) < 3:
            result["risk_level"] = "Needs Review"

        else:
            result["risk_level"] = "Good"

    except requests.RequestException as error:
        result["error"] = str(error)
        result["https"] = False
        result["server_info"] = "Unknown"
        result["open_directory"] = False
        result["robots_txt"] = False
        result["risk_level"] = "Error"

        for header in RECOMMENDED_HEADERS:
            result[header] = False

    return result