import streamlit as st
import requests
from urllib.parse import urlparse

# These are the security headers we want to look for when we scan a website
RECOMMENDED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy"
]

def scan_website(url):
    # This function does the actual scanning of one website URL and returns info about it
    result = {"url": url}  # Start with the URL we’re checking
    headers_for_request = {
        # Pretend we’re a browser so sites don’t block us
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/115.0 Safari/537.36"
    }
    try:
        # Make a GET request to the URL, following any redirects and timing out after 5 seconds
        res = requests.get(url, headers=headers_for_request, timeout=5, allow_redirects=True)
        headers = res.headers  # Grab the response headers from the server

        # Check the final URL after redirects to see if it uses HTTPS (secure)
        final_url = res.url
        parsed_final = urlparse(final_url)
        result['https'] = parsed_final.scheme == 'https'

        # Find which recommended security headers are actually present
        present_headers = [header for header in RECOMMENDED_HEADERS if header in headers]
        server_info = headers.get("Server", "Not Present")  # Info about the server software
        result["server_info"] = server_info

        # Save True/False for each recommended header to our result
        result.update({header: (header in headers) for header in RECOMMENDED_HEADERS})

        # Look for "Index of /" text in the page to detect if directory listing is open (bad)
        result["open_directory"] = "Index of /" in res.text

        # Check if the site has a robots.txt file (good to have)
        robots_url = f"{parsed_final.scheme}://{parsed_final.netloc}/robots.txt"
        robots_res = requests.get(robots_url, headers=headers_for_request, timeout=3)
        result["robots_txt"] = robots_res.status_code == 200

        # Now decide a simple risk level based on HTTPS and headers found
        if not result['https']:
            result['risk_level'] = "High Risk"
        elif any(x in server_info.lower() for x in ["gws", "googlefrontend", "google frontends"]):
            # Some Google frontends are generally safe/trusted
            result['risk_level'] = "Good"
        elif len(present_headers) < 3:
            # If less than 3 recommended headers, that’s a risk flag
            result['risk_level'] = "High Risk"
        else:
            # Otherwise, consider it Good
            result['risk_level'] = "Good"

    except Exception as e:
        # If something went wrong (site down, bad URL, etc), mark as error
        result['error'] = str(e)
        for header in RECOMMENDED_HEADERS:
            result[header] = False  # Mark all headers as missing
        result["server_info"] = "Unknown"
        result["open_directory"] = False
        result["robots_txt"] = False
        result["risk_level"] = "Error"

    return result

def main():
    # This is the main Streamlit function where UI lives
    st.title("Website Vulnerability Scanner")  # Big title on top

    # Let user type or paste URLs, one per line
    urls_input = st.text_area("Enter URLs to scan (one per line)")

    # Scan button: when clicked, start scanning
    if st.button("Scan"):
        # Clean up user input: remove empty lines and spaces
        url_list = [url.strip() for url in urls_input.splitlines() if url.strip()]

        results = []  # We'll store each site's scan result here
        for url in url_list:
            # Make sure URL has a scheme (http/https), default to http if missing
            if not url.startswith("http"):
                url = "http://" + url
            
            # Scan the website and get its security info
            result = scan_website(url)
            results.append(result)

        # Show results in a neat format
        for site in results:
            st.subheader(site["url"])
            if "error" in site:
                st.error(f"Error scanning site: {site['error']}")
            else:
                st.write(f"**HTTPS:** {'✅' if site['https'] else '❌'}")
                st.write(f"**Server Info:** {site['server_info']}")
                st.write(f"**Open Directory Listing:** {'⚠️' if site['open_directory'] else '✅'}")
                st.write(f"**robots.txt Found:** {'✅' if site['robots_txt'] else '❌'}")
                for header in RECOMMENDED_HEADERS:
                    st.write(f"**{header}:** {'✅' if site[header] else '❌'}")
                st.write(f"**Security Summary:** {site['risk_level']}")

if __name__ == "__main__":
    main()

