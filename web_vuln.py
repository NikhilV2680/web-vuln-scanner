import os

import requests
import streamlit as st

from scanner import scan_website


API_URL = os.getenv(
    "API_URL",
    "http://127.0.0.1:5000"
)

RECOMMENDED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]


def request_scan(url):
    """
    Use the Flask API when it is running.
    If Flask is unavailable, run the scanner directly.
    """
    try:
        response = requests.post(
            f"{API_URL}/scan",
            json={"url": url},
            timeout=10,
        )

        response.raise_for_status()

        return response.json()

    except requests.ConnectionError:
        return scan_website(url)


def show_result(result):
    st.subheader(result["url"])

    if "error" in result:
        st.error(
            f"Error scanning site: {result['error']}"
        )
        return

    st.write(
        f"**Final URL:** {result['final_url']}"
    )

    st.write(
        f"**Status Code:** {result['status_code']}"
    )

    https_status = "✅" if result["https"] else "❌"

    st.write(
        f"**HTTPS:** {https_status}"
    )

    st.write(
        f"**Server Info:** {result['server_info']}"
    )

    if result["open_directory"]:
        directory_status = "⚠️ Found"
    else:
        directory_status = "✅ Not found"

    st.write(
        f"**Open Directory Listing:** "
        f"{directory_status}"
    )

    robots_status = (
        "✅" if result["robots_txt"] else "❌"
    )

    st.write(
        f"**robots.txt Found:** {robots_status}"
    )

    st.write("**Security Headers:**")

    for header in RECOMMENDED_HEADERS:
        if result[header]:
            header_status = "✅"
        else:
            header_status = "❌"

        st.write(
            f"- {header}: {header_status}"
        )

    st.write(
        f"**Security Summary:** "
        f"{result['risk_level']}"
    )


def main():
    st.set_page_config(
        page_title="Website Vulnerability Scanner"
    )

    st.title("Website Vulnerability Scanner")

    st.write(
        "Enter one URL per line to check "
        "basic website security settings."
    )

    urls_input = st.text_area(
        "URLs to scan"
    )

    if st.button("Scan"):
        urls = [
            url.strip()
            for url in urls_input.splitlines()
            if url.strip()
        ]

        if not urls:
            st.warning(
                "Enter at least one URL."
            )
            return

        for url in urls:
            try:
                result = request_scan(url)
                show_result(result)

            except requests.RequestException as error:
                st.error(
                    "Could not communicate with the "
                    f"Flask backend: {error}"
                )


if __name__ == "__main__":
    main()