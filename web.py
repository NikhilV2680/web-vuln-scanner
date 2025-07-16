import streamlit as st
import requests
from urllib.parse import urlparse
import csv
import io

st.set_page_config(page_title="Web URL Scanner")

st.title("Web URL Scanner")
st.write("Enter one URL per line to check its status and basic security information.")

# User input
urls_input = st.text_area("Enter URLs (one per line)", height=200)

if st.button("Scan"):
    urls = [u.strip() for u in urls_input.splitlines() if u.strip()]
    headers = {"User-Agent": "Mozilla/5.0"}
    results = []

    for url in urls:
        data = {"url": url}
        try:
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

    # Show results
    st.subheader("Scan Results")

    for result in results:
        st.markdown(f"**URL:** {result['url']}")
        st.write(f"Reachable: {result['reachable']}")
        st.write(f"Uses HTTPS: {result['https']}")
        st.write(f"Server: {result['server']}")
        st.write(f"robots.txt Found: {result['robots_txt']}")
        if 'error' in result:
            st.write(f"Error: {result['error']}")
        st.markdown("---")

    # Prepare CSV
    csv_buffer = io.StringIO()
    fieldnames = ['url', 'reachable', 'https', 'server', 'robots_txt', 'error']
    writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
    writer.writeheader()
    for row in results:
        writer.writerow(row)

    st.download_button(
        label="Download Results as CSV",
        data=csv_buffer.getvalue(),
        file_name="scan_results.csv",
        mime="text/csv"
    )
