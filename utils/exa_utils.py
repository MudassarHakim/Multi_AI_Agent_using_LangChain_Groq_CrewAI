from exa_py import Exa

def fetch_threats(api_key, query="Latest cybersecurity threats 2024"):
    """
    Fetch recent cybersecurity threats from Exa API.
    Returns a list of dicts with keys: title, url, published_date, summary.
    """
    client = Exa(api_key=api_key)
    results = client.search_and_contents(query, summary=True)
    formatted = []
    for res in getattr(results, "results", []):
        formatted.append({
            "title": getattr(res, "title", "No Title"),
            "url": getattr(res, "url", None),
            "published_date": getattr(res, "published_date", "Unknown Date"),
            "summary": getattr(res, "summary", "No Summary")
        })
    return formatted

def fetch_latest_cves(api_key):
    """
    Fetch latest CVEs from Exa API.
    Returns a list of up to 5 dicts with keys: title, url, published_date, summary.
    """
    client = Exa(api_key=api_key)
    results = client.search_and_contents("Latest CVEs and security vulnerabilities 2024", summary=True)
    formatted = []
    for res in getattr(results, "results", [])[:5]:  # Only top 5 for brevity
        formatted.append({
            "title": getattr(res, "title", "No Title"),
            "url": getattr(res, "url", None),
            "published_date": getattr(res, "published_date", "Unknown Date"),
            "summary": getattr(res, "summary", "No Summary")
        })
    return formatted
