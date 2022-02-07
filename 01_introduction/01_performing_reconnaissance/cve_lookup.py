import requests

with open("vuldb_api.txt", "r") as f:
    key = f.read()


def vuldb_lookup(product, version=None) -> list:
    """Use information obtained from service_lookup
    to see if there is a vulnerability to exploit."""
    url = "https://vuldb.com/?api"
    if version:
        q = f"{product},{version}"
    else:
        q = f"{product}"
    query = {
        "apikey": key,
        "advancedsearch": q
    }
    results = requests.post(url, query)
    j = results.json()
    if "result" in j:
        sources = [result["source"] for result in j["result"] if "source" in result]
        return sources
    else:
        return []
