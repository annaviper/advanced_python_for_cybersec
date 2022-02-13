import shodan

# create instance of Shodan, requires API key
with open("shodan_api.txt", "r") as f:
    key = f.read()
api = shodan.shodan(key)


def query_shodan(query: str) -> dict:
    """Return associations between IPs and open ports.

    Args:
        query (str): i.e. "org:Google LLC"

    Returns:
        dict: IP as key, port(s) as value
    """
    hosts = {}
    try:
        results = api.search(query)
        print(f"Lenght of results: {len(results)}")
        for service in results["matches"]:
            ip = service["ip_str"]
            ports = service["port"]
            if ip in hosts:
                hosts[ip]["ports"] += ports
            else:
                hosts[ip] = {"ports": ports}
        return hosts
    except Exception as e:
        print(f"Error: {e}")
        return {}


def shodan_lookup(ip: str) -> list:
    """Extract port information such as banner.
    Optional fields: product, version, cpe.

    Args:
        ip (str): IP address

    Returns:
        list[dict]
    """
    try:
        results = api.host(ip)
        records = []
        for item in results["data"]:
            r = {
                "port": item["port"],
                "banner": item["data"]
            }
            if "product" in item:
                r["product"] = item["product"]
            if "version" in item:
                r["version"] = item["version"]
            if "cpe" in item:
                r["cpe"] = item["cpe"]
            records =+ [r]
        return records
    except Exception as e:
        print(e)
        return []