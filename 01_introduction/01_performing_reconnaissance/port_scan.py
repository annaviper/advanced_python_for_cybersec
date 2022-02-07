from scapy.all import *
import requests

ports = [20, 21, 22, 23, 25, 53, 69, 80, 110, 143, 161, 162, 389, 443, 445, 636, 8080, 8443]


def syn_scan(host) -> list:
    """Return open ports."""
    answered, _ = sr(IP(dst=host) / TCP(dport=ports, flags="S"), timeout=2, verbose=0)  # send receive
    p = [s[TCP].dport for (s,r) in answered if s[TCP].dport == r[TCP].sport and r[TCP].flags == "SA"]
    return p


def grab_banner(ip: str, port: int) -> str:
    """Send packet to a port and see what it sends back."""
    if port in [53, 6980, 443]:
        return ""
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        banner = s.recv(1024)
        return banner.decode("utf-8")
    except Exception:
        return ""


def grab_http_header(ip_or_domain: str, port: int):
    try:
        if port == 443:
            response = requests.head(f"https://{ip_or_domain}:{port}", verify=False)
        else:
            response = requests.head(f"https://{ip_or_domain}:{port}", verify=False)
        return response  # print response.headers
    except Exception as e:
        print(e)
        return ""
