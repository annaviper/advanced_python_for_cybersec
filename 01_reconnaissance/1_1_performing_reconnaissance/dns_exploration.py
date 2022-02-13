import dns
import dns.resolver
import socket

# contains most common subdomains
with open("subdomains.txt", "r") as f:
    dictionary = f.read().splitlines()

hosts = {}


def reverse_dns(ip_address) -> list:
    """Get domain from IP address."""
    try:
        result = socket.gethostbyaddr(ip)
        return [result[0]] + result[1]
    except socket.herror:
        return []


def dns_requests(sub, domain):
    """Get hostnames."""
    global hosts
    hostname = sub + domain
    try:
        # DNS response
        result = dns.resolver.resolve(hostname)
        if result:
            for answer in result:
                ip = answer.to_text()
                hostnames = reverse_dns(ip)
                subs = [sub]
                for hostname in hostnames:
                    if hostname.endswith(domain):
                        s = hostname.rstrip(domain)
                        subs.append(s)
                if ip in hosts:
                    s = hosts[ip]["subs"]
                    hosts[ip] = list(dict.fromkeys(s + subs))
                else:
                    hosts[ip] = list(dict.fromkeys(subs))
    except:
        return


def subdomain_search(domain: str, nums: bool):
    for word in dictionary:
        dns_requests(word, domain)
        if nums:  # check if extra servers exist
            for i in range(0, 10):
                dns_requests(word + str(i), domain)


def dns_search(domain: str, nums: bool) -> dict:
    """Map IP addresses to its associated subdomains."""
    subdomain_search(domain, nums)
    return hosts


if __name__ == '__main__':
    domain_name = ".google.com"
    hosts = dns_search(domain_name, True)
    for ip in hosts:
        print(ip, hosts[ip])
