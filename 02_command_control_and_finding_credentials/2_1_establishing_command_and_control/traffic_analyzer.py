from scapy.all import *
from scapy.layers.http import *
from pandas import Series
from entropy import field_entropy
from check_encoding import check_encoding

"""
To conceal command-and-control among the normal traffic.
Result: Count of protocols, type of packet, name, length, entropy, encoding...
"""

protocols = {}
target_layers = ("Raw", "DNS", "HTTP Request", "HTTP Response")
fields = {}


def protocol_analysis(p):
    """Investigate to hide CC in target layers."""
    layers = p.layers()
    # extract layer's name if layer matches our desired list `target_layers`
    match_layers = [l.name for l in [p.getlayer(i) for i in range(len(layers))] if l.name in target_layers]
    for proto in match_layers:
        if proto in protocols:
            protocols[proto] += 1
        else:
            protocols[proto] = 1
    return match_layers


def get_field_name(p, f):
    name = ""
    l = 0
    while p.getlayer(l).name != f:
        name += "%s:" % p.getlayer(l).name
        l += 1
    name += "%s" % p.getlayer(l).name
    return name


def field_analysis(p, proto):
    """Look for potential opportunities to hide data.
    Which fields of the packet could be used to store useful info."""
    x = get_field_name(p, proto)

    # Loop through fields of the packet
    for field in p[proto].fields:
        value = p[proto].fields[field]
        # Amount of randomness in a particular field
        entropy = field_entropy(value)
        if entropy:
            # Check if field carries encoded data
            enc = check_encoding(value)
            name = "%s:%s" % (x, field)
            if name in fields:
                fields[name]["entropy"].append(entropy)
                fields[name]["length"].append(len(value))
                fields[name]["encoding"].append(enc)
            else:
                fields[name] = {
                    "entropy": [entropy],
                    "length": [len(value)],
                    "encoding": [enc]
                }
    # nested fields
    for packet_field in p[proto].packetfields:
        name = packet_field.name
        if p[proto].getfieldval(name):
            for field in p[proto].getfieldval(name).fields:
                value = p[proto].getfieldval(name).getfieldval(field)
                entropy = field_entropy(value)
                if entropy:
                    enc = check_encoding(value)
                    n = "%s:%s:%s" % (x, name, field)
                    if n in fields:
                        fields[n]["entropy"].append(entropy)
                        fields[n]["length"].append(len(value))
                        fields[n]["encoding"].append(enc)
                    else:
                        fields[n] = {
                            "entropy": [entropy],
                            "length": [len(value)],
                            "encoding": [enc]}


def analyze_traffic(p):
    """Helper function."""
    protos = protocol_analysis(p)
    for proto in protos:
        field_analysis(p, proto)


# sniff(count=100,prn=analyzeTraffic) for live traffic, 100 packets, calling analyses on each one
sniff(offline="02_command_control_and_finding_credentials/assets/traffic.pcap", prn=analyze_traffic)

for p in protocols:
    print(p, protocols[p])

for f in fields:
    # Calculate average entropy
    entropies = fields[f]["entropy"]
    entropy_average = sum(entropies) / len(entropies)

    # Calculate average length
    lengths = fields[f]["length"]
    length_average = sum(lengths) / len(lengths)

    # Calculate counts of each encoding
    s = Series(fields[f]["encoding"])
    # print(s)
    counts = s.value_counts().to_dict()
    url = counts["URL"] / len(lengths) if "URL" in counts else 0.0
    b64 = counts["B64"] / len(lengths) if "B64" in counts else 0.0
    print("%s\n\tCount: %d\n\tAverage Length: %f\n\tAverage Entropy: %f\n\tURL Encoded: %f\n\tBase64 Encoded: %f" % (
    f, len(lengths), length_average, entropy_average, url, b64))
