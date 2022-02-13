from scapy.all import *
from scapy.layers.http import *
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

"""Takes a listing of layers and creates a packet wit the C2."""

settings = {
    "src": "127.0.0.1",
    "dst": "8.8.8.8"
}


def build_layers(layers):
    p = Ether() / IP(src=settings["src"], dst=settings["dst"])
    for layer in layers.split(":")[2:]:  # TCP
        try:
            layer = layer.replace(" ", "")
            if layer == "HTTP1":
                layer = "HTTP"
            l = globals()[layer]()  # call func with a string
            p.add_payload(l)  # add additional layers to the packet
        except:
            return p
    return p


def set_payload(packet, layers, data):
    """C2 into the `load` value of the layers."""
    p = packet
    l = layers.split(":")
    for layer in l[:-1]:
        if packet.haslayer(layer):
            p = p[layer]
        else:  # nested field, i.e DNS
            p = getattr(p, layer)
    p.setfieldval(l[-1], data)  # `load` value of layers
    return packet


if __name__ == "__main__":
    # Listing of layers we want in our packet
    layers = "Ethernet:IP:TCP:HTTP 1:HTTP Response:Raw:load"
    packet = build_layers(layers)
    data = "Hello"  # C2
    packet = set_payload(packet, layers, data)
    packet.show()
