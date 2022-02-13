import re
from base64 import b64decode, b64encode


def check_URL_encoding(data):
    """%hexadecimal."""
    if re.fullmatch("(%[0-9A-Fa-f]{2})+", str(data)):
        return True
    return False


def check_B64_encoding(data):
    """64 alphanumeric. Try to decode and see if it fails."""
    try:
        b64decode(data)
        return True
    except:
        return False


def check_encoding(data):
    """If data is likely to be encoded."""
    if len(data) == 0:
        return False

    if check_URL_encoding(data):
        return "URL"
    elif check_B64_encoding(data):
        return "B64"
    else:
        return ""


if __name__ == "__main__":
    data = [
        b64encode(bytes("Hello world!", "utf-8")),
        "%48%65%6C%6c%6F",
        "FFFFFFFF"
    ]
    for d in data:
        encoding = check_encoding(d)
        if encoding:
            print(d, encoding)
