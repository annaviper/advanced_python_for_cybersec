from pandas import Series
from scipy.stats import entropy

minLen = 5


def calc_entropy(data):
    s = Series(data)
    counts = s.value_counts()
    return entropy(counts)


def field_entropy(v):
    """Amount of randomness in the data or amount of information a particular piece of data can encode.
    Repetition lowers entropy. Higher values of entropy are better."""
    if type(v) in (str, bytes, bytearray):
        if type(v) is str:
            b = bytearray(v, "utf-8")
        else:
            b = bytearray(v)
        if len(b) >= minLen:
            e = calc_entropy(b)
            return e
        return None
    return None


if __name__ == "__main__":
    print("%s Entropy: %s" % ("Hello world!", field_entropy("Hello world!")))
    from random import randbytes
    r = randbytes(12)
    print("%s Entropy: %s" % (r, field_entropy(r)))
