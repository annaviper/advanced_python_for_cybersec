from pandas import Series
from scipy.stats import entropy


def calc_entropy(data):
    s = Series(bytearray(data, "utf-8"))
    counts = s.value_counts()
    return entropy(counts)


def calc_hamming_distance(pass1, pass2):
    distance = 0
    l = min(len(pass1), len(pass2))
    for i in range(l):
        if pass1[i] != pass2[i]:
            distance += 1
    return distance


def check_subs(pass1, pass2):
    matches = []
    s = 0
    while s < len(pass1):
        m = None
        for l in range(len(pass1) - s, 1, -1):
            if pass1[s:s + l] in pass2:
                m = [pass1[s:s + l], s]
                break
        if m:
            matches.append(m)
            s = s + l
            m = None
        else:
            s += 1
    return matches


def analyze_passwords(passwords):
    p = {}
    for password in passwords:
        entropy = calc_entropy(password)
        matches = []
        for pass2 in passwords:
            if password != pass2:
                if calc_hamming_distance(password, pass2) < len(password):
                    subs = check_subs(password, pass2)
                    if subs:
                        matches.append([pass2, subs])
        p[password] = {"entropy": entropy, "matches": matches}
    return p


if __name__ == "__main__":
    passwords = [
        "Password",
        "FBPassword",
        "LIPassword",
        "GMPassword",
        "aHC[_'5y<f",
        "aHC[_'5y<f_FB"
    ]

    results = analyze_passwords(passwords)
    for password in results:
        r = results[password]
        print(password)
        print("\tEntropy: %s" % r["entropy"])
        print("\tMatches:")
        for match in r["matches"]:
            print("\t\t%s: %s" % (match[0], match[1]))
