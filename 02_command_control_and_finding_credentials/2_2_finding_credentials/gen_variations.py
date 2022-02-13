from itertools import product

common_subs = {
    "a": ["@", "4"],
    "b": ["8"],
    "e": ["3"],
    "g": ["6", "9"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["5", "$"],
    "t": ["7", "+"],
}
special = " !\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"


def gen_variations(password):
    variations = [""]
    for p in password:
        uppers = [v + p.upper() for v in variations]
        lowers = [v + p.lower() for v in variations]
        vs = uppers + lowers
        if p in common_subs:
            for s in common_subs[p]:
                x = [v + s for v in variations]
                vs += x
        variations = vs
    return variations


def gen_suffixes():
    specs = [x for x in special]
    nums = [str(n) for n in range(100)]
    combos = list(product(specs, nums))
    sn = [c[0] + c[1] for c in combos]
    ns = [c[1] + c[0] for c in combos]
    return sn + ns


def gen_passwords(password):
    variations = gen_variations(password)
    suffixes = gen_suffixes()
    passwords = variations + [[v + s for v in variations] for s in suffixes]
    return passwords