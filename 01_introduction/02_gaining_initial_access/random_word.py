from itertools import product
from timeit import default_timer


def load_words():
    with open("dictionary3000.txt", "r") as f:
        words = f.read().split("\n")
    return words


def gen_random_word_passwords(num):
    words = load_words()
    passwords = [""]
    for i in range(num):
        p = ["".join(p) for p in list(product(passwords, words))]
        passwords = p
    return passwords


if __name__ == "__main__":
    start = default_timer()
    gen_random_word_passwords(2)
    stop = default_timer()
    print("Runtime: %s" % (stop - start))
