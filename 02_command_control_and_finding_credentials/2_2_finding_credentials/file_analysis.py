import os
import pathlib

threshold = 15634800  # About 6 months


def keyword_check(filename):
    keywords = ["password"]
    return True in [k in filename.lower() for k in keywords]


def contents_check(filename):
    keywords = ["http", ".com", ".org", ".net", ".edu", ".gov", "facebook", "twitter", "gmail"]
    with open(filename, "r") as f:
        try:
            contents = f.read()
        except:
            return False
    return True in [k in contents.lower() for k in keywords]


def usage_check(filename):
    fname = pathlib.Path(filename)
    stats = fname.stat()
    if (stats.st_atime - stats.st_mtime > threshold) \
            and (stats.st_mtime != stats.st_ctime):
        return True
    else:
        return False


def file_search(d):
    results = []
    for dirpath, _, files in os.walk(d):
        for filename in files:
            fname = os.path.join(dirpath, filename)
            if keyword_check(fname) or usage_check(fname):
                if contents_check(fname):
                    results.append(fname)
    return results


if __name__ == "__main__":
    directory = "C:\\Users\\hepos\\Documents"
    results = file_search(directory)
    for r in results:
        print(r)
