import winreg

"""Getting access to credentials cached in the Windows registry."""

matches = {}
string_values = [winreg.REG_SZ, winreg.REG_MULTI_SZ, winreg.REG_EXPAND_SZ]


def subkeys(hive, path):
    try:
        key = winreg.OpenKey(hive, path)
    except Exception as e:
        return
    num_subkeys = winreg.QueryInfoKey(key)[0]
    for i in range(num_subkeys):
        subkey = winreg.EnumKey(key, i)
        yield subkey


def values(hive, path):
    """Open key"""
    try:
        key = winreg.OpenKey(hive, path)
    except Exception as e:
        return
    num_values = winreg.QueryInfoKey(key)[1]
    for i in range(num_values):
        value = winreg.EnumValue(key, i)
        yield value  # creates a generator


def traverse_subkeys(name, hive, regpath, keywords):
    """Searches recursively through the registries."""
    for value in values(hive, regpath):
        match = True in [k in value[0].lower() for k in keywords]
        if match and value[2] in string_values:
            if len(value[1]) > 0 and not value[1].replace(".", "", 1).isdigit():
                print(f"{name}\\{regpath}\\{value[0]}: {value[1]}")
    # subdirectories
    for subkey in subkeys(hive, regpath):
        subpath = f"{regpath}\\{subkey}"
        match = True in [k in subkey.lower() for k in keywords]
        if match:
            val = winreg.QueryValue(hive, subpath)
            if len(val) > 0 and not val.replace(".", "", 1).isdigit():
                print(f"{name}\\{subpath}: {val}")
            matches[subpath] = val
        traverse_subkeys(name, hive, subpath, keywords)


def search_registry_keys(hive, path, keyword):
    traverse_subkeys(hive[0], hive[1], path, keyword)


if __name__ == "__main":
    keywords = ["password", "keyfile"]
    for hive in [["HKLM", winreg.HKEY_LOCAL_MACHINE], ["HKCU", winreg.HKEY_CURRENT_USER], ["HKU", winreg.HKEY_USERS]]:
        search_registry_keys(hive, r"SOFTWARE", keywords)
