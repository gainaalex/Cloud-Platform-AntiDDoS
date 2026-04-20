import urllib.parse

path_encoded = "/assets/config.php%00.jpg"

path_decoded = urllib.parse.unquote(path_encoded)

print(f"encoded: {path_encoded}")
print(f"decoded:  {path_decoded}")

print(f"decoded_repr: {repr(path_decoded)}")

print(f"decoded_len: {len(path_decoded)}")