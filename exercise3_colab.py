# COMP842 - Applied Blockchains and Cryptocurrencies
# Exercise 3 - Elliptic Curve Cryptography (ECDSA on secp256k1)
# Zin Mar Win

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# secp256k1 (same curve Bitcoin uses): y^2 = x^3 + 7 mod P
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
CURVE = ec.SECP256K1()


def mod_sqrt(a, p):
    # p % 4 == 3 for secp256k1 so this shortcut works: sqrt(a) = a^((p+1)/4) mod p
    return pow(a, (p + 1) // 4, p)


def compress_pubkey(x, y):
    # instead of storing both x and y, we only need x + which "side" y is on (even/odd)
    # since the curve equation lets us recompute y from x later
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    return prefix + x.to_bytes(32, "big")


def decompress_pubkey(comp_bytes):
    prefix = comp_bytes[0]
    x = int.from_bytes(comp_bytes[1:], "big")
    y_squared = (pow(x, 3, P) + 7) % P
    y = mod_sqrt(y_squared, P)
    # the sqrt gives us one of the two possible y values, flip it if parity doesn't match
    if (y % 2 == 0) != (prefix == 0x02):
        y = P - y
    return x, y


def check_signature(pubkey, sig, msg, tag):
    try:
        pubkey.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        print(f"  -> {tag}: signature OK")
        return True
    except InvalidSignature:
        print(f"  -> {tag}: signature INVALID")
        return False


print("### 1. generating an ECDSA key pair ###\n")

priv_key = ec.generate_private_key(CURVE)
pub_key = priv_key.public_key()

priv_num = priv_key.private_numbers().private_value
pub_num = pub_key.public_numbers()
x, y = pub_num.x, pub_num.y

# private_ks / public_ks as required by the assignment - raw hex form
private_ks = priv_num.to_bytes(32, "big")
public_ks = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")  # 0x04 = uncompressed marker

priv_pem = priv_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()

pub_pem = pub_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()

print("Private key (PEM):")
print(priv_pem)
print("private_ks (hex):", private_ks.hex())
print()
print("Public key (PEM):")
print(pub_pem)
print("public_ks (hex):", public_ks.hex())


print("\n### 2. comparing key sizes ###\n")
print(f"private_ks -> {len(private_ks)} bytes ({len(private_ks.hex())} hex chars)")
print(f"public_ks  -> {len(public_ks)} bytes ({len(public_ks.hex())} hex chars)")
# public key is bigger because it's a full (x, y) point, private key is just one number


print("\n### 3. compressing the public key ###\n")
compressed = compress_pubkey(x, y)
print("uncompressed:", public_ks.hex(), f"({len(public_ks)} bytes)")
print("compressed  :", compressed.hex(), f"({len(compressed)} bytes)")

saving = (1 - len(compressed) / len(public_ks)) * 100
print(f"space saved: {saving:.2f}%")


print("\n### 4. decompressing and checking it matches ###\n")
x2, y2 = decompress_pubkey(compressed)
same = (x2 == x) and (y2 == y)
print("x matches:", x2 == x)
print("y matches:", y2 == y)
print("decompression correct overall:", same)

rebuilt_pubkey = ec.EllipticCurvePublicNumbers(x2, y2, CURVE).public_key()


print("\n### 5. sign + verify demo ###\n")
message = b"Blockchain assignment: ECDSA compressed public key demonstration"
signature = priv_key.sign(message, ec.ECDSA(hashes.SHA256()))

print("message   :", message.decode())
print("signature :", signature.hex(), f"({len(signature)} bytes, DER)")
print()

v1 = check_signature(pub_key, signature, message, "original public key")
v2 = check_signature(rebuilt_pubkey, signature, message, "decompressed public key")

print("\n--- summary ---")
print(f"private key size    : {len(private_ks)} bytes")
print(f"public key size     : {len(public_ks)} bytes -> {len(compressed)} bytes compressed ({saving:.2f}% smaller)")
print(f"decompression worked: {same}")
print(f"verified with original key    : {v1}")
print(f"verified with decompressed key: {v2}")
