import hashlib
from rsa_python import *

def concat(plaintext: str, hashed: list) -> str:
    return plaintext + "-----" + "=".join([str(int) for int in hashed])

def unconcat(plaintext: str) -> tuple:
    splitted = plaintext.split("-----")
    return splitted[0], list(map(int, splitted[1].split("=")))

def hash(plaintext: str) -> str:
    h = hashlib.sha3_256()
    h.update(plaintext.encode('utf-8'))
    return "".join(str(hex(i)) + "/" for i in h.digest())

def valid_check(message: str, public_key: tuple) -> None:
    realtext, encrypt_hashed = unconcat(message)

    hashed = hash(realtext)
    print("\nhashed    =", hashed)

    decrypted = decrypt(encrypt_hashed, public_key)
    print("decrypted =", decrypted)

    assert hashed == decrypted
    print("\nassertion success, message is valid!")

if __name__ == '__main__':
    public_key,private_key = generate_keyPairs() 
    print("\nPublic: ",public_key)
    print("Private: ",private_key)
    
    plaintext = "Hello from Alice"
    print("plaintext =", plaintext, "\n")
    hashed = hash(plaintext)

    ctext = encrypt(hashed, private_key)
    print("encrypted  =", ctext)

    message = concat(plaintext, ctext)

    valid_check(message, public_key)
