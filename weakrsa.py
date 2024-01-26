from Crypto.PublicKey import RSA
from Cryptodome.Util.number import bytes_to_long, long_to_bytes
import owiener

def get_pubkey(f):
    with open(f) as pub:
        key = RSA.importKey(pub.read())
    return (key.n, key.e)


def get_ciphertext(f):
    with open(f, 'rb') as ct:
        return bytes_to_long(ct.read())
    
def decrypt_rsa(N, e, d, ct):
    pt = pow(ct, d, N)
    return long_to_bytes(pt)

def pwn():
    N, e = get_pubkey('./key.pub') # the public key
    ct = get_ciphertext('./flag.enc') # the encrypted file
    d = owiener.attack(e, N)
    flag = decrypt_rsa(N, e, d, ct)
    print(flag)


pwn()