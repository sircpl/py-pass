import gnupg
import sys
import hashlib


def sha256(fname):
    hash_sha256 = hashlib.sha256()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()


if __name__ == '__main__':
    gpg = gnupg.GPG()
    with open('test', 'w') as f:
        f.write('This is a test mesage')
    with open('test', 'rb') as f:
        enc = gpg.encrypt_file(f, 'colin.p.lancaster@gmail.com', output='test.enc')
        if not enc.ok:
            sys.exit(1)
    with open('test.enc', 'rb') as f:
        dec = gpg.decrypt_file(f, output='test.dec')
        if not dec.ok:
            sys.exit(1)
    i_hash = sha256('test')
    o_hash = sha256('test.dec')
    if i_hash != o_hash:
        sys.exit(1)
