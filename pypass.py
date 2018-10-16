import sys
import os
import select
import gnupg
import hashlib
import boto3
import io
import json

CONF_FILE = 'pypass.conf'
GPG = gnupg.GPG()

def sha256(fname):
    hash_sha256 = hashlib.sha256()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()


def fetch_db(config):
    buf = io.BytesIO()
    session = boto3.Session(profile_name=config['AWS_PROFILE'])
    s3 = session.client('s3')
    s3.download_fileobj(config['BUCKET_NAME'], config['DB_KEY'], buf)
    dec_db = GPG.decrypt(buf.getvalue())
    if dec_db.ok:
        return json.loads(dec_db.data)
    else:
        raise ValueError('Could no decrypt DB file')


def store_db(json_db, config):
    enc_db = GPG.encrypt(json.dumps(json_db), config['GPG_KEY_ID'])
    if enc_db.ok:
        session = boto3.Session(profile_name=config['AWS_PROFILE'])
        s3 = session.client('s3')
        s3.put_object(Body=enc_db.data, Bucket=config['BUCKET_NAME'], Key=config['DB_KEY'])
    else:
        raise Exception('Could not encrypt DB: ' + enc_db.status)


def tbd(config):
    with open('test', 'w') as f:
        f.write('This is a test mesage')
    with open('test', 'rb') as f:
        enc = GPG.encrypt_file(f, config['GPG_KEY_ID'], output='test.enc')
        if not enc.ok:
            sys.exit(1)
    with open('test.enc', 'rb') as f:
        dec = GPG.decrypt_file(f, output='test.dec')
        if not dec.ok:
            sys.exit(1)
    i_hash = sha256('test')
    o_hash = sha256('test.dec')
    if i_hash != o_hash:
        sys.exit(1)


def add_password(db, _):
    pass


def view_password(db, _):
    account_id = input('account id: ')
    for account in db.keys():
        if account_id in account:
            print('Details for account id=' + account)
            print(json.dumps(db[account], indent=2))
    ready, _, _ = select.select([sys.stdin], [], [], 10)
    if ready:
        sys.stdin.readline()
    _ = os.system('clear')


def quit(*args):
    sys.exit(0)


COMMANDS = {
    'add': add_password,
    'view': view_password,
    'store': store_db,
    'quit': quit
}


def read_command():
    while True:
        command = input('command: ')
        if command in COMMANDS:
            return COMMANDS[command]
        else:
            print("Valid commands are %s" % (', '.join([str(k) for k in COMMANDS.keys()])))


if __name__ == '__main__':
    with open(CONF_FILE, 'r') as f:
        config = json.load(f)
        db = fetch_db(config)
        while True:
            command = read_command()
            command(db, config)
