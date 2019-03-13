import sys
import os
import select
import gnupg
import hashlib
import boto3
import botocore
import io
import json
import random
import string

CONF_FILE = 'pypass.conf'
GPG = gnupg.GPG()


def sha256(fname):
    hash_sha256 = hashlib.sha256()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()


def confirm(field, validator=lambda _: True):
    while True:
        try:
            value1 = input('enter ' + field + ': ')
            if not validator(value1):
                continue
            value2 = input('confirm ' + field + ': ')
            if value1 == value2:
                return value1
            print('values did not match\n')
        except KeyboardInterrupt:
            return None


def random_password(length=20):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def fetch_db(config):
    buf = io.BytesIO()
    session = boto3.Session(profile_name=config['AWS_PROFILE'])
    s3 = session.client('s3')
    try:
        s3.download_fileobj(config['BUCKET_NAME'], config['DB_KEY'], buf)
        dec_db = GPG.decrypt(buf.getvalue())
        if dec_db.ok:
            return json.loads(dec_db.data)
        else:
            raise ValueError('Could no decrypt DB file')
    except botocore.exceptions.ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == '404':
            return []


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


def modify_password(db, account_id, user_id, password=None, overwrite=False):
    account = None
    for acc in db:
        if acc['id'] == account_id:
            account = acc
            break
    if account and not overwrite:
        return False
    if account is None:
        account = {'id': account_id}
        db.append(account)
    account['user_id'] = user_id
    account['password'] = password
    return True


def change_password(db, _):
    account_id = confirm('account')
    user_id = confirm('userid')
    password = confirm('password')
    if not password:
        password = random_password(length=20)
    modify_password(db, account_id, user_id, password, overwrite=True)


def add_password(db, _):
    account_id = confirm('account')
    user_id = confirm('userid')
    password = confirm('password')
    if not password:
        password = random_password(length=20)
    if not modify_password(db, account_id, user_id, password, overwrite=False):
        print('Could not add password for account %s - account exists' % account_id)


def cls(delay=10):
    print('press any key to continue\n')
    ready, _, _ = select.select([sys.stdin], [], [], delay)
    if ready:
        sys.stdin.readline()
    _ = os.system('clear')


def find_accounts(db, account_id):
    result = []
    for account in db:
        if account_id in account['id']:
            result.append(account)
    return result


def view_password_cmd(db, _):
    for account in find_accounts(db, input('account id: ')):
        print(json.dumps(account, indent=2) + '\n')
    cls()


def list_accounts(db, _):
    for account in db:
        print(account)
    cls()


def quit(*args):
    sys.exit(0)


class PasswordDatabase:

    def __init__(self, db):
        self.db = db
        self.initial_db = [d.copy() for d in db]

    def _find_account(self, account_id):
        for account in self.db:
            if account['id'] == account_id:
                return account

    def modify_account(self, account_id, user_id=None, password=None, overwrite=True):
        account = self._find_account(account_id)
        if account and not overwrite:
            return False
        if account is None:
            account = {'id': account_id}
            self.db.append(account)
        account['user_id'] = user_id
        account['password'] = password
        return True

    def add_account(self, account_id, user_id=None, password=None):
        self.modify_account(account_id, user_id, password, overwrite=False)

    def remove_account(self, account_id):
        account = self._find_account(account_id)
        if account:
            self.db.remove(account)

    def is_modified(self):
        if len(self.db) != len(self.initial_db):
            return True

        def sort_key(d):
            return d['id']

        for a, b in zip(sorted(self.db, key=sort_key), sorted(self.initial_db, key=sort_key)):
            if a != b:
                return True
        return False


COMMANDS = {
    'add': add_password,
    'ls': list_accounts,
    'view': view_password_cmd,
    'change': change_password,
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
