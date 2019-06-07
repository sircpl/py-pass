import sys
import os
import select
from datetime import datetime
import gnupg
import hashlib
import boto3
import botocore
import io
import json
import random
import string

CONF_FILE = 'pypass.conf'
DEFAULT_PASSWORD_LENGTH = 20
GPG = gnupg.GPG()


def sha256(fname):
    hash_sha256 = hashlib.sha256()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()


def confirm_input(field, validator=lambda _: True):
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


def read_input(field):
    return input('enter ' + field + ': ')


def random_password(length=DEFAULT_PASSWORD_LENGTH):
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


def cls(delay=10):
    print('\npress any key to continue\n')
    ready, _, _ = select.select([sys.stdin], [], [], delay)
    if ready:
        sys.stdin.readline()
    _ = os.system('clear')


class PasswordDatabase:

    _ACCOUNT_ID = 'id'
    _USER_ID = 'user_id'
    _PASSWORD = 'password'
    _PREVIOUS = "previous"
    _MODIFIED = 'modified'

    def __init__(self, db=None):
        if not db:
            db = []
        self.db = [d.copy() for d in db]
        self.initial_db = self.copy()

    def __iter__(self):
        return iter(self.copy())

    def _find_account(self, account_id):
        for account in self.db:
            if account[self._ACCOUNT_ID] == account_id:
                return account

    def search(self, account_id):
        return [account.copy() for account in filter(lambda a: account_id in a[self._ACCOUNT_ID], self.db)]

    def copy(self):
        return [account.copy() for account in self.db]

    def modify_account(self, account_id, user_id=None, password=None):
        if not account_id:
            return False
        account = self._find_account(account_id)
        if not account:
            return False
        if password:
            if self._PASSWORD in account:
                account[self._PREVIOUS] = account[self._PASSWORD]
            account[self._PASSWORD] = password
        if user_id:
            account[self._USER_ID] = user_id
        if password or user_id:
            account[self._MODIFIED] = datetime.utcnow().isoformat(' ')
        return True

    def add_account(self, account_id, user_id, password):
        if not account_id or not user_id or not password:
            return False
        account = self._find_account(account_id)
        if account:
            return False
        account = {
            self._ACCOUNT_ID: account_id,
            self._USER_ID: user_id,
            self._PASSWORD: password
        }
        self.db.append(account)
        return True

    def remove_account(self, account_id):
        account = self._find_account(account_id)
        if account:
            self.db.remove(account)
            return True
        return False

    def is_modified(self):
        if len(self.db) != len(self.initial_db):
            return True

        def sort_key(d):
            return d['id']

        for a, b in zip(sorted(self.db, key=sort_key), sorted(self.initial_db, key=sort_key)):
            if a != b:
                return True
        return False


# Commands


def add_account_cmd(db, _):
    account_id = confirm_input('account')
    user_id = confirm_input('userid')
    password = confirm_input('password')
    if not password:
        password = random_password(length=DEFAULT_PASSWORD_LENGTH)
    if not db.add_account(account_id, user_id, password):
        print('Could not add password for account %s - account exists' % account_id)


def change_account_cmd(db, _):
    account_id = confirm_input('account')
    user_id = confirm_input('userid')
    password = confirm_input('password')
    if not password:
        password = random_password(length=DEFAULT_PASSWORD_LENGTH)
    if not db.modify_account(account_id, user_id, password):
        print('Could not modify account %s - account does not exist' % account_id)


def delete_account_cmd(db, _):
    account_id = confirm_input('account')
    if not db.remove_account(account_id):
        print('Could not delete account ''%s''. Account does not exist')


def list_accounts_cmd(db, _):
    for account in db:
        print(account)


def search_password_cmd(db, _):
    for account in db.search(read_input('account')):
        print(json.dumps(account, indent=2) + '\n')


def store_db_cmd(db, config):
    enc_db = GPG.encrypt(json.dumps(db.copy()), config['GPG_KEY_ID'])
    if enc_db.ok:
        session = boto3.Session(profile_name=config['AWS_PROFILE'])
        s3 = session.client('s3')
        s3.put_object(Body=enc_db.data, Bucket=config['BUCKET_NAME'], Key=config['DB_KEY'])
    else:
        raise Exception('Could not encrypt DB: ' + enc_db.status)


def quit_cmd(*args):
    sys.exit(0)


COMMANDS = {
    'add': add_account_cmd,
    'change': change_account_cmd,
    'delete': delete_account_cmd,
    'ls': list_accounts_cmd,
    'quit': quit_cmd,
    'search': search_password_cmd,
    'store': store_db_cmd,
}


def read_command():
    while True:
        command = read_input('command')
        if command in COMMANDS:
            return COMMANDS[command]
        else:
            for c in COMMANDS.keys():
                if c.startswith(command):
                    return COMMANDS[c]
            print("Valid commands are %s" % (', '.join(['(' + str(k)[0] + ')' + str(k)[1:] for k in COMMANDS.keys()])))


if __name__ == '__main__':
    with open(CONF_FILE, 'r') as f:
        config = json.load(f)
        db = PasswordDatabase(fetch_db(config))
        os.system('clear')
        while True:
            command = read_command()
            command(db, config)
            cls()
