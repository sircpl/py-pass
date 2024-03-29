import sys
import logging
import os
import select
from datetime import datetime
import gnupg
import boto3
import botocore
import io
import json
import random
import string
from getpass import getpass
from collections import OrderedDict
from pypass.load import LineParser

CONF_FILE = 'pypass.conf'
DEFAULT_PASSWORD_LENGTH = 20
GPG = gnupg.GPG()
LOGGER = logging.getLogger('pypass')


def confirm_input(field):
    while True:
        value1 = console_input('Enter ' + field + ': ')
        value2 = console_input('Confirm ' + field + ': ')
        if value1 == value2:
            return value1
        print('Entered values for %s did not match\n' % field)


def read_input(field):
    return console_input('Enter ' + field + ': ')


def random_password(length=DEFAULT_PASSWORD_LENGTH):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def fetch_db(config, password):
    buf = io.BytesIO()
    session = boto3.Session(profile_name=config['AWS_PROFILE'])
    s3 = session.client('s3')
    try:
        s3.download_fileobj(config['BUCKET_NAME'], config['DB_KEY'], buf)
        dec_db = GPG.decrypt(buf.getvalue(), passphrase=password)
        if dec_db.ok:
            return json.loads(dec_db.data)
        else:
            raise ValueError('Could not decrypt DB file')
    except botocore.exceptions.ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == '404':
            return []


def cls(timeout=10):
    print('\nPress enter to continue\n')
    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    if ready:
        sys.stdin.readline()
    _ = os.system('clear')


class TimeoutError(Exception):
    pass


def console_input(prompt, timeout=10):
    print(prompt, end='', flush=True)
    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    if ready:
        return sys.stdin.readline().strip()
    print()
    raise TimeoutError()


class PasswordDatabase:
    _ACCOUNT_ID = 'id'
    _USER_ID = 'user_id'
    _PASSWORD = 'password'
    _PREVIOUS = "previous"
    _MODIFIED = 'modified'

    def __init__(self, db=None, persistence_strategy=lambda pwdb: False):
        if not db:
            db = []
        self.db = [d.copy() for d in db]
        self.initial_db = self.copy()
        self.persistence_strategy = persistence_strategy

    def __iter__(self):
        return iter(self.copy())

    def _find_account(self, account_id):
        for account in self.db:
            if account[self._ACCOUNT_ID] == account_id:
                return account

    @staticmethod
    def _modified_timestamp():
        return datetime.utcnow().isoformat(' ')

    def contains_account(self, account_id):
        return True if self._find_account(account_id) else False

    def search(self, account_id):
        return [account.copy() for account in filter(lambda a: account_id in a[self._ACCOUNT_ID], self.db)]

    def copy(self):
        return [account.copy() for account in self.db]

    def modify_account(self, account_id, new_account_id=None, user_id=None, password=None):
        if not account_id:
            return False
        account = self._find_account(account_id)
        if not account:
            return False
        if new_account_id:
            account[self._ACCOUNT_ID] = new_account_id
        if password:
            if self._PASSWORD in account:
                account[self._PREVIOUS] = account[self._PASSWORD]
            account[self._PASSWORD] = password
        if user_id:
            account[self._USER_ID] = user_id
        if new_account_id or password or user_id:
            account[self._MODIFIED] = self._modified_timestamp()
            return True
        return False

    def add_account(self, account_id, user_id, password):
        if not account_id or not user_id or not password:
            return False
        account = self._find_account(account_id)
        if account:
            return False
        account = OrderedDict([
            (self._ACCOUNT_ID, account_id),
            (self._USER_ID, user_id),
            (self._PASSWORD, password),
            (self._PREVIOUS, None),
            (self._MODIFIED, self._modified_timestamp())
        ])
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
            return d[self._ACCOUNT_ID]

        for a, b in zip(sorted(self.db, key=sort_key), sorted(self.initial_db, key=sort_key)):
            if a != b:
                return True
        return False

    def persist(self) -> bool:
        if not self.is_modified():
            return False
        try:
            result = self.persistence_strategy(self)
            if result:
                self.initial_db = self.db.copy()
            return result
        except Exception as e:
            print(e)
            return False


# Commands

MODIFY_PROMPT = '''Which attribute would you like to modify?
    1) account_id
    2) user_id
    3) password
'''
MODIFY_PASSWORD_PROMPT = '''How would you like to modify the password?
    1) randomize
    2) manually
'''


def password_input():
    password_choice = console_input(MODIFY_PASSWORD_PROMPT)
    if password_choice == '1':
        return random_password()
    elif password_choice == '2':
        return confirm_input('password')
    else:
        print('Invalid selection')


def add_account_cmd(db, _):
    account_id = read_input('account_id')
    if db.contains_account(account_id):
        print('Cannot add account "%s". Account exists' % account_id)
        return
    user_id = read_input('user_id')
    password = password_input()
    if db.add_account(account_id, user_id, password):
        print('Added account "%s"' % account_id)
    else:
        print('Failed to add account')


def modify_account_cmd(db, _):
    account_id = read_input('account_id')
    if not db.contains_account(account_id):
        print('Cannot modify account "%s". Account does not exist' % account_id)
        return
    new_account_id, user_id, password = None, None, None
    attribute_id = console_input(MODIFY_PROMPT)
    if attribute_id == '1':
        new_account_id = read_input('new_account_id')
    elif attribute_id == '2':
        user_id = read_input('user_id')
    elif attribute_id == '3':
        password = password_input()
    else:
        print('Invalid selection')
    if db.modify_account(account_id, new_account_id, user_id, password):
        print('Modified account "%s"' % (new_account_id if new_account_id else account_id))
    else:
        print('No modifications made to account %s' % account_id)


def delete_account_cmd(db, _):
    account_id = confirm_input('account_id')
    if not db.contains_account(account_id):
        print('Cannot delete account "%s". Account does not exist' % account_id)
        return
    if db.remove_account(account_id):
        print('Deleted account "%s"' % account_id)
    else:
        print('Failed to delete account "%s"' % account_id)


def list_accounts_cmd(db, _):
    for account in db:
        print(_account_str(account))


def search_accounts_cmd(db, _):
    for account in db.search(read_input('account')):
        print(_account_str(account))


def _account_str(account):
    return json.dumps(account, indent=2)


def write_db_cmd(db, _):
    if db.persist():
        print("Persisted database succesfully")
    else:
        print("Failed to persist database")


def write_db_to_s3(db, config) -> bool:
    enc_db = GPG.encrypt(json.dumps(db.copy()), config['GPG_KEY_ID'])
    if enc_db.ok:
        try:
            session = boto3.Session(profile_name=config['AWS_PROFILE'])
            s3 = session.client('s3')
            s3.put_object(Body=enc_db.data, Bucket=config['BUCKET_NAME'], Key=config['DB_KEY'])
            return True
        except Exception as e:
            LOGGER.exception(e)
    else:
        raise Exception('Could not encrypt DB: ' + enc_db.status)


def quit_cmd(db, _):
    if db.is_modified():
        timeout = 60
        try:
            should_quit = console_input('Unsaved changes exist. Quit? (y/n): ', timeout)
            if should_quit.lower() != 'y':
                return
        except TimeoutError:
            print('\nTimed out after %s seconds. Unsaved changes were not persisted' % timeout)
    print('Goodbye!')
    sys.exit(0)


COMMANDS = {
    'add': add_account_cmd,
    'modify': modify_account_cmd,
    'delete': delete_account_cmd,
    'ls': list_accounts_cmd,
    'quit': quit_cmd,
    'search': search_accounts_cmd,
    'write': write_db_cmd,
}


def read_command():
    while True:
        try:
            command = read_input('command')
        except TimeoutError:
            command = 'quit'
        if command in COMMANDS:
            return COMMANDS[command]
        elif command:
            for c in COMMANDS.keys():
                if c.startswith(command):
                    return COMMANDS[c]
        print("Valid commands are %s" % (', '.join(['(' + str(k)[0] + ')' + str(k)[1:] for k in COMMANDS.keys()])))
        cls()


if __name__ == '__main__':
    conf = sys.argv[1] if len(sys.argv) > 1 else CONF_FILE
    with open(conf, 'r') as f:
        config = json.load(f)
        db = None
        if len(sys.argv) > 1 and sys.argv[1] == 'import':
            db = PasswordDatabase()
            for line in sys.stdin:
                try:
                    lp = LineParser(line)
                    db.add_account(lp.account, lp.user, lp.password)
                    print(lp)
                except ValueError as e:
                    print('could not parse: ' + line)
            write_db_cmd(db, config)
        else:
            password = getpass()
            db = PasswordDatabase(fetch_db(config, password), lambda pw_db: write_db_to_s3(pw_db, config))
            os.system('clear')

            while True:
                try:
                    command = read_command()
                    command(db, config)
                    cls()
                except KeyboardInterrupt:
                    _ = os.system('clear')
                except TimeoutError:
                    _ = os.system('clear')


