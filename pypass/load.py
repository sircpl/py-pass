from typing import Tuple
import re


class LineParser:

    LINE_FORMATS = [
        (re.compile(r'([^:]+): (\S+) - (\S+)'), lambda m: (m.group(1), m.group(2), m.group(3), None)),
        (re.compile('([^:]+):([^/]+)/(.*)'), lambda m: (m.group(1), m.group(2), m.group(3), None)),
        (re.compile(r'([^(]+)\(([^)]+)\): ?([^/]+)/(.*)'), lambda m: (m.group(1), m.group(3), m.group(4), m.group(2)))
    ]

    def __init__(self, line: str = None):
        account = None
        user = None
        password = None
        note = None
        if line:
            account, user, password, note = self.parse(line)
        self.account = account
        self.user = user
        self.password = password
        self.note = note

    @property
    def account(self) -> str:
        return self.__account

    @account.setter
    def account(self, account: str):
        self.__account = account.strip() if account else None

    @property
    def user(self) -> str:
        return self.__user

    @user.setter
    def user(self, user: str):
        self.__user = user.strip() if user else None

    @property
    def password(self) -> str:
        return self.__password

    @password.setter
    def password(self, password: str):
        self.__password = password.strip() if password else None

    @property
    def note(self) -> str:
        return self.__note

    @note.setter
    def note(self, note: str):
        self.__note = note.strip() if note else None

    def __str__(self):
        return 'LineParser[account=%s, user=%s, password=%s, note=%s]' % (self.account, self.user, self.password, self.note)

    @staticmethod
    def parse(line: str) -> Tuple:
        for lf, extract_fn in LineParser.LINE_FORMATS:
            m = lf.match(line.strip())
            if m:
                return extract_fn(m)
        raise ValueError('line did not match expected format')
