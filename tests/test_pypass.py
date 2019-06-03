import unittest
from unittest import mock
from pypass import pypass


class TestPypass(unittest.TestCase):

    def setUp(self):
        def do_nothing(*args, **kwargs):
            pass
        pypass.cls = do_nothing

    def test_default_rand_pass_len(self):
        self.assertEqual(len(pypass.random_password()), 20)

    def test_password_db_modified(self):
        db = pypass.PasswordDatabase([])
        self.assertFalse(db.is_modified())
        db.modify_account('test_account', 'test_user', 'password')
        self.assertTrue(db.is_modified())
        db.remove_account('test_account')
        self.assertFalse(db.is_modified())
        db = pypass.PasswordDatabase([{'id': 'test_account'}])
        db.modify_account('test_account', password='password')
        self.assertTrue(db.is_modified())

    def test_db_search(self):
        db = pypass.PasswordDatabase()
        db.add_account('test', 'test', 'test')
        db.add_account('tester', 'tester', 'tester')
        db.add_account('testing', 'testing', 'testing')
        db.add_account('miss', 'miss', 'miss')
        result = db.search('test')
        self.assertEqual(3, len(result))

    def test_db_remove(self):
        db = pypass.PasswordDatabase()
        self.assertFalse(db.remove_account('test'))
        db.add_account('test', 'test', 'test')
        self.assertTrue(db.remove_account('test'))

    def test_db_copy(self):
        db = pypass.PasswordDatabase()
        db.add_account('test', 'test', 'test')
        copy = db.copy()
        db = pypass.PasswordDatabase(copy)
        self.assertEqual(copy, db.copy())
        copy.append('modification')
        self.assertNotEqual(copy, db.copy())

    def test_db_modify(self):
        db = pypass.PasswordDatabase()
        self.assertFalse(db.modify_account(None))
        self.assertFalse(db.modify_account(''))
        self.assertTrue(db.modify_account('test', 'test', 'test'))
        self.assertFalse(db.modify_account('test', 'test', 'test', overwrite=False))
        self.assertTrue(db.modify_account('test', 'test', 'update', overwrite=True))
        account = db.search('test')[0]
        self.assertEqual('update', account['password'])
        self.assertEqual('test', account['previous'])

    def test_db_iterator(self):
        db = pypass.PasswordDatabase()
        db.add_account('test', 'test', 'test')
        copy = db.copy()
        for account in db:
            self.assertEqual(account, copy[0])

    @mock.patch('pypass.pypass.confirm_input')
    def test_cmd_add(self, mock_confirm_input):
        mock_confirm_input.side_effect = ['test_account', 'test_user', None]
        db = unittest.mock.Mock()
        pypass.add_password_cmd(db, {})
        db.add_account.assert_called_once()
        account, user, password = db.add_account.call_args[0]
        self.assertEqual(account, 'test_account')
        self.assertEqual(user, 'test_user')
        self.assertEqual(len(password), pypass.DEFAULT_PASSWORD_LENGTH)


if __name__ == '__main__':
    unittest.main()
