import unittest
from pypass import pypass


class TestPypass(unittest.TestCase):

    def setUp(self):
        def do_nothing(*args, **kwargs):
            pass
        pypass.cls = do_nothing

    def test_default_rand_pass_len(self):
        self.assertEqual(len(pypass.random_password()), 20)
        pypass.cls()

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


if __name__ == '__main__':
    unittest.main()
