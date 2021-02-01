import unittest
from unittest import mock
from unittest.mock import Mock

from pypass.main import PasswordDatabase
from pypass.main import TimeoutError
from pypass import main


class TestPypass(unittest.TestCase):

    def setUp(self):
        self.patches = [mock.patch('pypass.main.cls'), mock.patch('builtins.print')]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def test_default_rand_pass_len(self):
        self.assertEqual(len(main.random_password()), 20)

    def test_password_db_modified(self):
        db = PasswordDatabase([])
        self.assertFalse(db.is_modified())
        db.add_account('test_account', 'test_user', 'password')
        self.assertTrue(db.is_modified())
        db.remove_account('test_account')
        self.assertFalse(db.is_modified())
        db = PasswordDatabase([{PasswordDatabase._ACCOUNT_ID: 'test_account'}])
        db.modify_account('test_account', password='password')
        self.assertTrue(db.is_modified())

    def test_db_search(self):
        db = PasswordDatabase()
        db.add_account('test', 'test', 'test')
        db.add_account('tester', 'tester', 'tester')
        db.add_account('testing', 'testing', 'testing')
        db.add_account('miss', 'miss', 'miss')
        result = db.search('test')
        self.assertEqual(3, len(result))

    def test_db_remove(self):
        db = PasswordDatabase()
        self.assertFalse(db.remove_account('test'))
        db.add_account('test', 'test', 'test')
        self.assertTrue(db.remove_account('test'))

    def test_db_copy(self):
        db = PasswordDatabase()
        db.add_account('test', 'test', 'test')
        copy = db.copy()
        db = PasswordDatabase(copy)
        self.assertEqual(copy, db.copy())
        copy.append('modification')
        self.assertNotEqual(copy, db.copy())

    def test_db_modify(self):
        db = PasswordDatabase()
        self.assertFalse(db.modify_account('test', None, None, None))
        self.assertFalse(db.modify_account(None, 'test', None, None))
        self.assertFalse(db.modify_account(None, None, 'test', None))
        self.assertFalse(db.modify_account(None, None, None, 'test'))
        self.assertFalse(db.modify_account('test', 'test', 'test', 'test'))
        db.add_account('test', 'test', 'test')
        self.assertFalse(db.modify_account('wrong', 'update', 'update', 'update'))
        self.assertTrue(db.modify_account('test', None, 'update', 'update'))
        account = db.search('test')[0]
        self.assertEqual('update', account[PasswordDatabase._USER_ID])
        self.assertEqual('update', account[PasswordDatabase._PASSWORD])
        self.assertEqual('test', account[PasswordDatabase._PREVIOUS])

        # test that you can modify the account id
        self.assertTrue(db.modify_account('test', 'update'))
        self.assertFalse(db.search('test'))
        account = db.search('update')[0]
        self.assertEqual('update', account[PasswordDatabase._USER_ID])
        self.assertEqual('update', account[PasswordDatabase._PASSWORD])
        self.assertEqual('test', account[PasswordDatabase._PREVIOUS])

    def test_db_iterator(self):
        db = PasswordDatabase()
        db.add_account('test', 'test', 'test')
        copy = db.copy()
        for account in db:
            self.assertEqual(account, copy[0])

    @mock.patch('pypass.main.read_input')
    @mock.patch('pypass.main.confirm_input')
    def test_cmd_add_account_exists(self, mock_confirm_input: Mock, mock_read_input: Mock):
        mock_confirm_input.return_value = None
        mock_read_input.return_value = 'test_account'
        db = Mock()
        db.contains_account.return_value = True
        main.add_account_cmd(db, {})
        db.add_account.assert_not_called()

    @mock.patch('pypass.main.password_input')
    @mock.patch('pypass.main.read_input')
    def test_cmd_add_account(self, mock_read_input: Mock, mock_password_input: Mock):
        mock_read_input.side_effect = ['test_account', 'test_user']
        mock_password_input.return_value = 'test_password'
        db = Mock()
        db.contains_account.return_value = False
        main.add_account_cmd(db, {})
        db.add_account.assert_called_once()
        account, user, password = db.add_account.call_args[0]
        self.assertEqual(account, 'test_account')
        self.assertEqual(user, 'test_user')
        self.assertEqual(password, 'test_password')

    @mock.patch('pypass.main.read_input')
    def test_cmd_add_account_timeout_account_id(self, mock_read_input: Mock):
        mock_read_input.side_effect = TimeoutError()
        db = Mock()
        db.contains_account.return_value = False
        main.add_account_cmd(db, {})
        db.add_account.not_called()

    @mock.patch('pypass.main.read_input')
    def test_cmd_add_account_timeout_user_id(self, mock_read_input: Mock):
        mock_read_input.side_effect = ['test_account', TimeoutError()]
        db = Mock()
        db.contains_account.return_value = False
        main.add_account_cmd(db, {})
        db.add_account.not_called()

    @mock.patch('pypass.main.password_input')
    @mock.patch('pypass.main.read_input')
    def test_cmd_add_account_timeout_password(self, mock_read_input: Mock, mock_password_input: Mock):
        mock_read_input.side_effect = ['test_account', 'test_user']
        mock_password_input.side_effect = TimeoutError()
        db = Mock()
        db.contains_account.return_value = False
        main.add_account_cmd(db, {})
        db.add_account.not_called()

    @mock.patch('pypass.main.read_input')
    def test_cmd_modify_account_dne(self, mock_read_input):
        mock_read_input.return_value = 'test_account'
        db = Mock()
        db.contains_account.return_value = False
        main.modify_account_cmd(db, {})
        db.modify_account.assert_not_called()

    @mock.patch('pypass.main.console_input')
    @mock.patch('pypass.main.read_input')
    def test_cmd_modify_account_account_id(self, mock_read_input: Mock, mock_console_input: Mock):
        mock_read_input.side_effect = ['test_account', 'test_account_id']
        mock_console_input.return_value = '1'
        db = Mock()
        db.contains_account.return_value = True
        main.modify_account_cmd(db, {})
        db.modify_account.assert_called_once()
        account, new_account_id, user, password = db.modify_account.call_args[0]
        self.assertEqual(account, 'test_account')
        self.assertEqual(new_account_id, 'test_account_id')
        self.assertEqual(user, None)
        self.assertEqual(password, None)

    @mock.patch('pypass.main.console_input')
    @mock.patch('pypass.main.read_input')
    def test_cmd_modify_account_user_id(self, mock_read_input: Mock, mock_console_input: Mock):
        mock_read_input.side_effect = ['test_account', 'test_user_id']
        mock_console_input.return_value = '2'
        db = Mock()
        db.contains_account.return_value = True
        main.modify_account_cmd(db, {})
        db.modify_account.assert_called_once()
        account, new_account_id, user, password = db.modify_account.call_args[0]
        self.assertEqual(account, 'test_account')
        self.assertEqual(new_account_id, None)
        self.assertEqual(user, 'test_user_id')
        self.assertEqual(password, None)

    @mock.patch('pypass.main.read_input')
    def test_cmd_modify_account_timeout_account_id(self, mock_read_input: Mock):
        mock_read_input.side_effect = TimeoutError()
        db = Mock()
        db.contains_account.return_value = True
        main.modify_account_cmd(db, {})
        db.modify_account.assert_not_called()

    @mock.patch('pypass.main.read_input')
    @mock.patch('pypass.main.console_input')
    def test_cmd_modify_account_timeout_choice(self, mock_console_input: Mock, mock_read_input: Mock):
        mock_read_input.return_value = 'test_account'
        mock_console_input.side_effect = TimeoutError()
        db = Mock()
        db.contains_account.return_value = True
        main.modify_account_cmd(db, {})
        db.modify_account.assert_not_called()

    @mock.patch('pypass.main.read_input')
    @mock.patch('pypass.main.console_input')
    def test_cmd_modify_account_timeout_attribute(self, mock_console_input: Mock, mock_read_input: Mock):
        mock_read_input.side_effect = ['test_account', TimeoutError()]
        mock_console_input.return_value = '1'
        db = Mock()
        db.contains_account.return_value = True
        main.modify_account_cmd(db, {})
        db.modify_account.assert_not_called()

    @mock.patch('pypass.main.password_input')
    @mock.patch('pypass.main.read_input')
    @mock.patch('pypass.main.console_input')
    def test_cmd_modify_account_timeout_password(self, mock_console_input: Mock, mock_read_input: Mock, mock_password_input: Mock):
        mock_read_input.return_value = 'test_account'
        mock_console_input.return_value = '3'
        mock_password_input.side_effect = TimeoutError()
        db = Mock()
        db.contains_account.return_value = True
        main.modify_account_cmd(db, {})
        db.modify_account.assert_not_called()

    @mock.patch('pypass.main.console_input')
    @mock.patch('pypass.main.read_input')
    def test_cmd_modify_account_invalid_choice(self, mock_read_input: Mock, mock_console_input: Mock):
        mock_read_input.return_value = 'test_account'
        mock_console_input.return_value = '4'
        db = Mock()
        db.contains_account.return_value = True
        main.modify_account_cmd(db, {})
        db.modify_account.assert_called_once()
        account, new_account_id, user, password = db.modify_account.call_args[0]
        self.assertEqual(account, 'test_account')
        self.assertEqual(new_account_id, None)
        self.assertEqual(user, None)
        self.assertEqual(password, None)

    @mock.patch('pypass.main.console_input')
    @mock.patch('pypass.main.read_input')
    def test_cmd_modify_account_randomize_password(self, mock_read_input, mock_console_input):
        mock_read_input.return_value = 'test_account'
        mock_console_input.side_effect = ['3', '1']
        db = Mock()
        db.contains_account.return_value = True
        main.modify_account_cmd(db, {})
        db.modify_account.assert_called_once()
        account, new_account_id, user, password = db.modify_account.call_args[0]
        self.assertEqual(account, 'test_account')
        self.assertEqual(new_account_id, None)
        self.assertEqual(user, None)
        self.assertEqual(len(password), main.DEFAULT_PASSWORD_LENGTH)

    @mock.patch('pypass.main.confirm_input')
    @mock.patch('pypass.main.console_input')
    @mock.patch('pypass.main.read_input')
    def test_cmd_modify_account_manual_password(self, mock_read_input, mock_console_input, mock_confirm_input):
        mock_read_input.return_value = 'test_account'
        mock_console_input.side_effect = ['3', '2']
        mock_confirm_input.return_value = 'test_password'
        db = Mock()
        db.contains_account.return_value = True
        main.modify_account_cmd(db, {})
        db.modify_account.assert_called_once()
        account, new_account_id, user, password = db.modify_account.call_args[0]
        self.assertEqual(account, 'test_account')
        self.assertEqual(new_account_id, None)
        self.assertEqual(user, None)
        self.assertEqual(password, 'test_password')

    @mock.patch('pypass.main.console_input')
    @mock.patch('pypass.main.read_input')
    def test_cmd_modify_account_timeout_password(self, mock_read_input, mock_console_input):
        mock_read_input.return_value = 'test_account'
        mock_console_input.side_effect = ['3', TimeoutError()]
        db = Mock()
        db.contains_account.return_value = True
        main.modify_account_cmd(db, {})
        db.modify_account.assert_not_called()

    @mock.patch('pypass.main.console_input')
    @mock.patch('pypass.main.read_input')
    def test_cmd_modify_account_password_invalid_choice(self, mock_read_input: Mock, mock_console_input: Mock):
        mock_read_input.return_value = 'test_account'
        mock_console_input.side_effect = ['3', '3']
        db = Mock()
        db.contains_account.return_value = True
        main.modify_account_cmd(db, {})
        db.modify_account.assert_called_once()
        account, new_account_id, user, password = db.modify_account.call_args[0]
        self.assertEqual(account, 'test_account')
        self.assertEqual(new_account_id, None)
        self.assertEqual(user, None)
        self.assertEqual(password, None)

    @mock.patch('pypass.main.confirm_input')
    def test_cmd_delete_account_dne(self, mock_confirm_input, *args):
        mock_confirm_input.return_value = 'test_account'
        db = Mock()
        db.contains_account.return_value = False
        main.delete_account_cmd(db, {})
        db.delete_account.assert_not_called()

    @mock.patch('pypass.main.confirm_input')
    def test_cmd_delete_account_exists(self, mock_confirm_input):
        mock_confirm_input.return_value = 'test_account'
        db = Mock()
        db.contains_account.return_value = True
        main.delete_account_cmd(db, {})
        db.remove_account.assert_called_once()

    @mock.patch('pypass.main.confirm_input')
    def test_cmd_delete_account_timeout(self, mock_confirm_input):
        mock_confirm_input.side_effect = TimeoutError()
        db = Mock()
        db.contains_account.return_value = True
        main.delete_account_cmd(db, {})
        db.remove_account.assert_not_called()

    @mock.patch('pypass.main.sys')
    @mock.patch('pypass.main.console_input')
    def test_cmd_quit_cancel_with_unsaved_changes(self, mock_console_input: Mock, mock_sys: Mock):
        mock_console_input.return_value = 'n'
        db = Mock()
        db.is_modified.return_value = True
        main.quit_cmd(db, {})
        mock_sys.exit.assert_not_called()

    @mock.patch('pypass.main.sys')
    @mock.patch('pypass.main.console_input')
    def test_cmd_quit_exit_with_unsaved_changes(self, mock_console_input: Mock, mock_sys: Mock):
        mock_console_input.return_value = 'y'
        db = Mock()
        db.is_modified.return_value = True
        main.quit_cmd(db, {})
        mock_sys.exit.assert_called_with(0)

    @mock.patch('pypass.main.sys')
    @mock.patch('pypass.main.console_input')
    def test_cmd_quit_timeout_with_unsaved_changes(self, mock_console_input: Mock, mock_sys: Mock):
        mock_console_input.side_effect = TimeoutError()
        db = Mock()
        db.is_modified.return_value = True
        main.quit_cmd(db, {})
        mock_sys.exit.assert_called_with(0)

    @mock.patch('pypass.main.read_input')
    def test_cmd_search(self, mock_read_input: Mock):
        db = Mock()
        db.search.return_value = []
        mock_read_input.return_value = 'test_account'
        main.search_accounts_cmd(db, {})
        db.search.assert_called_once()

    @mock.patch('pypass.main.read_input')
    def test_cmd_search_timeout(self, mock_read_input: Mock):
        db = Mock()
        mock_read_input.side_effect = TimeoutError()
        main.search_accounts_cmd(db, {})
        db.search.assert_not_called()


if __name__ == '__main__':
    unittest.main()
