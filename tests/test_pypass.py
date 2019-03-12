import unittest
from pypass import pypass


class TestPypass(unittest.TestCase):

    def setUp(self):
        def do_nothing(*args, **kwargs):
            pass
        pypass.cls = do_nothing

    def test_function(self):
        self.assertEqual('foo'.upper(), 'FOO')

    def test_default_rand_pass_len(self):
        self.assertEqual(len(pypass.random_password()), 20)
        pypass.cls()


if __name__ == '__main__':
    unittest.main()
