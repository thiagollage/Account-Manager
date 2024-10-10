import unittest
from AccountManager import DatabaseManager

class TestDatabaseManager(unittest.TestCase):
    def setUp(self):
        self.db = DatabaseManager(':memory:')

    def test_add_account(self):
        result = self.db.add_account('test@example.com', 'password123', 'Test account')
        self.assertTrue(result)

    def test_get_accounts(self):
        self.db.add_account('test@example.com', 'password123', 'Test account')
        accounts = self.db.get_accounts()
        self.assertEqual(len(accounts), 1)
        self.assertEqual(accounts[0][1], 'test@example.com')

if __name__ == '__main__':
    unittest.main()