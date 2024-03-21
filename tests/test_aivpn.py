import unittest
from unittest.mock import patch, MagicMock
import aivpn
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)


class TestAIVPN(unittest.TestCase):
    def setUp(self):
        # Setup common mock Redis client
        self.mock_redis_client = MagicMock()

    @patch("aivpn.redis_connect_to_db")
    @patch("aivpn.print")
    def test_manage_whois(self, mock_print, mock_redis_connect_to_db):
        logging.info("Testing manage_whois...")
        # Setup
        profile_name = "test_profile"
        expected_identity = "test@example.com"
        # Mock the Redis client method to return the expected identity
        mock_redis_client = mock_redis_connect_to_db.return_value
        mock_redis_client.hget.return_value = expected_identity

        # Call the function under test
        aivpn.manage_whois(mock_redis_client, profile_name)

        # Assert the expected print call was made
        mock_print.assert_called_once_with(
            f"[+] User identity for {profile_name} is {expected_identity}"
        )

    def test_validate_identity_email(self):
        """
        Test validate_identity with a valid email
        """
        logging.info("Testing validate_identity with a valid email...")
        identity = "test@example.com"
        result = aivpn.validate_identity(identity)
        self.assertEqual(result, "email")

    def test_validate_identity_telegram(self):
        """
        Test validate_identity with a valid Telegram ID
        """
        logging.info("Testing validate_identity with a valid Telegram ID...")
        identity = "123456789"
        result = aivpn.validate_identity(identity)
        self.assertEqual(result, "telegram")

    def test_validate_identity_invalid(self):
        """
        Test validate_identity with invalid input
        """
        logging.info("Testing validate_identity with invalid input...")
        identity = "invalid_identity"
        result = aivpn.validate_identity(identity)
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
