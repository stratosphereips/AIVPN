import unittest
from unittest.mock import MagicMock, patch
from mod_comm_send.mod_comm_send import send_mime_msg_via_email

class TestSendMimeMsgViaEmail(unittest.TestCase):

    @patch('mod_comm_send.SMTP_SSL')
    def test_send_mime_msg_via_email_success(self, mock_smtp_ssl):
        """Test sending a MIME message via email successfully."""
        msg_task = "send_vpn_profile"
        profile_name = "test_profile"
        msg_addr = "test@example.com"
        msg_vpn_type = "wireguard"
        config = {
            'IMAP': {'SERVER': 'test_server', 'USERNAME': 'test_user', 'PASSWORD': 'test_password'},
            'AIVPN': {'MESSAGE_SUBJECT_PREFIX': 'Test Subject', 'MESSAGE_NEW_PROFILE': 'Test Message'},
            'STORAGE': {'PATH': '/path/to/storage'}
        }

        # Act
        result = send_mime_msg_via_email(msg_task, profile_name, msg_addr, msg_vpn_type, config)

        # Assert
        self.assertTrue(result)
        mock_smtp_ssl.return_value.login.assert_called_once_with('test_user', 'test_password')
        mock_smtp_ssl.return_value.sendmail.assert_called_once()

    @patch('mod_comm_send.SMTP_SSL')
    def test_send_mime_msg_via_email_failure(self, mock_smtp_ssl):
        """Test failure scenario when sending a MIME message via email."""
        msg_task = "send_vpn_profile"
        profile_name = "test_profile"
        msg_addr = "test@example.com"
        msg_vpn_type = "wireguard"
        config = {
            'IMAP': {'SERVER': 'test_server', 'USERNAME': 'test_user', 'PASSWORD': 'test_password'},
            'AIVPN': {'MESSAGE_SUBJECT_PREFIX': 'Test Subject', 'MESSAGE_NEW_PROFILE': 'Test Message'},
            'STORAGE': {'PATH': '/path/to/storage'}
        }
        mock_smtp_ssl.side_effect = Exception("SMTP Error")

        # Act
        result = send_mime_msg_via_email(msg_task, profile_name, msg_addr, msg_vpn_type, config)

        # Assert
        self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()
