import unittest
from unittest.mock import MagicMock, patch
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from aivpn import *



class TestAIVPNCLI(unittest.TestCase):
    def setUp(self):
        # Setting up a mock Redis client for testing
        self.redis_client = MagicMock()

    def test_manage_info_active_profile(self):
        # Testing for an active profile
        profile_name = "example_profile"
        get_profile_vpn_type = MagicMock(return_value="OpenVPN")
        with patch('aivpn.get_profile_vpn_type', get_profile_vpn_type):
            manage_info(self.redis_client, profile_name)

    def test_manage_info_expired_profile(self):
        # Testing for an expired profile
        profile_name = "expired_profile"
        exists_active_profile = MagicMock(return_value=False)
        get_expired_profile_information = MagicMock(return_value='{"creation_time": 1616259000, "expiration_time": 1616259100, "reported_time": 1616259200, "deletion_time": 1616259300}')
        with patch('aivpn.exists_active_profile', exists_active_profile), \
             patch('aivpn.get_expired_profile_information', get_expired_profile_information):
            manage_info(self.redis_client, profile_name)

    def test_manage_expire(self):
        # Testing for expiring a profile
        profile_name = "example_profile"
        exists_active_profile = MagicMock(return_value=True)
        add_profile_to_force_expire = MagicMock(return_value="success")
        with patch('aivpn.exists_active_profile', exists_active_profile), \
             patch('aivpn.add_profile_to_force_expire', add_profile_to_force_expire):
            manage_expire(self.redis_client, profile_name)

    def test_get_validated_data_success_email(self):
        # Test successful validation of an email identity.
        identity = "test@example.com"
        
        # Act
        result = get_validated_data(identity)
        
        # Assert
        self.assertEqual(result["msg_type"], "email")
        self.assertEqual(result["msg_addr "], identity)
        self.assertEqual(result["msg_request"], ["openvpn", "wireguard", "novpn"])
        
    def test_get_validated_data_success_telegram(self):
        # Test successful validation of a telegram identity.
        identity = "12345678"  # Assuming a valid telegram ID
        
        # Act
        result = get_validated_data(identity)
        
        # Assert
        self.assertEqual(result["msg_type"], "telegram")
        self.assertEqual(result["msg_addr "], identity)
        self.assertEqual(result["msg_request"], ["openvpn", "wireguard", "novpn"])
        
    def test_get_validated_data_failure(self):
        # Test failure scenario when validating an invalid identity.
        invalid_identity = "invalid_identity"
        
        # Act
        result = get_validated_data(invalid_identity)
        
        # Assert
        self.assertIsInstance(result, dict)
        self.assertEqual(result["msg_type"], False)
        self.assertEqual(result["msg_addr "], invalid_identity)
        self.assertEqual(result["msg_request"], ["openvpn", "wireguard", "novpn"])    

    @patch('aivpn.get_active_profiles_keys')
    def test_audit_active_profiles(self, mock_get_active_profiles_keys):
        # Mocking the return value of get_active_profiles_keys
        mock_get_active_profiles_keys.return_value = ['profile1', 'profile2']

        with patch('builtins.print') as mock_print:
            audit_active_profiles(None, None)
            mock_print.assert_any_call('[+] Number of active profiles: 2')
            mock_print.assert_any_call('   [-] profile1')
            mock_print.assert_any_call('   [-] profile2')

    @patch('aivpn.get_expired_profiles_keys')
    def test_audit_expired_profiles(self, mock_get_expired_profiles_keys):
        # Mocking the return value of get_expired_profiles_keys
        mock_get_expired_profiles_keys.return_value = ['expired_profile1', 'expired_profile2']
        
        with patch('builtins.print') as mock_print:
            audit_expired_profiles(None, None)

            mock_print.assert_any_call('[+] Number of expired profiles: 2')
            mock_print.assert_any_call('   [-] expired_profile1')
            mock_print.assert_any_call('   [-] expired_profile2')

    @patch('aivpn.list_items_provisioning_queue')
    def test_audit_queued_profiles(self, mock_list_items_provisioning_queue):
        # Mocking the return value of list_items_provisioning_queue
        mock_list_items_provisioning_queue.return_value = 5

        with patch('builtins.print') as mock_print:
            audit_queued_profiles(None, None)
            mock_print.assert_any_call('[+] Number of queued profiles to provision: 5')        

if __name__ == '__main__':
    unittest.main()
