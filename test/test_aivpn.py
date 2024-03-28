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

if __name__ == '__main__':
    unittest.main()
