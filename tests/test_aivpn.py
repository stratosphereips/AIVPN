import sys
import os
# Add the root directory of the project to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from unittest.mock import patch, MagicMock
import aivpn
import logging


# Common fixture for setting up mock Redis client
@pytest.fixture
def mock_redis_client():
    return MagicMock()

@patch("aivpn.redis_connect_to_db")
@patch("aivpn.print")
def test_manage_whois(mock_print, mock_redis_connect_to_db, mock_redis_client):
    logging.info("Testing manage_whois...")
    profile_name = "test_profile"
    expected_identity = "test@example.com"
    mock_redis_client = mock_redis_connect_to_db.return_value
    mock_redis_client.hget.return_value = expected_identity

    aivpn.manage_whois(mock_redis_client, profile_name)

    mock_print.assert_called_once_with(f"[+] User identity for {profile_name} is {expected_identity}")

def test_validate_identity_email():
    logging.info("Testing validate_identity with a valid email...")
    identity = "test@example.com"
    result = aivpn.validate_identity(identity)
    assert result == "email"

def test_validate_identity_telegram():
    logging.info("Testing validate_identity with a valid Telegram ID...")
    identity = "123456789"
    result = aivpn.validate_identity(identity)
    assert result == "telegram"

def test_validate_identity_invalid():
    logging.info("Testing validate_identity with invalid input...")
    identity = "invalid_identity"
    result = aivpn.validate_identity(identity)
    assert not result
