import sys
import os
# Adjust the path so that mod_report can be imported
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import MagicMock, patch, mock_open
import json
from mod_report.mod_report import process_profile_traffic, generate_profile_report_html

@pytest.fixture
def mock_redis_client():
    mock_client = MagicMock()
    return mock_client


# Test case for verifying the processing of profile traffic works as expected
def test_process_profile_traffic(mock_redis_client):
    profile_name = "test_profile"
    PATH = "/test/path"

    with patch("mod_report.mod_report.os.chdir"), patch(
        "mod_report.mod_report.glob.glob", return_value=["test.pcap"]
    ), patch(
        "mod_report.mod_report.os.stat", return_value=MagicMock(st_size=100)
    ), patch(
        "mod_report.mod_report.subprocess.Popen"
    ) as mock_popen:
        mock_popen.return_value.wait.return_value = 0
        valid_capture, slips_result = process_profile_traffic(
            profile_name, PATH, mock_redis_client
        )

        assert valid_capture == True

# Test case for verifying small file handling in the profile traffic processing
def test_process_profile_traffic_ignores_small_files(mock_redis_client):
    profile_name = "empty_profile"
    PATH = "/empty/test/path"

    with patch("mod_report.mod_report.os.chdir"), patch(
        "mod_report.mod_report.glob.glob", return_value=["empty.pcap"]
    ), patch("mod_report.mod_report.os.stat", return_value=MagicMock(st_size=0)), patch(
        "mod_report.mod_report.subprocess.Popen"
    ) as mock_popen:

        mock_popen.return_value.wait.return_value = 0
        valid_capture, slips_result = process_profile_traffic(
            profile_name, PATH, mock_redis_client
        )

        assert (
            valid_capture == False
        ), "Expected valid_capture to be False for an empty pcap file"
        assert (
            slips_result == False
        ), "Expected slips_result to be False for an empty pcap file"

# Tests for the report generation functionality with detailed data mocking
@patch("mod_report.mod_report.pdfkit.from_file", return_value=True)
@patch("mod_report.mod_report.jinja2.Environment.get_template")
@patch("mod_report.mod_report.json.load")
@patch("mod_report.mod_report.glob.glob", return_value=["20test.pcap"])
@patch("mod_report.mod_report.os.chdir")
def test_generate_profile_report_html(
    mock_chdir, mock_glob, mock_json_load, mock_get_template, mock_pdfkit
):
    mock_template = MagicMock()
    mock_template.render.return_value = "rendered content"
    mock_get_template.return_value = mock_template

    # Mock the json.load to return the structured data expected by your function
    mock_json_load.return_value = {
        "capinfos": {
            "Capture duration (seconds)": 3600,
            "Number of packets": 1000,
            "File size (bytes)": 1000000,
        },
        "zeek": {"connections": 10, "dns": 5, "dns_blocked": 1, "ssl": 3, "http": 2},
        "top_uploads": [
            {
                "Source-Destination": "1.1.1.1 2.2.2.2",
                "Total Upload": 500,
                "Total Transferred": 1000,
                "Duration": 60,
            }
        ],
        "top_dns": [{"_source": {"layers": {"dns.qry.name": ["example.com"]}}}],
    }

    # Mock open function for reading JSON files
    mock_open_func = mock_open(read_data=json.dumps(mock_json_load.return_value))
    with patch("builtins.open", mock_open_func):
        profile_name = "test_profile"
        PATH = "/test/path"
        SLIPS_STATUS = True

        from mod_report.mod_report import generate_profile_report_html

        result = generate_profile_report_html(profile_name, PATH, SLIPS_STATUS)

        assert result is True, "Expected generate_profile_report_html to return True"


@patch("mod_report.mod_report.pdfkit.from_file", return_value=True)
@patch("mod_report.mod_report.jinja2.Environment.get_template")
@patch("mod_report.mod_report.json.load", autospec=True)
@patch("mod_report.mod_report.glob.glob", return_value=["20test.pcap"])
@patch("mod_report.mod_report.os.chdir")
def test_generate_profile_report_html_detailed(
    mock_chdir, mock_glob, mock_json_load, mock_get_template, mock_pdfkit
):
    mock_template = MagicMock()
    mock_template.render.return_value = "rendered content"
    mock_get_template.return_value = mock_template

    mock_json_data = {
        "capinfos": {
            "Capture duration (seconds)": 3600,
            "Number of packets": 1000,
            "File size (bytes)": 1000000,
        },
        "zeek": {"connections": 10, "dns": 5, "dns_blocked": 1, "ssl": 3, "http": 2},
        "top_uploads": [
            {
                "Source-Destination": "1.1.1.1 2.2.2.2",
                "Total Upload": 500,
                "Total Transferred": 1000,
                "Duration": 60,
            }
        ],
        "top_dns": [{"_source": {"layers": {"dns.qry.name": ["example.com"]}}}],
    }
    mock_json_load.return_value = mock_json_data

    profile_name = "test_profile"
    PATH = "/test/path"
    SLIPS_STATUS = True

    with patch("builtins.open", mock_open(read_data=json.dumps(mock_json_data))):
        result = generate_profile_report_html(profile_name, PATH, SLIPS_STATUS)

        expected_session_data = {
            "hours": 1.0,
            "connections": 10,
            "packets": 1000,
            "data": 0.001,
            "dns": 5,
            "trackers": 1,
            "encrypted": 3,
            "insecure": 2,
            "ASN0": "Unknown",
            "uploaded0": 500,
            "transferredtotal0": 1000,
            "duration0": 60,
            "ASN1": "-",
            "uploaded1": "-",
            "transferredtotal1": "-",
            "duration1": "-",
            "ASN2": "-",
            "uploaded2": "-",
            "transferredtotal2": "-",
            "duration2": "-",
            "ASN3": "-",
            "uploaded3": "-",
            "transferredtotal3": "-",
            "duration3": "-",
            "ASN4": "-",
            "uploaded4": "-",
            "transferredtotal4": "-",
            "duration4": "-",
            "dns0": "1 example[.]com",
            "dns1": "-",
            "dns2": "-",
            "dns3": "-",
            "dns4": "-",
            "dns5": "-",
            "dns6": "-",
            "dns7": "-",
            "dns8": "-",
            "dns9": "-",
            "dns10": "-",
            "dns11": "-",
            "dns12": "-",
            "dns13": "-",
            "dns14": "-",
            "dns15": "-",
            "dns16": "-",
            "dns17": "-",
            "dns18": "-",
            "dns19": "-",
            "dns20": "-",
            "dns21": "-",
            "dns22": "-",
            "dns23": "-",
            "dns24": "-",
            "dns25": "-",
            "dns26": "-",
            "dns27": "-",
            "dns28": "-",
        }

        mock_template.render.assert_called_once_with(expected_session_data)

        # Verify PDF generation was called with correct arguments
        # Assuming `pdfkit.from_file` is correctly mocked, this check ensures it's called once with expected arguments.
        mock_pdfkit.assert_called_once_with(
            f"{profile_name}.html",
            f"{profile_name}.pdf",
            css=["/code/template/nicepage.css", "/code/template/report-template.css"],
            options={"page-size": "A4", "dpi": 96},
        )

        assert (
            result is True
        ), "Expected generate_profile_report_html to successfully generate the report"
