#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Veronica Valeros
#         veronica.valeros@aic.fel.cvut.cz

"""
Communication module of the AI VPN. Receives VPN requests from users via
email and Telegram, and sends profiles, reports and notifications back.
"""

import sys
import re
import time
import imaplib
import logging
import threading
import configparser
from email.parser import BytesFeedParser
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.encoders import encode_base64
from smtplib import SMTP_SSL, SMTP_SSL_PORT
import redis
import requests
from common.database import add_item_provisioning_queue
from common.database import get_identity_type
from common.database import get_profile_name_address
from common.database import get_profile_vpn_type
from common.database import redis_connect_to_db
from common.database import redis_create_subscriber
from common.database import redis_subscribe_to_channel


# Read configuration file
config = configparser.ConfigParser()
config.read('config/config.ini')

REDIS_SERVER = config['REDIS']['REDIS_SERVER']
CHANNEL = config['REDIS']['REDIS_COMM_CHECK']
LOG_FILE = config['LOGS']['LOG_COMM']
IMAP_SERVER = config['IMAP']['SERVER']
IMAP_USERNAME = config['IMAP']['USERNAME']
IMAP_PASSWORD = config['IMAP']['PASSWORD']
T_BOT_TOKEN = config['TELEGRAM']['TELEGRAM_BOT_TOKEN']
T_START_MSG = config['TELEGRAM']['TELEGRAM_START_MSG']
T_WAIT_MSG = config['TELEGRAM']['TELEGRAM_WAIT_MSG']

# Telegram Bot API, used directly over HTTPS
T_API_URL = f'https://api.telegram.org/bot{T_BOT_TOKEN}'
T_POLL_TIMEOUT = 50
T_RETRY_DELAY = 30
T_COMMANDS = {'getopenvpn': 'openvpn',
              'getwireguard': 'wireguard',
              'getnoencryptedvpn': 'novpn'}

# Initialize logging
logging.basicConfig(filename=LOG_FILE,
                    encoding='utf-8',
                    level=logging.DEBUG,
                    format='%(asctime)s, MOD_COMM, %(message)s')

# urllib3 logs request URLs at DEBUG level, and Telegram URLs contain the
# bot token
logging.getLogger('urllib3').setLevel(logging.WARNING)

# Create a module-level logger
logger = logging.getLogger(__name__)

REDIS_CLIENT = None


def send_request_to_redis(msg_id, msg_addr, msg_type, msg_request):
    """
    This function writes a new AI-VPN request to Redis.
    This is the first step to get a new account provisioned.
    """
    try:
        logger.info('Sending request to Redis: %s, %s, %s, %s',
                    msg_request,
                    msg_id,
                    msg_addr,
                    msg_type)
        add_item_provisioning_queue(REDIS_CLIENT, msg_id, msg_type, msg_addr, msg_request)
        return True
    except Exception as loc_err:
        logger.info('Exception in send_request_to_redis: %s', loc_err)
        return False


# TELEGRAM
## Telegram is used through its HTTP Bot API instead of a client library.
## The Bot API is backwards compatible, client libraries are not.

def redact(text):
    """ Removes the Telegram bot token from a text before logging it. """
    if T_BOT_TOKEN:
        return str(text).replace(T_BOT_TOKEN, '<token>')
    return str(text)


def telegram_api(method, params=None, files=None, timeout=30):
    """
    Calls a Telegram Bot API method and returns its result.
    Raises an exception if the call fails.
    """
    response = requests.post(f'{T_API_URL}/{method}',
                             data=params,
                             files=files,
                             timeout=timeout)
    reply = response.json()
    if not reply.get('ok'):
        raise RuntimeError(f"Telegram {method} failed: "
                           f"{reply.get('error_code')} {reply.get('description')}")
    return reply['result']


def telegram_parse_command(text, bot_username):
    """
    Returns the command of a message ('/getopenvpn@bot' -> 'getopenvpn'),
    or None if the message is not a command for this bot.
    """
    if not text or not text.startswith('/'):
        return None
    words = text[1:].split()
    if not words:
        return None
    command, _, target = words[0].partition('@')
    if target and target.lower() != bot_username.lower():
        return None
    return command.lower()


def telegram_handle_update(update, bot_username):
    """
    Telegram handler to welcome new users and process users' requests
    """
    message = update.get('message')
    if not message:
        return
    chat_id = message['chat']['id']
    command = telegram_parse_command(message.get('text'), bot_username)

    if command == 'start':
        telegram_api('sendMessage', {'chat_id': chat_id, 'text': T_START_MSG})
        logger.info('New Telegram chat received from: %s', chat_id)
    elif command in T_COMMANDS:
        msg_request = T_COMMANDS[command]
        logger.info("New Telegram request: %s (%s)", msg_request, chat_id)

        # Write pending account to provision in REDIS
        send_request_to_redis(int(chat_id), chat_id, 'telegram', msg_request)

        # Notify manager of new request
        REDIS_CLIENT.publish('services_status', 'MOD_COMM:NEW_REQUEST')

        telegram_api('sendMessage', {'chat_id': chat_id, 'text': T_WAIT_MSG})


def telegram_poll_requests():
    """
    Receives VPN requests from Telegram using long polling. Runs forever.
    """
    offset = None
    bot_username = None
    while True:
        try:
            if bot_username is None:
                bot_username = telegram_api('getMe')['username']
                logger.info('Telegram bot initialized: %s', bot_username)

            updates = telegram_api('getUpdates',
                                   {'offset': offset,
                                    'timeout': T_POLL_TIMEOUT,
                                    'allowed_updates': '["message"]'},
                                   timeout=T_POLL_TIMEOUT + 10)
            for update in updates:
                # Confirm the update even if it fails, so a bad message is
                # not processed again and again
                offset = update['update_id'] + 1
                try:
                    telegram_handle_update(update, bot_username)
                except Exception as loc_err:
                    logger.error('Error processing Telegram update %s: %s',
                                 update['update_id'], redact(loc_err))
        except Exception as loc_err:
            logger.error('Telegram polling error: %s', redact(loc_err))
            time.sleep(T_RETRY_DELAY)


def send_message_via_telegram(msg_task, profile_name, msg_addr, msg_vpn_type, config):
    """ Function to send a message to the user via Telegram. """
    try:
        # Load configuration
        PATH = config.get('STORAGE', 'PATH')
        MSG_BODY = None
        MSG_ATTACHMENTS = []

        logger.info('Sending %s, %s to %s', msg_task, profile_name, msg_addr)

        # Different bodies based on the message type
        if 'send_vpn_profile' in msg_task:
            MSG_BODY = config.get('AIVPN', 'MESSAGE_NEW_PROFILE')
            if 'openvpn' in msg_vpn_type:
                MSG_ATTACHMENTS = [f'{PATH}/{profile_name}/{profile_name}.ovpn']
            elif 'novpn' in msg_vpn_type:
                MSG_ATTACHMENTS = [f'{PATH}/{profile_name}/{profile_name}.ovpn']
            elif 'wireguard' in msg_vpn_type:
                MSG_ATTACHMENTS = [f'{PATH}/{profile_name}/{profile_name}.conf',
                                   f'{PATH}/{profile_name}/{profile_name}.png']

        if 'send_report_profile' in msg_task:
            MSG_BODY = f"Profile: {profile_name}\r\n"
            MSG_BODY += config.get('AIVPN', 'MESSAGE_REPORT')
            MSG_ATTACHMENTS = [f'{PATH}/{profile_name}/{profile_name}.pdf']

        if 'send_expire_profile' in msg_task:
            MSG_BODY = f"Profile: {profile_name}\r\n"
            MSG_BODY += config.get('AIVPN', 'MESSAGE_EXPIRED_PROFILE')

        if 'send_empty_capture' in msg_task:
            MSG_BODY = f"Profile: {profile_name}\r\n"
            MSG_BODY += config.get('AIVPN', 'MESSAGE_REPORT_EMPTY')

        if 'error_limit_reached' in msg_task:
            MSG_BODY = config.get('AIVPN', 'MESSAGE_MAX_LIMIT')

        if 'error_max_capacity' in msg_task:
            MSG_BODY = config.get('AIVPN', 'MESSAGE_FULL_CAPACITY')

        if MSG_BODY is None:
            logger.info('Unknown Telegram task: %s', msg_task)
            return False

        telegram_api('sendMessage', {'chat_id': msg_addr, 'text': MSG_BODY})
        for attachment in MSG_ATTACHMENTS:
            with open(attachment, 'rb') as file_attachment:
                telegram_api('sendDocument',
                             {'chat_id': msg_addr},
                             files={'document': file_attachment},
                             timeout=120)
        return True
    except Exception as err:
        logger.info('Exception in send_message_via_telegram: %s', redact(err))
        return False


# EMAIL

def get_unread_emails(mailbox='Inbox'):
    """
    Fetches unread email UIDs and messages from the specified mailbox.

    :param mailbox: The mailbox to fetch from. Defaults to 'Inbox'.
    :return: Generator of (email UID, message data) tuples.
    """

    try:
        # Establish a secure IMAP connection
        imap_connection = imaplib.IMAP4_SSL(IMAP_SERVER)
        imap_connection.login(IMAP_USERNAME, IMAP_PASSWORD)

        logger.info("IMAP connection successful")

        # Select mailbox
        imap_connection.select(mailbox, readonly=False)

        # Search for all UNSEEN emails
        status, data = imap_connection.uid('search', None, 'UNSEEN')
        if status != 'OK':
            logger.error("No emails found.")
            return

        # Process unread emails
        for msg_id in data[0].split():
            # Fetch the email message by UID
            msg_type, msg_data = imap_connection.uid('fetch', msg_id, '(RFC822)')
            if msg_type != 'OK':
                logger.error("Failed to fetch email UID %s", msg_id)
                continue
            yield msg_id, msg_data[0][1]
    except imaplib.IMAP4.error as loc_err:
        logger.exception("IMAP4 error occurred: %s", loc_err)
    finally:
        # Ensure the connection is closed
        try:
            imap_connection.close()
            imap_connection.logout()
        except Exception as loc_err:
            logger.exception("IMAP connection failed to properly close: %s", loc_err)


def process_new_request(email_msg):
    """
    This function parses new email messages to extract headers and body content,
    ignoring replies and messages where the recipient is not the intended receiver.
    It searches the subject and body of the email for specific VPN-related keywords
    to identify new VPN requests.

    If a new VPN request is found, it is sent to a Redis queue for further processing.
    If no new request is identified, no action is taken.

    Returns:
        bool: True if the process completes successfully, False otherwise.
    """
    patterns = ["NOENCRYPTEDVPN", "WIREGUARD", "VPN"]
    keyword_match = False

    logger.info("Starting process_new_request")
    # Parse email to extract header and body
    try:
        email_parser = BytesFeedParser()
        email_parser.feed(email_msg)  # Feed the raw email bytes to the parser
        email_msg_parsed = email_parser.close()  # Finalize parsing and get the message object
    except TypeError as loc_err:
        logger.info("TypeError: %s", loc_err)
        email_msg_parsed = None
        return False
    except IndexError as loc_err:
        logger.info("IndexError: %s", loc_err)
        email_msg_parsed = None
        return False
    except Exception as loc_err:
        logger.info("General exception: %s", loc_err)

    # Do not process answers
    if email_msg_parsed['In-Reply-To'] is not None:
        return False

    # Do not process messages where we are not the receivers
    email_field_to = re.search(r'[\w\.-]+@[\w\.-]+', email_msg_parsed['to']).group(0)
    if email_field_to != IMAP_USERNAME:
        return False

    # Do not process messages whose subject is None
    if email_msg_parsed['subject'] is None:
        return False

    # Extract Email subject
    email_field_subject = email_msg_parsed['subject']
    # Extract Email body
    try:
        email_field_body = email_msg_parsed.get_payload().pop().get_payload()
    except (IndexError, AttributeError, TypeError) as loc_err:
        logger.info("Exception parsing body: %s", loc_err)
        email_field_body = None

    for pattern in patterns:
        try:
            # Search for VPN request in email subject
            keyword_match = re.search(pattern, email_field_subject, re.IGNORECASE)
            if keyword_match:
                break
        except re.error as loc_err:
            logger.info("Regex error: %s", loc_err)
        except TypeError as loc_err:
            logger.info("Type error: %s", loc_err)

        try:
            # Search for VPN request in email body
            keyword_match = re.search(pattern, email_field_body, re.IGNORECASE)
            if keyword_match:
                break
        except re.error as loc_err:
            logger.info("Regex error: %s", loc_err)
        except TypeError as loc_err:
            logger.info("Type error: %s", loc_err)

    if not keyword_match:
        return False

    if keyword_match.group(0).upper() == "NOENCRYPTEDVPN":
        email_request = "novpn"
    elif keyword_match.group(0).upper() == "WIREGUARD":
        email_request = "wireguard"
    elif keyword_match.group(0).upper() == "VPN":
        email_request = "openvpn"
    else:
        return False
    logger.info("Found keyword in email: %s (%s)", keyword_match, email_request)

    try:
        # Extract fields to send info to redis
        email_field_from = re.search(r'[\w\.-]+@[\w\.-]+', email_msg_parsed['from']).group(0)
    except re.error as loc_err:
        logger.info("Regex error: %s", loc_err)
        return False
    except TypeError as loc_err:
        logger.info("Type error: %s", loc_err)
        return False

    # Return the sender of the email and keyword
    return [email_field_from, email_request]


def check_email_requests():
    """
    Processes all unread emails and queues the VPN requests found.
    """
    for uid, new_message in get_unread_emails():
        logger.info("New email with UID: %s", uid)
        try:
            process_result = process_new_request(new_message)
        except Exception as loc_err:
            # A malformed email must not stop the processing of the others
            logger.error("Unable to process email UID %s: %s", uid, loc_err)
            continue

        if process_result is not False:
            # send request to redis
            send_request_to_redis(uid,                  # email_field_uid
                                  process_result[0],    # email_field_from
                                  "email",              # message_type
                                  process_result[1])    # keyword_match
            REDIS_CLIENT.publish('services_status', 'MOD_COMM:NEW_REQUEST')
            logger.info("New request send to redis from %s (%s)",
                        process_result[0],  # email_field_from
                        process_result[1])  # keyword_match


def send_mime_msg_via_email(msg_task, profile_name, msg_addr, msg_vpn_type, config):
    """ Function to send a MIME message to the user via email. """
    try:
        # Load general configuration
        EMAIL_SERVER = config.get('IMAP', 'SERVER')
        EMAIL_USER = config.get('IMAP', 'USERNAME')
        EMAIL_PASSWORD = config.get('IMAP', 'PASSWORD')
        EMAIL_SUBJ_PREFIX = config.get('AIVPN', 'MESSAGE_SUBJECT_PREFIX')
        PATH = config.get('STORAGE', 'PATH')
        EMAIL_ATTACHMENT = ""

        # Create message
        email_message = MIMEMultipart()
        email_message.add_header('From', EMAIL_USER)
        email_message.add_header('To', msg_addr)

        # Different bodies based on the message type
        if 'send_vpn_profile' in msg_task:
            EMAIL_BODY = config.get('AIVPN', 'MESSAGE_NEW_PROFILE')
            if 'wireguard' in msg_vpn_type:
                EMAIL_ATTACHMENT = f'{PATH}/{profile_name}/{profile_name}.conf'
                EMAIL_FILENAME = f'{profile_name}.conf'
            else:
                EMAIL_ATTACHMENT = f'{PATH}/{profile_name}/{profile_name}.ovpn'
                EMAIL_FILENAME = f'{profile_name}.ovpn'
            email_message.add_header('Subject', f"{EMAIL_SUBJ_PREFIX} VPN Profile Active: {profile_name}\r\n")

        if 'send_report_profile' in msg_task:
            EMAIL_BODY = config.get('AIVPN', 'MESSAGE_REPORT')
            EMAIL_ATTACHMENT = f'{PATH}/{profile_name}/{profile_name}.pdf'
            EMAIL_FILENAME = f'{profile_name}.pdf'
            email_message.add_header('Subject', f"{EMAIL_SUBJ_PREFIX} VPN Profile Report: {profile_name}\r\n")

        if 'send_expire_profile' in msg_task:
            EMAIL_BODY = config.get('AIVPN', 'MESSAGE_EXPIRED_PROFILE')
            email_message.add_header('Subject', f"{EMAIL_SUBJ_PREFIX} VPN Profile Expired: {profile_name}\r\n")

        if 'send_empty_capture' in msg_task:
            EMAIL_BODY = config.get('AIVPN', 'MESSAGE_REPORT_EMPTY')
            email_message.add_header('Subject', f"{EMAIL_SUBJ_PREFIX} VPN Profile Report: {profile_name}\r\n")

        # Create text and HTML bodies for email
        email_body_text = MIMEText(EMAIL_BODY, 'plain')

        # Attach all the parts to the Multipart MIME email
        email_message.attach(email_body_text)

        # Create file attachment
        if EMAIL_ATTACHMENT != "":
            attachment = MIMEBase("application", "octet-stream")
            attachment.set_payload(open(EMAIL_ATTACHMENT, "rb").read())
            encode_base64(attachment)
            attachment.add_header("Content-Disposition", f"attachment; filename={EMAIL_FILENAME}")
            email_message.attach(attachment)

        # Connect, authenticate, and send mail
        smtp_server = SMTP_SSL(EMAIL_SERVER, port=SMTP_SSL_PORT)
        smtp_server.set_debuglevel(1)  # Show SMTP server interactions
        smtp_server.login(EMAIL_USER, EMAIL_PASSWORD)
        smtp_server.sendmail(EMAIL_USER, msg_addr, email_message.as_bytes())

        # Disconnect
        smtp_server.quit()
        return True
    except Exception as err:
        logger.info('Exception in send_mime_msg_via_email: %s', err)
        return False


def send_plain_msg_via_email(msg_task, profile_name, msg_addr, config):
    """ Function to send a PLAIN message to the user via email. """
    try:
        # Load general configuration
        EMAIL_SERVER = config.get('IMAP', 'SERVER')
        EMAIL_USER = config.get('IMAP', 'USERNAME')
        EMAIL_PASSWORD = config.get('IMAP', 'PASSWORD')
        EMAIL_SUBJ_PREFIX = config.get('AIVPN', 'MESSAGE_SUBJECT_PREFIX')

        # Create message headers
        headers = f"From: {EMAIL_USER}\r\n"
        headers += f"To: {msg_addr}\r\n"

        # Different content based on the message type
        if 'error_limit_reached' in msg_task:
            EMAIL_BODY = config.get('AIVPN', 'MESSAGE_MAX_LIMIT')
            headers += f"Subject: {EMAIL_SUBJ_PREFIX} Account Limit Reached\r\n"

        if 'error_max_capacity' in msg_task:
            EMAIL_BODY = config.get('AIVPN', 'MESSAGE_FULL_CAPACITY')
            headers += f"Subject: {EMAIL_SUBJ_PREFIX} Service at Full Capacity\r\n"

        # Create message
        email_message = headers + "\r\n" + EMAIL_BODY  # Blank line needed between headers and body

        # Connect, authenticate, and send mail
        smtp_server = SMTP_SSL(EMAIL_SERVER, port=SMTP_SSL_PORT)
        smtp_server.login(EMAIL_USER, EMAIL_PASSWORD)
        smtp_server.sendmail(EMAIL_USER, msg_addr, email_message)

        # Disconnect
        smtp_server.quit()
        return True
    except Exception as err:
        logger.info('Exception in send_plain_msg_via_email: %s', err)
        return False


def process_send_task(task):
    """
    Sends information back to a user. Tasks are '<msg_task>:<profile_name>'
    for profile messages and '<msg_task>:<msg_addr>' for error messages.
    """
    # Obtain the profile name and address where to send
    msg_task = task.split(':')[0]
    profile_name = ""
    msg_vpn_type = ""
    if msg_task.startswith('send_'):
        profile_name = task.split(':')[1]
        msg_addr = get_profile_name_address(profile_name, REDIS_CLIENT)
        msg_vpn_type = get_profile_vpn_type(profile_name, REDIS_CLIENT)
    elif msg_task.startswith('error_'):
        msg_addr = task.split(':')[1]
    else:
        logger.info("Unknown task: %s", task)
        return
    msg_type = get_identity_type(msg_addr, REDIS_CLIENT)

    logger.info("Processing task: %s (%s) to %s (%s, %s)",
                msg_task, msg_vpn_type, profile_name, msg_addr, msg_type)

    status = ""
    # We have different logic for different type of messages
    # (email, telegram, etc).
    if msg_type == 'telegram':
        status = send_message_via_telegram(msg_task, profile_name, msg_addr, msg_vpn_type, config)
    elif msg_type == 'email':
        # Messages with prefix 'error' require this module to send back
        # error messages to the user
        if msg_task.startswith('send_'):
            status = send_mime_msg_via_email(msg_task, profile_name, msg_addr, msg_vpn_type, config)
        else:
            status = send_plain_msg_via_email(msg_task, profile_name, msg_addr, config)

    logger.info("Processing task: %s is %s", msg_task, status)
    REDIS_CLIENT.publish('services_status', f"MOD_COMM:{task}_{status}")


if __name__ == '__main__':

    # Connecting to the Redis database
    try:
        # Connecting to the Redis database
        REDIS_CLIENT = redis_connect_to_db(REDIS_SERVER)
        db_subscriber = redis_create_subscriber(REDIS_CLIENT)
        redis_subscribe_to_channel(db_subscriber, CHANNEL)

        logger.info("Redis connection and subscription successful.")
    except redis.AuthenticationError as err:
        logger.error('Redis authentication error (%s): %s', REDIS_SERVER, err)
        sys.exit(-1)
    except redis.ConnectionError as err:
        logger.error('Redis connection error (%s): %s', REDIS_SERVER, err)
        sys.exit(-1)
    except redis.TimeoutError as err:
        logger.error('Redis timeout error (%s): %s', REDIS_SERVER, err)
        sys.exit(-1)

    # Starting Telegram bot to check for new messages
    if T_BOT_TOKEN:
        telegram_bot = threading.Thread(target=telegram_poll_requests, daemon=True)
        telegram_bot.start()
        logger.info("Telegram bot thread started")
    else:
        logger.info("Telegram bot token not configured, Telegram is disabled")

    try:
        for item in db_subscriber.listen():
            if item['type'] != 'message':
                continue
            logger.info("New message received in %s: %s", item['channel'], item['data'])

            if item['data'] == 'report_status':
                # Process all the new email requests
                try:
                    check_email_requests()
                    # Report service status to manager
                    REDIS_CLIENT.publish('services_status', 'MOD_COMM:online')
                except (imaplib.IMAP4.error, OSError) as err:
                    logger.error("Error checking email requests: %s", err)
                    REDIS_CLIENT.publish('services_status', 'MOD_COMM:error_checking_requests')
            else:
                # Messages from the manager and other modules that require
                # this module to send information back to the user
                try:
                    process_send_task(item['data'])
                except Exception as err:
                    # A malformed task must not stop the module
                    logger.error("Error processing task %s: %s", item['data'], err)

    except redis.ConnectionError as err:
        logger.info("Connection error: %s", err)
    except redis.TimeoutError as err:
        logger.info("Timeout error: %s", err)
    finally:
        logger.info("Terminating")
        db_subscriber.close()
        REDIS_CLIENT.close()
        sys.exit(-1)
