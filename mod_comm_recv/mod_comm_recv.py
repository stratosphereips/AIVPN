#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Veronica Valeros
#         veronica.valeros@aic.fel.cvut.cz

import sys
import logging
import re
import imaplib
from functools import partial
import configparser
from email.parser import BytesFeedParser
import redis
from telegram.ext import ApplicationBuilder
from telegram.ext import CommandHandler
from common.database import add_item_provisioning_queue
from common.database import redis_connect_to_db
from common.database import redis_create_subscriber
from common.database import redis_subscribe_to_channel


# Global
global REDIS_CLIENT

# Read cofiguration file
config = configparser.ConfigParser()
config.read('config/config.ini')

REDIS_SERVER = config['REDIS']['REDIS_SERVER']
CHANNEL = config['REDIS']['REDIS_COMM_RECV_CHECK']
LOG_FILE = config['LOGS']['LOG_COMM_RECV']
IMAP_SERVER = config['IMAP']['SERVER']
IMAP_USERNAME = config['IMAP']['USERNAME']
IMAP_PASSWORD = config['IMAP']['PASSWORD']
T_BOT_TOKEN = config['TELEGRAM']['TELEGRAM_BOT_TOKEN']
T_START_MSG = config['TELEGRAM']['TELEGRAM_START_MSG']
T_WAIT_MSG = config['TELEGRAM']['TELEGRAM_WAIT_MSG']

# Initialize logging
logging.basicConfig(filename=LOG_FILE,
                    encoding='utf-8',
                    level=logging.DEBUG,
                    format='%(asctime)s, MOD_COMM_RECV, %(message)s')

# Create a module-level logger
logger = logging.getLogger(__name__)


def send_request_to_redis(msg_id, msg_addr, msg_type, msg_request):
    """
    This function writes a new AI-VPN request to Redis.
    This is the first step to get a new account provisioned.
    """
    try:
        logging.info('Sending request to Redis: %s, %s, %s, %s',
                     msg_request,
                     msg_id,
                     msg_addr,
                     msg_type)
        add_item_provisioning_queue(REDIS_CLIENT, msg_id, msg_type, msg_addr, msg_request)
        return True
    except Exception as loc_err:
        logging.info('Exception in send_request_to_redis: %s', loc_err)
        return False


# Telegram Handlers
async def telegram_cmd_start(update, context):
    """
    Telegram handle to welcome new users
    """

    await context.bot.send_message(chat_id=update.effective_chat.id, text=T_START_MSG)
    logging.info('New Telegram chat received from: %s', update.effective_chat.id)


async def telegram_cmd(msg_request, update, context):
    """
    Telegram handler to process users' requests
    """

    await context.bot.send_message(chat_id=update.effective_chat.id, text=T_WAIT_MSG)
    logging.info("New Telegram request: %s (%s)", msg_request, update.effective_chat.id)

    # Write pending account to provision in REDIS
    send_request_to_redis(int(update.effective_chat.id),
                          update.effective_chat.id,
                          'telegram',
                          msg_request)

    # Notify manager of new request
    REDIS_CLIENT.publish('services_status', 'MOD_COMM_RECV:NEW_REQUEST')


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
    application = ApplicationBuilder().token(T_BOT_TOKEN).build()
    logging.info('Telegram bot initialized')

    # Creating handlers per action
    start_handler = CommandHandler('start', telegram_cmd_start)
    application.add_handler(start_handler)

    openvpn_handler = CommandHandler('getopenvpn', partial(telegram_cmd, "openvpn"))
    wireguard_handler = CommandHandler('getwireguard', partial(telegram_cmd, "wireguard"))
    novpn_handler = CommandHandler('getnoencryptedvpn', partial(telegram_cmd, "novpn"))

    application.add_handler(openvpn_handler)
    application.add_handler(wireguard_handler)
    application.add_handler(novpn_handler)

    logging.info('Telegram handlers created')

    # Starting
    application.run_polling()

    try:
        for item in db_subscriber.listen():
            if item['type'] == 'message' and item['data'] == 'report_status':
                logger.info("New message received in %s: %s", item['channel'], item['data'])

                # Process all the new requests
                for uid, new_message in get_unread_emails():
                    logger.info("New email with UID: %s", uid)
                    process_result = process_new_request(new_message)

                    if process_result is not False:
                        # send request to redis
                        add_item_provisioning_queue(REDIS_CLIENT,
                                                    uid,  # email_field_uid
                                                    "email",  # message_type
                                                    process_result[0],  # email_field_from
                                                    process_result[1])  # keyword_match
                        REDIS_CLIENT.publish('services_status', 'MOD_COMM_RECV:NEW_REQUEST')
                        logger.info("New request send to redis from %s (%s)",
                                    process_result[0],  # email_field_from
                                    process_result[1])  # keyword_match

                    # Report service status to manager
                    REDIS_CLIENT.publish('services_status', 'MOD_COMM_RECV:online')

    except redis.ConnectionError as err:
        logger.info("Connection error: %s", err)
    except redis.TimeoutError as err:
        logger.info("Timeout error: %s", err)
    finally:
        logger.info("Terminating")
        db_subscriber.close()
        REDIS_CLIENT.close()
        sys.exit(-1)
