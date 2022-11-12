#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Veronica Valeros, vero.valeros@gmail.com, veronica.valeros@aic.fel.cvut.cz
from functools import partial
import sys
import logging
import re
import imaplib
import threading
from email.parser import BytesFeedParser
from common.database import *
from telegram.ext import CommandHandler, Updater


def send_request_to_redis(msg_id, msg_addr, msg_type, msg_request, logging, redis_client):
    """
    This function writes a new AI-VPN request to Redis.
    This is the first step to get a new account provisioned.
    """
    try:
        logging.debug(f'Sending {msg_request} request to Redis: ({str(msg_id)}) {msg_addr} on {msg_type}')
        add_item_provisioning_queue(redis_client,msg_id,msg_type,msg_addr,msg_request)
        return True
    except Exception as err:
        logging.info(f'Exception in send_request_to_redis: {err}')
        return False

def get_telegram_requests(redis_client,TELEGRAM_BOT_TOKEN,TELEGRAM_START_MSG,TELEGRAM_WAIT_MSG):
    """
    This function runs the telegram bot in charge of receiving messages
    """
    msg_type = "telegram"

    # Telegram Handlers
    def telegram_cmd_start(update, context):
        context.bot.send_message(chat_id=update.effective_chat.id,text=TELEGRAM_START_MSG)
        logging.info('New Telegram chat received')

    def telegram_cmd(update, context, msg_request):

        context.bot.send_message(chat_id=update.effective_chat.id,text=TELEGRAM_WAIT_MSG)
        logging.info(f'New Telegram OpenVPN request received from: {update.effective_chat.id}')
        # Write pending account to provision in REDIS
        send_request_to_redis(int(update.effective_chat.id),update.effective_chat.id,msg_type,msg_request,logging,redis_client)
        # Notify manager of new request
        redis_client.publish('services_status', 'MOD_COMM_RECV:NEW_REQUEST')

    try:
        # Initializing
        updater = Updater(token=TELEGRAM_BOT_TOKEN, use_context=True)
        dispatcher = updater.dispatcher
        logging.info('Telegram bot initialized')

        # Creating handlers per action
        start_handler = CommandHandler('start', telegram_cmd_start)
        dispatcher.add_handler(start_handler)

        openvpn_handler = CommandHandler('getopenvpn', partial(telegram_cmd, "openvpn"))
        dispatcher.add_handler(openvpn_handler)

        wireguard_handler = CommandHandler('getwireguard', partial(telegram_cmd, "wireguard"))
        dispatcher.add_handler(wireguard_handler)

        novpn_handler = CommandHandler('getnoencryptedvpn', partial(telegram_cmd, "novpn"))
        dispatcher.add_handler(novpn_handler)

        logging.info('Telegram handlers created')

        # Starting
        updater.start_polling()

    except Exception as err:
        logging.debug(f'Exception in get_telegram_requests: {err}')

def open_imap_connection():
    # Connect to the server
    connection = imaplib.IMAP4_SSL(IMAP_SERVER)
    connection.login(IMAP_USERNAME, IMAP_PASSWORD)
    return connection


def select_inbox_messages():
    " Returns generator:"
    global mail
    try:
        mail = open_imap_connection()

        mail.select("Inbox", readonly=False)
        # # Search and return UIDS of all UNSEEN/UNREAD emails in Inbox
        status, data = mail.uid('search', None, "UNSEEN")
        if status == "OK":
            id_msg_list = data[0].split()
            if len(id_msg_list) > 0:
                # process messages
                for msg_id in id_msg_list:
                    print("Processing message", msg_id)
                    typ, data = mail.uid('fetch', msg_id, '(RFC822)')
                    msg = data[0]
                    yield msg_id, msg
    except Exception as e:
        logging.error(f"Exception occurred in select_inbox_messages function {e}")
        return False
    finally:
        mail.expunge()
        mail.close()
        mail.logout()

def parse_email_messages(inbox_message):
    # Parse email to extract header and body
    email_parser = BytesFeedParser()
    email_parser.feed(inbox_message[1])
    return email_parser.close()

def process_email_message(msg):
    """
    Function takes parsed message and processed only those which
    current user is a receiver and answers to the emails are not send by AI VPN
    """
    # Do not process answers to the emails we send
    if msg['In-Reply-To'] is None:
        email_to = re.search(r'[\w\.-]+@[\w\.-]+', msg['to']).group(0)
        # Do not process messages where we are not the receivers
        if email_to == IMAP_USERNAME:
            return msg

def get_email_by_vpn_keyword(email_field):
    if email_field is None:
        return ""
    elif email_field == "NOENCRYPTEDVPN":
        return "novpn"
    elif email_field == "WIREGUARD":
        return "wireguard"
    elif email_field == "VPN":
        return "openvpn"
    else:
        return False

def search_for_vpn_keyword(msg):
    patterns = ["NOENCRYPTEDVPN", "WIREGUARD", "VPN"]
    for pattern in patterns:
        try:
            match = re.search(pattern, msg, re.IGNORECASE)
            if match:
                logging.info(f"Found the correct match for vpn keyword: {match.group(0)}")
                return match.group(0)
        except Exception as e:
            logging.error(f"Failed to find the correct email subject in parse_email_subject {e}")
            return False

def search_body_or_subject(email_field):
    email_search_match = search_for_vpn_keyword(email_field)
    if email_search_match:
        return get_email_by_vpn_keyword(email_search_match)
def get_email_body_data(message):
    try:
        return message.get_payload().pop().get_payload()
    except Exception as e:
        logging.debug(f"Failed with exception {e}. Email body is not in rich email.")
        return message.get_payload()

def get_msg_request(processed_emails):
    """
    Takes email message and search for vpn keyword in subject or body of the email
    and returns vpn keyword as message request
    """
    # search for vpn name in subject of an email
    if processed_emails['subject'] is not None:
        email_subject_search = search_body_or_subject(processed_emails['subject'])
        if email_subject_search:
            return email_subject_search
        else:
            # search for vpn keyword in a body of an email
            email_body_data = get_email_body_data(processed_emails)
            email_body_search = search_body_or_subject(email_body_data)
            if email_body_search:
                return email_body_search

def get_email_requests(redis_client):
    try:
        messages = select_inbox_messages()
        for email_uid, inbox_message in messages:
            msg = parse_email_messages(inbox_message)
            msg_type = "email"
            email_reply_to = re.search(r'[\w\.-]+@[\w\.-]+', msg['to']).group(0)
            processed_emails = process_email_message(msg)
            msg_request = get_msg_request(processed_emails)
            if msg_request:
                email_date = msg['date']
                email_from = re.search(r'[\w\.-]+@[\w\.-]+', msg['from']).group(0)
                email_to = re.search(r'[\w\.-]+@[\w\.-]+', msg['to']).group(0)
                email_subject = msg.get("Subject", "empty")
                email_body = msg_request
                logging.info(f"Extracted email request: {email_subject}:{email_body}({msg_request})")
                # Write pending account to provision in REDIS
                send_request_to_redis(int(email_uid), email_from, msg_type, msg_request, logging, redis_client)
                # Notify manager of new request
                redis_client.publish('services_status', 'MOD_COMM_RECV:NEW_REQUEST')

                logging.debug("This email matches the keywords")
                logging.debug('{:8}: {}'.format("Email ID", int(email_uid)))
                logging.debug('{:8}: {}'.format("Date", email_date))
                logging.debug('{:8}: {}'.format("To", email_to))
                logging.debug('{:8}: {}'.format("From", email_from))
                logging.debug('{:8}: {}'.format("Reply To", email_reply_to))
                logging.debug('{:8}: {}'.format("Subject", msg_request))
                logging.debug('{:8}: {}'.format("Body", msg_request))
            else:
                email_date = msg['date']
                email_from = re.search(r'[\w\.-]+@[\w\.-]+', msg['from']).group(0)
                email_to = re.search(r'[\w\.-]+@[\w\.-]+', msg['to']).group(0)
                logging.debug("This email matches the keywords")
                logging.debug('{:8}: {}'.format("Email ID", int(email_uid)))
                logging.debug('{:8}: {}'.format("Date", email_date))
                logging.debug('{:8}: {}'.format("To", email_to))
                logging.debug('{:8}: {}'.format("From", email_from))
                logging.debug('{:8}: {}'.format("Reply To", email_reply_to))
                logging.debug('{:8}: {}'.format("Subject", msg_request))
                logging.debug('{:8}: {}'.format("Body", msg_request))
    except Exception as e:
        print(e)
        return False


if __name__ == '__main__':
    # Read cofiguration file 
    config = configparser.ConfigParser()
    config.read('config/config.ini')

    REDIS_SERVER = config['REDIS']['REDIS_SERVER']
    CHANNEL = config['REDIS']['REDIS_COMM_RECV_CHECK']
    LOG_FILE = config['LOGS']['LOG_COMM_RECV']
    IMAP_SERVER = config['IMAP']['SERVER']
    IMAP_USERNAME = config['IMAP']['USERNAME']
    IMAP_PASSWORD = config['IMAP']['PASSWORD']
    TELEGRAM_BOT_TOKEN = config['TELEGRAM']['TELEGRAM_BOT_TOKEN']
    TELEGRAM_START_MSG = config['TELEGRAM']['TELEGRAM_START_MSG']
    TELEGRAM_WAIT_MSG = config['TELEGRAM']['TELEGRAM_WAIT_MSG']

    # Initialize logging
    logging.basicConfig(filename=LOG_FILE, encoding='utf-8', level=logging.INFO,format='%(asctime)s, MOD_COMM_RECV, %(message)s')

    # Connecting to the Redis database
    try:
        redis_client = redis_connect_to_db(REDIS_SERVER)
    except Exception as err:
        logging.error(f'Unable to connect to the Redis {REDIS_SERVER}: {err}')
        sys.exit(-1)

    # Creating a Redis subscriber
    try:
        db_subscriber = redis_create_subscriber(redis_client)
    except Exception as err:
        logging.error(f'Unable to create a Redis subscriber: {err}')
        sys.exit(-1)

    # Subscribing to Redis channel
    try:
        redis_subscribe_to_channel(db_subscriber,CHANNEL)
    except Exception as err:
        logging.error('Channel subscription failed: {err}')
        sys.exit(-1)

    try:
        logging.info("Connection and channel subscription to redis successful.")

        # Starting Telegram bot to check for new messages
        telegram_bot = threading.Thread(target=get_telegram_requests, args=(redis_client,TELEGRAM_BOT_TOKEN,TELEGRAM_START_MSG,TELEGRAM_WAIT_MSG,), daemon=True)
        telegram_bot.start()
        logging.info("Telegram bot thread started")

        # Checking for email messages
        for item in db_subscriber.listen():
            if item['type'] == 'message':
                logging.info(f"New message received in channel {item['channel']}: {item['data']}")
                if item['data'] == 'report_status':
                    if get_email_requests(redis_client, IMAP_SERVER, IMAP_USERNAME, IMAP_PASSWORD):
                        redis_client.publish('services_status','MOD_COMM_RECV:online')
                        logging.info('Status Online')
                    else:
                        IMAP_SERVER = config['IMAP']['SERVER']
                        IMAP_USERNAME = config['IMAP']['USERNAME']
                        IMAP_PASSWORD = config['IMAP']['PASSWORD']
                        redis_client.publish('services_status','MOD_COMM_RECV:error_checking_requests')
                        logging.info('Error checking requests')

        redis_client.publish('services_status','MOD_COMM_RECV:offline')
        logging.info("Terminating.")
        db_subscriber.close()
        redis_client.close()
        sys.exit(0)
    except Exception as err:
        logging.info(f'Terminating via exception in __main__: {err}')
        db_subscriber.close()
        redis_client.close()
        sys.exit(-1)
