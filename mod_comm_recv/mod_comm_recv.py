#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Veronica Valeros, vero.valeros@gmail.com, veronica.valeros@aic.fel.cvut.cz

import sys
import redis
import logging
import configparser
import re
import imaplib
import threading
from email.parser import BytesFeedParser
from common.database import *
from telegram.ext import CommandHandler
from telegram.ext import MessageHandler, Filters
from telegram.ext import Updater

def send_request_to_redis(msg_id, msg_addr, msg_type, msg_request, logging, redis_client):
    """
    This function writes a new AI-VPN request to Redis.
    This is the first step to get a new account provisioned.
    """
    try:
        logging.debug(f'Sending {msg_request} request to Redis: ({str(msg_id)}) {msg_addr} on {msg_type}')
        logging.info(f'**** [send_request_to_redis] Sending {msg_request} request to Redis: ({str(msg_id)}) {msg_addr} on {msg_type}')
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
    msg_request = "openvpn"

    # Telegram Handlers
    def telegram_cmd_start(update, context):
        context.bot.send_message(chat_id=update.effective_chat.id,text=TELEGRAM_START_MSG)
        logging.info('New Telegram chat received')

    def telegram_cmd_getopenvpn(update, context):
        context.bot.send_message(chat_id=update.effective_chat.id,text=TELEGRAM_WAIT_MSG)
        msg_request = "openvpn"
        logging.info(f'New Telegram OpenVPN request received from: {update.effective_chat.id}')
        # Write pending account to provision in REDIS
        send_request_to_redis(int(update.effective_chat.id),update.effective_chat.id,msg_type,msg_request,logging,redis_client)
        # Notify manager of new request
        redis_client.publish('services_status', 'MOD_COMM_RECV:NEW_REQUEST')

    def telegram_cmd_getwireguard(update, context):
        context.bot.send_message(chat_id=update.effective_chat.id,text=TELEGRAM_WAIT_MSG)
        msg_request = "wireguard"
        logging.info(f'New Telegram WireGuard request received from: {update.effective_chat.id}')
        # Write pending account to provision in REDIS
        send_request_to_redis(int(update.effective_chat.id),update.effective_chat.id,msg_type,msg_request,logging,redis_client)
        # Notify manager of new request
        redis_client.publish('services_status', 'MOD_COMM_RECV:NEW_REQUEST')

    def telegram_cmd_getnoencryptedvpn(update, context):
        context.bot.send_message(chat_id=update.effective_chat.id,text=TELEGRAM_WAIT_MSG)
        msg_request = "novpn"
        logging.info(f'New Telegram Not Encrypted OpenVPN request received from: {update.effective_chat.id}')
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

        openvpn_handler = CommandHandler('getopenvpn', telegram_cmd_getopenvpn)
        dispatcher.add_handler(openvpn_handler)

        wireguard_handler = CommandHandler('getwireguard', telegram_cmd_getwireguard)
        dispatcher.add_handler(wireguard_handler)

        novpn_handler = CommandHandler('getnoencryptedvpn', telegram_cmd_getnoencryptedvpn)
        dispatcher.add_handler(novpn_handler)

        logging.info('Telegram handlers created')

        # Starting
        updater.start_polling()


    except Exception as err:
        logging.info(f'Exception in get_telegram_requests: {err}')

def get_email_requests(redis_client,IMAP_SERVER,IMAP_USERNAME,IMAP_PASSWORD):
    """
    This function connects to an email server and retrieves all new emails to
    identify new VPN requests.
    """

    email_requests = []
    msg_type = "email"
    try:
        # Connect to email
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(IMAP_USERNAME,IMAP_PASSWORD)
        logging.debug("Connected to account successful")

        # Connect to Inbox. Readyonly option: False=marks msgs as read; True=keep messages as unread.
        mail.select("Inbox", readonly=False)

        # Search and return UIDS of all UNSEEN/UNREAD emails in Inbox
        result, data = mail.uid('search', None, "UNSEEN")

        # We receive a list of unread email UID
        id_list = data[0].split() # data is a list.
        logging.info("Found {} new requests to process".format(len(id_list)))

        # Process the new unread emails. If zero, nothing returns
        while len(id_list) > 0:
            # In case another process checked emails simultaneously, we refresh the list of ids
            result, data = mail.uid('search', None, "UNSEEN")
            id_list = data[0].split() # data is a list.

            # Get the first email ID to process
            email_uid = id_list.pop(0)
            logging.debug(f"Processing email UID {email_uid}")

            # Fetch the email headers and body (RFC822) for the given email UID
            result, data = mail.uid('fetch', email_uid, '(RFC822)')

            # Parse email to extract header and body
            email_parser = BytesFeedParser()
            email_parser.feed(data[0][1])
            msg = email_parser.close()

            # Do not process answers to the emails we send
            if msg['In-Reply-To'] is not None:
                continue

            # Parse email receiver
            email_to = re.search(r'[\w\.-]+@[\w\.-]+', msg['to']).group(0)
            logging.info(f"Processing email receiver {email_to}")

            # Do not process messages where we are not the receivers
            if not email_to == IMAP_USERNAME:
                continue

            # Parse subject and find matches for keyword VPN
            email_subject = ""
            msg_request=""
            try:
                logging.info(f"looking for   NOENCRYPTEDVPN IN MAIL  subject: {msg['subject']}")
                email_subject = re.search(r'NOENCRYPTEDVPN', msg['subject'],re.IGNORECASE).group(0)
                msg_request="novpn"
            except:
                try:
                    logging.info(f"looking for   NOTENCRYPTEDVPN IN MAIL  subject: {msg['subject']}")

                    email_subject = re.search(r'NOTENCRYPTEDVPN', msg['subject'],re.IGNORECASE).group(0)
                    msg_request="novpn"
                except:
                    try:
                        logging.info(f"looking for   WIREGUARD IN MAIL  subject: {msg['subject']}")

                        email_subject = re.search(r'WIREGUARD', msg['subject'],re.IGNORECASE).group(0)
                        msg_request="wireguard"
                    except:
                        try:

                            logging.info(f'*********looking for EDUVPN REQUEST IN MAIL  subject: {msg["subject"]}*************')

                            email_subject = re.search(r'EDUVPN', msg['subject'],re.IGNORECASE).group(0)
                            msg_request="eduvpn"
                            logging.info('*********FOUND EDUVPN REQUEST IN MAIL subject *************')
                        except:
                            try:
                                logging.info(f'*********looking for openvpn REQUEST IN MAIL  subject: {msg["subject"]}*************')

                                email_subject = re.search(r'VPN', msg['subject'],re.IGNORECASE).group(0)
                                msg_request="openvpn"
                                logging.info('*********FOUND openvpn REQUEST IN MAIL subject*************')

                            except Exception as ex:
                                logging.info(f"@@@@@@@@@@@@@@@@@@  exception??: {ex} {msg['subject']}*************")
                                pass

            logging.info(f"Extracted email subject: {email_subject} ({msg_request})")

            # Parse email body and find matches for keyword VPN
            try:
                # Extract email body in rich email
                email_body = msg.get_payload().pop().get_payload()
            except:
                # Extract email body in plain email
                email_body = msg.get_payload()

            try:
                email_body = re.search(r'NOENCRYPTEDVPN',email_body,re.IGNORECASE).group(0)
                msg_request="novpn"
            except:
                try:
                    logging.info(f'*********looking for NOTENCRYPTEDVPN REQUEST IN MAIL BODY: {email_body}*************')

                    email_body = re.search(r'NOTENCRYPTEDVPN',email_body,re.IGNORECASE).group(0)
                    msg_request="novpn"
                except:
                    try:
                        logging.info(f'*********looking for WIREGUARD REQUEST IN MAIL BODY: {email_body}*************')

                        email_body = re.search(r'WIREGUARD',email_body,re.IGNORECASE).group(0)
                        msg_request="wireguard"
                    except:
                        try:
                            logging.info(f'*********looking for EDUVPN REQUEST IN MAIL BODY: {email_body}*************')

                            email_body = re.search(r'EDUVPN',email_body,re.IGNORECASE).group(0)
                            msg_request="eduvpn"
                            logging.info('*********FOUND EDUVPN REQUEST IN MAIL BODY*************')
                        except:
                            try:
                                logging.info(f'*********looking for VPN REQUEST IN MAIL BODY: {email_body}*************')

                                email_body = re.search(r'VPN',email_body,re.IGNORECASE).group(0)
                                msg_request="openvpn"
                                logging.info('*********FOUND openvpn REQUEST IN MAIL BODY*************')
                            except:
                                pass

            logging.info(f"Extracted email body: {email_body} ({msg_request})")

            # We only parse messages that contain VPN in subject or body
            # These prints will be removed after we test everything is good
            if msg_request != "":
                logging.info(f"Extracted email request: {email_subject}:{email_body}({msg_request})")
                # Parse email date
                email_date = msg['date']

                # Parse email sender
                email_from = re.search(r'[\w\.-]+@[\w\.-]+', msg['from']).group(0)

                # Write pending account to provision in REDIS
                send_request_to_redis(int(email_uid),email_from,msg_type,msg_request,logging,redis_client)

                # Notify manager of new request
                redis_client.publish('services_status', 'MOD_COMM_RECV:NEW_REQUEST')

                logging.debug("This email matches the keywords")
                logging.debug('{:8}: {}'.format("email id",int(email_uid)))
                logging.debug('{:8}: {}'.format("date",email_date))
                logging.debug('{:8}: {}'.format("to",email_to))
                logging.debug('{:8}: {}'.format("from",email_from))
                logging.debug('{:8}: {}'.format("reply_to",msg['In-Reply-To']))
                logging.debug('{:8}: {}'.format("subject",email_subject))
                logging.debug('{:8}: {}'.format("body",email_body))
            else:
                logging.debug("This email does not match the keywords")
                logging.debug('{:8}: {}'.format("Email ID",email_uid))
                logging.debug('{:8}: {}'.format("Date",email_date))
                logging.debug('{:8}: {}'.format("To",email_to))
                logging.debug('{:8}: {}'.format("From",email_from))
                logging.debug('{:8}: {}'.format("reply_to",msg['In-Reply-To']))
                logging.debug('{:8}: {}'.format("Subject",email_subject))
                logging.debug('{:8}: {}'.format("Body",email_body))

        # Close connection to server
        mail.expunge()
        mail.close()
        mail.logout()
        return True
    except Exception as e:
        logging.info(e)
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
