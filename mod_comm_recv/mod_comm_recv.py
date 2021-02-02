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
from email.parser import BytesFeedParser
from common.database import *

def send_request_to_redis(email_uid, email_date, email_from, logging,redis_client):
    """
    This function writes a new AI-VPN request to Redis.
    This is the first step to get a new account provisioned.
    """
    try:
        logging.debug("Sending a request to Redis: ({}) {} on {}".format(email_uid,email_from,email_date))
        redis_client.publish('aivpn_accounts_new', [email_uid,email_from_email_date])
        return True
    except Exception as e:
        print(e)
        return False

def get_new_requests(redis_client,IMAP_SERVER,IMAP_USERNAME,IMAP_PASSWORD,logging):
    email_requests = []

    try:
        # Connect to email
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(IMAP_USERNAME,IMAP_PASSWORD)
        logging.info("Connected to account successful")

        # Connect to Inbox. Readyonly option: False=marks msgs as read; True=keep messages as unread.
        mail.select("Inbox", readonly=True)

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

            # Do not process messages where we are not the receivers
            if not email_to == IMAP_USERNAME:
                continue

            # Parse subject and find matches for keyword VPN
            try:
                email_subject = re.search(r'[VPN]+', msg['subject']).group(0)
            except:
                email_subject = ""

            # Parse email body and find matches for keyword VPN
            try:
                # Extract email body in rich email
                email_body = msg.get_payload().pop().get_payload()
            except:
                # Extract email body in plain email
                email_body = msg.get_payload()

            try:
                email_body = re.search(r'[VPN]+', email_body).group(0)
            except:
                email_body = ""


            # We only parse messages that contain VPN in subject or body
            # These prints will be removed after we test everythig is good
            if (email_subject == 'VPN' or email_body == 'VPN'):
                # Parse email date
                email_date = msg['date']

                # Parse email sender
                email_from = re.search(r'[\w\.-]+@[\w\.-]+', msg['from']).group(0)

                # Write pending account to provision in REDIS
                send_request_to_redis(int(email_uid),email_date,email_from,logging,redis_client)

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
        print(e)
        return False

if __name__ == '__main__':
    # Read configuration file
    config = configparser.ConfigParser()
    config.read('config/config.ini')

    REDIS_SERVER = config['REDIS']['REDIS_SERVER']
    CHANNEL = config['REDIS']['REDIS_COMM_RECV_CHECK']
    LOG_FILE = config['LOGS']['LOG_COMM_RECV']
    IMAP_SERVER = config['IMAP']['SERVER']
    IMAP_USERNAME = config['IMAP']['USERNAME']
    IMAP_PASSWORD = config['IMAP']['PASSWORD']

    # Initialize logging
    logging.basicConfig(filename=LOG_FILE, encoding='utf-8', level=logging.INFO,format='%(asctime)s, MOD_CONN_RECV, %(message)s')

    # Connecting to the Redis database
    try:
        redis_client = redis_connect_to_db(REDIS_SERVER)
    except:
        logging.error("Unable to connect to the Redis database (",REDIS_SERVER,")")
        sys.exit(-1)

    # Creating a Redis subscriber
    try:
        db_subscriber = redis_create_subscriber(redis_client)
    except:
        logging.error("Unable to create a Redis subscriber")
        sys.exit(-1)

    # Subscribing to Redis channel
    try:
        redis_subscribe_to_channel(db_subscriber,CHANNEL)
    except:
        logging.error("Channel subscription failed")
        sys.exit(-1)

    try:
        logging.info("Connection and channel subscription to redis successful.")

        # Checking for messages
        for item in db_subscriber.listen():
            if item['type'] == 'message':
                logging.info(item['channel'])
                logging.info(item['data'])
                if item['data'] == b'report_status':
                    if get_new_requests(redis_client, IMAP_SERVER, IMAP_USERNAME, IMAP_PASSWORD,logging):
                        redis_client.publish('services_status', 'MOD_COMM_RECV:online')
                        logging.info('MOD_COMM_RECV:online')
                    else:
                        redis_client.publish('services_status', 'MOD_COMM_RECV:error_checking_requests')
                        logging.info('MOD_COMM_RECV:error_checking_requests')

        redis_client.publish('services_status', 'MOD_COMM_RECV:offline')
        logging.info("Terminating.")
        redis_client.close()
        db_subscriber.close()
        sys.exit(0)
    except Exception as err:
        redis_client.close()
        db_subscriber.close()
        logging.info("Terminating via exception in main")
        logging.info(err)
        sys.exit(-1)
