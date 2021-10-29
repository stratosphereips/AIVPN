#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Veronica Valeros, vero.valeros@gmail.com, veronica.valeros@aic.fel.cvut.cz

import sys
import redis
import logging
import configparser
from common.database import *
from smtplib import SMTP_SSL, SMTP_SSL_PORT
from email.mime.multipart import MIMEMultipart, MIMEBase
from email.mime.text import MIMEText
from email.encoders import encode_base64
from telegram.ext import CommandHandler
from telegram.ext import Updater

def send_mime_msg_via_email(msg_type,profile_name,msg_addr,config):
    """ Function to send a MIME message to the user via email. """
    try:
        # Load general configuration
        EMAIL_SERVER = config.get('IMAP','SERVER')
        EMAIL_USER = config.get('IMAP','USERNAME')
        EMAIL_PASSWORD = config.get('IMAP','PASSWORD')
        EMAIL_SUBJ_PREFIX = config.get('AIVPN','MESSAGE_SUBJECT_PREFIX')
        PATH = config.get('STORAGE','PATH')

        # Create message
        email_message = MIMEMultipart()
        email_message.add_header('From', EMAIL_USER)
        email_message.add_header('To', msg_addr)

        # Different bodies based on the message type
        if msg_type == 'send_openvpn_profile_email':
            EMAIL_BODY = config.get('AIVPN','MESSAGE_NEW_PROFILE')
            EMAIL_ATTACHMENT = f'{PATH}/{profile_name}/{profile_name}.ovpn'
            EMAIL_FILENAME = f'{profile_name}.ovpn'
            email_message.add_header('Subject', f"{EMAIL_SUBJ_PREFIX} VPN Profile Active: {profile_name}\r\n")

        if msg_type == 'send_report_profile_email':
            EMAIL_BODY = config.get('AIVPN','MESSAGE_REPORT')
            EMAIL_ATTACHMENT = f'{PATH}/{profile_name}/{profile_name}.pdf'
            EMAIL_FILENAME = f'{profile_name}.pdf'
            email_message.add_header('Subject', f"{EMAIL_SUBJ_PREFIX} VPN Profile Report: {profile_name}\r\n")

        # Create text and HTML bodies for email
        email_body_text = MIMEText(EMAIL_BODY,'plain')

        # Create file attachment
        attachment = MIMEBase("application", "octet-stream")
        attachment.set_payload(open(EMAIL_ATTACHMENT, "rb").read())
        encode_base64(attachment)
        attachment.add_header("Content-Disposition", f"attachment; filename={EMAIL_FILENAME}")

        # Attach all the parts to the Multipart MIME email
        email_message.attach(email_body_text)
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
        logging.info(f'Exception in send_mime_msg_via_email: {err}')
        return False

def send_plain_msg_via_email(msg_type,profile_name,msg_addr,config):
    """ Function to send a PLAIN message to the user via email. """
    try:
        # Load general configuration
        EMAIL_SERVER = config.get('IMAP','SERVER')
        EMAIL_USER = config.get('IMAP','USERNAME')
        EMAIL_PASSWORD = config.get('IMAP','PASSWORD')
        EMAIL_SUBJ_PREFIX = config.get('AIVPN','MESSAGE_SUBJECT_PREFIX')
        PATH = config.get('STORAGE','PATH')

        # Create message headers
        headers = f"From: {EMAIL_USER}\r\n"
        headers += f"To: {msg_addr}\r\n"

        # Different content based on the message type
        if msg_type == 'send_expire_profile_email':
            EMAIL_BODY = config.get('AIVPN','MESSAGE_EXPIRED_PROFILE')
            headers += f"Subject: {EMAIL_SUBJ_PREFIX} VPN Profile Expired: {profile_name}\r\n"

        if msg_type == 'send_empty_capture_email':
            EMAIL_BODY = config.get('AIVPN','MESSAGE_REPORT_EMPTY')
            headers += f"Subject: {EMAIL_SUBJ_PREFIX} VPN Profile Report: {profile_name}\r\n"

        if msg_type == 'error_limit_reached':
            EMAIL_BODY = config.get('AIVPN','MESSAGE_MAX_LIMIT')
            headers += f"Subject: {EMAIL_SUBJ_PREFIX} Account Limit Reached\r\n"

        if msg_type == 'error_max_capacity':
            EMAIL_BODY = config.get('AIVPN','MESSAGE_FULL_CAPACITY')
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
        logging.info(f'Exception in send_plain_msg_via_email: {err}')
        return False

def send_message_via_telegram(msg_type,profile_name,msg_addr,config):
    """ Function to send a message to the user via Telegram. """
    try:
        pass
        # Load configuration
        TELEGRAM_BOT_TOKEN = config['TELEGRAM']['TELEGRAM_BOT_TOKEN']

        # Initializing Telegram Bot
        updater = Updater(token=TELEGRAM_BOT_TOKEN, use_context=True)
        dispatcher = updater.dispatcher

        dispatcher.bot.send_message(msg_addr, text="Your profile has expired")
    except Exception as err:
        logging.info(f'Exception in send_message_via_telegram: {err}')
        return False

if __name__ == '__main__':
    # Read configuration
    config = configparser.ConfigParser()
    config.read('config/config.ini')

    REDIS_SERVER = config['REDIS']['REDIS_SERVER']
    CHANNEL = config['REDIS']['REDIS_COMM_SEND_CHECK']
    LOG_FILE = config['LOGS']['LOG_COMM_SEND']

    logging.basicConfig(filename=LOG_FILE, encoding='utf-8', level=logging.DEBUG,format='%(asctime)s, MOD_COMM_SEND, %(message)s')

    # Connecting to the Redis database
    try:
        redis_client = redis_connect_to_db(REDIS_SERVER)
    except Exception as err:
        logging.error(f'Unable to connect to Redis database {err}')
        sys.exit(-1)

    # Creating a Redis subscriber
    try:
        db_subscriber = redis_create_subscriber(redis_client)
    except Exception as err:
        logging.error(f'Unable to create Redis subscriber {err}')
        sys.exit(-1)

    # Subscribing to Redis channel
    try:
        redis_subscribe_to_channel(db_subscriber,CHANNEL)
    except Exception as err:
        logging.error(f'Unable to subscribe to Redis channel {err}')
        sys.exit(-1)

    try:
        logging.info("Connection and channel subscription to Redis successful.")

        # Checking for messages
        for item in db_subscriber.listen():
            if item['type'] == 'message':
                logging.info(f"New message received in {item['channel']}: {item['data']}")
                if item['data'] == 'report_status':
                    redis_client.publish('services_status','MOD_COMM_SEND:online')
                    logging.info('Status Online')
                elif 'send' in item['data']:
                    # Obtain the profile name and address where to send
                    profile_name = item['data'].split(':')[1]
                    msg_type = item['data'].split(':')[0]
                    msg_addr=get_profile_name_address(profile_name,redis_client)

                    # Different options of what to send
                    logging.info(f"{msg_type} to {profile_name} ({msg_addr})")
                    status = ""
                    if 'send_openvpn_profile_email' in item['data']:
                        status = send_mime_msg_via_email(msg_type,profile_name,msg_addr,config)
                    elif 'send_report_profile_email' in item['data']:
                        status = send_mime_msg_via_email(msg_type,profile_name,msg_addr,config)
                    else:
                        status = send_plain_msg_via_email(msg_type,profile_name,msg_addr,config)

                    logging.info(f"{item['data']} status: {status}")
                    redis_client.publish('services_status',f"MOD_COMM_SEND:{item['data']}_{status}")

                elif 'error' in item['data']:
                    # Obtain the address where to send the error message
                    msg_addr=item['data'].split(':')[1]
                    msg_type = item['data'].split(':')[0]
                    profile_name=""

                    logging.info(f"Sending {msg_type} to {msg_addr}")
                    status = send_plain_msg_via_email(msg_type,profile_name,msg_addr,config)

                    logging.info(f"Sending {msg_type} status: {status}")
                    redis_client.publish('services_status',f"MOD_COMM_SEND:{msg_type}_{status}")

        redis_client.publish('services_status', 'MOD_COMM_SEND:offline')
        logging.info("Terminating")
        db_subscriber.close()
        redis_client.close()
        sys.exit(0)
    except Exception as err:
        logging.info(f'Terminating via exception in __main__: {err}')
        db_subscriber.close()
        redis_client.close()
        sys.exit(-1)
