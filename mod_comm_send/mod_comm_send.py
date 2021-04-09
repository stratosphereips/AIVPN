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

def read_configuration():
    # Read configuration file
    config = configparser.ConfigParser()
    config.read('config/config.ini')

    REDIS_SERVER = config['REDIS']['REDIS_SERVER']
    CHANNEL = config['REDIS']['REDIS_COMM_SEND_CHECK']
    LOG_FILE = config['LOGS']['LOG_COMM_SEND']
    IMAP_SERVER = config['IMAP']['SERVER']
    IMAP_USERNAME = config['IMAP']['USERNAME']
    IMAP_PASSWORD = config['IMAP']['PASSWORD']
    PATH = config['STORAGE']['PATH']
    return REDIS_SERVER,CHANNEL,LOG_FILE,IMAP_SERVER,IMAP_USERNAME,IMAP_PASSWORD,PATH

def send_ovpn_profile_via_email(msg_account_name,msg_address,SMTP_HOST,SMTP_USER,SMTP_PASSWORD,PATH):
    """ Function to send the openvpn profile file to the user via email. """
    try:
        # Create multipart MIME email
        email_message = MIMEMultipart()
        email_message.add_header('To', msg_address)
        email_message.add_header('From', SMTP_USER)
        email_message.add_header('Subject', f"[Civilsphere Emergency VPN] New profile: {msg_account_name}\r\n")

        # Create text and HTML bodies for email
        text_part = MIMEText('Please find attached your new Emergency VPN profile.', 'plain')

        # Create file attachment
        attachment = MIMEBase("application", "octet-stream")
        attachment.set_payload(open(f"{PATH}/{msg_account_name}/{msg_account_name}.ovpn", "rb").read())
        encode_base64(attachment)
        attachment.add_header("Content-Disposition", f"attachment; filename={msg_account_name}.ovpn")

        # Attach all the parts to the Multipart MIME email
        email_message.attach(text_part)
        email_message.attach(attachment)

        # Connect, authenticate, and send mail
        smtp_server = SMTP_SSL(SMTP_HOST, port=SMTP_SSL_PORT)
        smtp_server.set_debuglevel(1)  # Show SMTP server interactions
        smtp_server.login(SMTP_USER, SMTP_PASSWORD)
        smtp_server.sendmail(SMTP_USER, msg_address, email_message.as_bytes())

        # Disconnect
        smtp_server.quit()
        return True
    except Exception as err:
        return err

def send_max_account_limit_reached_via_email(msg_address,SMTP_HOST,SMTP_USER,SMTP_PASSWORD):
    """ Function to send the message that the user requested too many profiles. """
    try:
        # Craft the email by hand
        body = "Thank you for your interest in using our service. You have reached the maximum number of active profiles per account. Try again after your existing profiles have expired."
        headers = f"From: {SMTP_USER}\r\n"
        headers += f"To: {msg_address}\r\n"
        headers += f"Subject: [CivilSphere Emergency VPN] Maximum Number of Requests Received\r\n"
        email_message = headers + "\r\n" + body  # Blank line needed between headers and body

        # Connect, authenticate, and send mail
        smtp_server = SMTP_SSL(SMTP_HOST, port=SMTP_SSL_PORT)
        smtp_server.set_debuglevel(1)  # Show SMTP server interactions
        smtp_server.login(SMTP_USER, SMTP_PASSWORD)
        smtp_server.sendmail(SMTP_USER, msg_address, email_message)

        # Disconnect
        smtp_server.quit()
        return True
    except Exception as err:
        return err


def send_max_capacity_reached_via_email(msg_address,SMTP_HOST,SMTP_USER,SMTP_PASSWORD):
    """ Function to send the message that the service is at full capacity. """
    try:
        # Craft the email by hand
        body = "Our service is at full capacity. Please try again in some days."
        headers = f"From: {SMTP_USER}\r\n"
        headers += f"To: {msg_address}\r\n"
        headers += f"Subject: [CivilSphere Emergency VPN] Our Service Capacity is Full\r\n"
        email_message = headers + "\r\n" + body  # Blank line needed between headers and body

        # Connect, authenticate, and send mail
        smtp_server = SMTP_SSL(SMTP_HOST, port=SMTP_SSL_PORT)
        smtp_server.set_debuglevel(1)  # Show SMTP server interactions
        smtp_server.login(SMTP_USER, SMTP_PASSWORD)
        smtp_server.sendmail(SMTP_USER, msg_address, email_message)

        # Disconnect
        smtp_server.quit()
        return True
    except Exception as err:
        return err

def send_expired_profile_msg_via_email(msg_account_name,msg_address,SMTP_HOST,SMTP_USER,SMTP_PASSWORD):
    """ Function to send the message that profile expired to the user via email. """
    try:
        # Craft the email by hand
        body = "Thank you for using our Emergency VPN service."
        headers = f"From: {SMTP_USER}\r\n"
        headers += f"To: {msg_address}\r\n"
        headers += f"Subject: [CivilSphere Emergency VPN] Your VPN profile {msg_account_name} has expired\r\n"
        email_message = headers + "\r\n" + body  # Blank line needed between headers and body

        # Connect, authenticate, and send mail
        smtp_server = SMTP_SSL(SMTP_HOST, port=SMTP_SSL_PORT)
        smtp_server.set_debuglevel(1)  # Show SMTP server interactions
        smtp_server.login(SMTP_USER, SMTP_PASSWORD)
        smtp_server.sendmail(SMTP_USER, msg_address, email_message)

        # Disconnect
        smtp_server.quit()
        return True
    except Exception as err:
        return err

def send_profile_report_via_email(msg_account_name,msg_address,SMTP_HOST,SMTP_USER,SMTP_PASSWORD,PATH):
    """ Function to send the profile report to the user via email. """
    try:
        # Create multipart MIME email
        email_message = MIMEMultipart()
        email_message.add_header('To', msg_address)
        email_message.add_header('From', SMTP_USER)
        email_message.add_header('Subject', f"[Civilsphere Emergency VPN] New profile: {msg_account_name}\r\n")

        # Create text and HTML bodies for email
        text_part = MIMEText('Please find attached your new Emergency VPN profile.', 'plain')

        # Create file attachment
        attachment = MIMEBase("application", "octet-stream")
        attachment.set_payload(open(f"{PATH}/{msg_account_name}/{msg_account_name}.pdf", "rb").read())
        encode_base64(attachment)
        attachment.add_header("Content-Disposition", f"attachment; filename={msg_account_name}.pdf")

        # Attach all the parts to the Multipart MIME email
        email_message.attach(text_part)
        email_message.attach(attachment)

        # Connect, authenticate, and send mail
        smtp_server = SMTP_SSL(SMTP_HOST, port=SMTP_SSL_PORT)
        smtp_server.set_debuglevel(1)  # Show SMTP server interactions
        smtp_server.login(SMTP_USER, SMTP_PASSWORD)
        smtp_server.sendmail(SMTP_USER, msg_address, email_message.as_bytes())

        # Disconnect
        smtp_server.quit()
        return True
    except Exception as err:
        return err

if __name__ == '__main__':
    # Read configuration
    REDIS_SERVER,CHANNEL,LOG_FILE,IMAP_SERVER,IMAP_USERNAME,IMAP_PASSWORD,PATH = read_configuration()

    logging.basicConfig(filename=LOG_FILE, encoding='utf-8', level=logging.DEBUG,format='%(asctime)s, MOD_COMM_SEND, %(message)s')

    # Connecting to the Redis database
    try:
        redis_client = redis_connect_to_db(REDIS_SERVER)
    except Exception as err:
        logging.error("Exception in __main__, unable to connect to Redis database (",REDIS_SERVER,")")
        sys.exit(-1)

    # Creating a Redis subscriber
    try:
        db_subscriber = redis_create_subscriber(redis_client)
    except Exception as err:
        logging.error("Exception in __main__, unable to create a Redis subscriber {}".format(err))
        sys.exit(-1)

    # Subscribing to Redis channel
    try:
        redis_subscribe_to_channel(db_subscriber,CHANNEL)
    except Exception as err:
        logging.error("Exception in __main__, unable to subscribe to Redis channel {}".format(err))
        sys.exit(-1)

    try:
        logging.info("Connection and channel subscription to redis successful.")

        # Checking for messages
        for item in db_subscriber.listen():
            if item['type'] == 'message':
                logging.info("New message received in channel {}: {}".format(item['channel'],item['data']))
                if item['data'] == 'report_status':
                    redis_client.publish('services_status', 'MOD_COMM_SEND:online')
                    logging.info('MOD_COMM_SEND:online')
                elif 'send' in item['data']:
                    # Obtain the profile name and address where to send
                    msg_account_name=item['data'].split(':')[1]
                    msg_address=get_profile_name_address(msg_account_name,redis_client)

                    # Different options of what to send
                    if 'send_openvpn_profile_email' in item['data']:
                        logging.info('Sending OpenVPN profile to {} ({})'.format(msg_account_name,msg_address))
                        if send_ovpn_profile_via_email(msg_account_name,msg_address,IMAP_SERVER,IMAP_USERNAME,IMAP_PASSWORD,PATH):
                            redis_client.publish('services_status', 'MOD_COMM_SEND:openvpn profile sent successfully')
                            logging.info('openvpn profile sent successfully')
                        else:
                            redis_client.publish('services_status', 'MOD_COMM_SEND:failed to send openvpn profile')
                            logging.info('failed to send openvpn profile')
                        continue
                    if 'send_expire_profile_email' in item['data']:
                        logging.info('Sending expiration of profile to {} ({})'.format(msg_account_name,msg_address))
                        if send_expired_profile_msg_via_email(msg_account_name,msg_address,IMAP_SERVER,IMAP_USERNAME,IMAP_PASSWORD):
                            redis_client.publish('services_status', 'MOD_COMM_SEND:openvpn expiration sent successfully')
                            logging.info('openvpn expiration sent successfully')
                        else:
                            redis_client.publish('services_status', 'MOD_COMM_SEND:failed to send profile expiration message')
                            logging.info('failed to send profile expiration message')
                        continue
                    if 'send_report_profile_email' in item['data']:
                        logging.info('Sending report on profile to {} ({})'.format(msg_account_name,msg_address))
                        if send_profile_report_via_email(msg_account_name,msg_address,IMAP_SERVER,IMAP_USERNAME,IMAP_PASSWORD,PATH):
                            redis_client.publish('services_status', 'MOD_COMM_SEND:profile report sent successfully')
                            logging.info('profile report sent successfully')
                        else:
                            redis_client.publish('services_status', 'MOD_COMM_SEND:failed to send profile report')
                            logging.info('failed to send profile report')
                        continue
                elif 'error' in item['data']:
                    # Obtain the address where to send the error message
                    msg_address=item['data'].split(':')[1]
                    if 'error_limit_reached' in item['data']:
                        logging.info(f'Sending max limit reached to {msg_address}')
                        if send_max_account_limit_reached_via_email(msg_address,IMAP_SERVER,IMAP_USERNAME,IMAP_PASSWORD):
                            redis_client.publish('services_status', 'MOD_COMM_SEND:message limit reached sent successfully')
                            logging.info('limit reached message sent successfully')
                        else:
                            redis_client.publish('services_status', 'MOD_COMM_SEND:failed to send message that limit was reached.')
                            logging.info('failed to send message that limit was reached.')
                        continue
                    if 'error_max_capacity' in item['data']:
                        logging.info(f'Sending max capacity reached to {msg_address}')
                        if send_max_capacity_reached_via_email(msg_address,IMAP_SERVER,IMAP_USERNAME,IMAP_PASSWORD):
                            redis_client.publish('services_status', 'MOD_COMM_SEND:message capacity reached sent successfully')
                            logging.info('capacity reached message sent successfully')
                        else:
                            redis_client.publish('services_status','MOD_COMM_SEND:failed to send message that maximum capacity was reached.')
                            logging.info('failed to send message that maximum capacity was reached.')
                        continue

        redis_client.publish('services_status', 'MOD_COMM_SEND:offline')
        logging.info("Terminating")
        redis_client.close()
        db_subscriber.close()
        sys.exit(0)
    except Exception as err:
        logging.info("Terminating via exception in __main__: {}".format(err))
        redis_client.close()
        db_subscriber.close()
        sys.exit(-1)
