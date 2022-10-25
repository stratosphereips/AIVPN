#!/usr/bin/env python3
# This file is part of the Civilsphere AI VPN
# See the file 'LICENSE' for copying permission.
# Author: Veronica Valeros, vero.valeros@gmail.com, veronica.valeros@aic.fel.cvut.cz

import redis
import time
import json
import random
import ipaddress
import configparser


# REDIS COMMON
## Series of functions to handle the connections to the Redis database, as well
## as subscribing to channels using pub/sub.

def redis_connect_to_db(REDIS_SERVER):
    """ Function to connect to a Redis database. Returns object publisher. """
    try:
        client = redis.Redis(REDIS_SERVER, port=6379, db=0, decode_responses=True )
        return client
    except Exception as err:
        return err

def redis_create_subscriber(publisher):
    """ Function to create a pubsub() object. Returns object subscriber. """
    try:
        subscriber = publisher.pubsub()
        return subscriber
    except Exception as err:
        return err

def redis_subscribe_to_channel(subscriber,CHANNEL):
    """ Function to subscribe to a given Redis channel"""
    try:
        subscriber.subscribe(CHANNEL)
        return True
    except Exception as err:
        return err

# IDENTITY HANDLING
## The IDENTITY HANDLING are a series of functions associated with the handling
## of user identities. The identity of a user is an email address, account name or
## any other account identified used to communicate between the AIVPN and the user
##
## The hash table will be account_identities and the value will be a JSON.
## Fields: msg_addr
## Value:
## {'total_profiles':1,'type':'email','profiles':'[profile_name1,profile_name2]','gpg':string-gpg}

identity_template = json.dumps({'total_profiles':0,'type':'email','profiles':[],'gpg':''})
hash_account_identities = "account_identities"

def add_identity(msg_addr,REDIS_CLIENT):
    """ Stores the msg_addr in redis  """

    try:
        status = REDIS_CLIENT.hsetnx(hash_account_identities,msg_addr,identity_template)

        # status==1 if HSETNX created a field in the hash set
        # status==0 if the identity exists and no operation is done.
        return status
    except Exception as err:
        return err

def exists_identity(msg_addr,REDIS_CLIENT):
    """ Checks if the msg_addr in redis exists """
    try:
        hash_table = "account_identities"

        status = REDIS_CLIENT.hexists(hash_account_identities,msg_addr)

        # Returns a boolean indicating if key exists within hash name
        return status
    except Exception as err:
        return err

def upd_identity_counter(msg_addr,REDIS_CLIENT):
    """ Updates counter if the msg_addr in redis exists  by 1. """
    try:
        identity_object = json.loads(REDIS_CLIENT.hget(hash_account_identities,msg_addr))

        identity_object['total_profiles'] = int(identity_object['total_profiles'])+ 1

        identity_value = json.dumps(identity_object)

        status = REDIS_CLIENT.hset(hash_account_identities,msg_addr,identity_value)

        return status
    except Exception as err:
        return err

def upd_identity_type(msg_addr,REDIS_CLIENT,msg_type='email'):
    """
    If identity exists, add the identity type (email, telegram, etc).
    Default value is 'email'.
    """
    try:
        identity_value = REDIS_CLIENT.hget(hash_account_identities,msg_addr)
        identity_object = json.loads(identity_value)

        #identity = {'total_profiles':0,'type':'','profiles':'[]','gpg':''g}
        identity_object['type'] = str(msg_type)

        identity_value = json.dumps(identity_object)

        status = REDIS_CLIENT.hset(hash_account_identities,msg_addr,identity_value)

        return True
    except Exception as err:
        return err

def get_identity_type(msg_addr,REDIS_CLIENT):
    """
    If identity exists, return the identity type (email, telegram, etc).
    """
    try:
        identity_value = REDIS_CLIENT.hget(hash_account_identities,msg_addr)
        identity_object = json.loads(identity_value)

        #identity = {'total_profiles':0,'type':'','profiles':'[]','gpg':''g}
        return identity_object['type']
    except Exception as err:
        return err

def upd_identity_profiles(msg_addr,profile_name,REDIS_CLIENT):
    """ If identity exists, add a new profile for the identity """
    try:
        identity_value = REDIS_CLIENT.hget(hash_account_identities,msg_addr)
        identity_object = json.loads(identity_value)

        #identity = {'total_profiles':0,'type':'','profiles':'[]','gpg':''g}
        identity_object['profiles'].append(str(profile_name))

        identity_value = json.dumps(identity_object)

        status = REDIS_CLIENT.hset(hash_account_identities,msg_addr,identity_value)

        return True
    except Exception as err:
        return err

def upd_identity_gpg(msg_addr,gpg_key,REDIS_CLIENT):
    """ If identity exists, add a new gpg key for the identity """
    try:
        identity_object = json.loads(REDIS_CLIENT.hget(hash_account_identities,msg_addr))

        #identity = {'total_profiles':0,'type':'','profiles':'[]','gpg':''g}
        identity_object['gpg'] = gpg_key

        identity_value = json.dumps(identity_object)

        status = REDIS_CLIENT.hset(hash_account_identities,msg_addr,identity_value)
        return status
    except Exception as err:
        return err

def del_identity(msg_addr,REDIS_CLIENT):
    """ Deletes the msg_addr in redis """
    try:
        REDIS_CLIENT.hdel(hash_account_identities,msg_addr)
        return True
    except Exception as err:
        return err

# ACTIVE PROFILE HASH
## We want to quickly consult the number of active profiles in a given identity
## to check that it a certain limit has been reached or not. Users cannot
## request unlimited number of accounts. This is a DDoS protection.
hash_number_active_profiles_per_account = "number_active_profiles_per_account"

def add_active_profile_counter(msg_addr,REDIS_CLIENT):
    """ Increases the counter of active profiles for a given identity by one. """

    try:
        # Create a new entry if there is not one. Initalize at 0.
        REDIS_CLIENT.hsetnx(hash_number_active_profiles_per_account,msg_addr,0)

        REDIS_CLIENT.hincrby(hash_number_active_profiles_per_account,msg_addr,1)

        return True
    except Exception as err:
        return err

def subs_active_profile_counter(msg_addr,REDIS_CLIENT):
    """ Decreases the counter of active profiles for a given identity by one. """

    try:
        # Get current value, if above zero substract one.
        counter_active_profiles = int(REDIS_CLIENT.hget(hash_number_active_profiles_per_account,msg_addr))
        if counter_active_profiles > 0:
            REDIS_CLIENT.hincrby(hash_number_active_profiles_per_account,msg_addr,-1)
        return True
    except Exception as err:
        return err

def get_active_profile_counter(msg_addr,REDIS_CLIENT):
    """ Returns the counter of active profiles for a given identity. """
    try:
        counter_active_profiles = REDIS_CLIENT.hget(hash_number_active_profiles_per_account,msg_addr)
        if counter_active_profiles is None:
            counter_active_profiles=0
        return int(counter_active_profiles)
    except Exception as err:
        return err


def del_active_profile_counter(msg_addr,REDIS_CLIENT):
    """ Deletes the counter of active profiles for a given identity. """
    try:
        REDIS_CLIENT.hdel(hash_number_active_profiles_per_account,msg_addr)
        return True
    except Exception as err:
        return err

# VPN IP ADDRESS SPACE HANDLING
## We want to quickly check if an IP address is in use
#hash_blocked_ip_addresses = "blocked_ip_addresses_mod_openvpn"
#hash_blocked_ip_addresses = "blocked_ip_addresses_mod_wireguard"
#hash_blocked_ip_addresses = "blocked_ip_addresses_mod_novpn"
hash_blocked_ip_addresses = "blocked_ip_addresses_mod_"

def add_ip_address(ip_address,vpn_type,REDIS_CLIENT):
    """ Adds a new IP address to the blocked IP addresses hash table. """
    try:
        hash_blocked_ip_addresses = f'blocked_ip_addresses_mod_{vpn_type}'
        REDIS_CLIENT.hsetnx(hash_blocked_ip_addresses,ip_address,0)
        return True
    except Exception as err:
        return err

def exists_ip_address(ip_address,vpn_type,REDIS_CLIENT):
    """ Checks if a given IP address exists in the blocked IP addresses hash table. """

    try:
        hash_blocked_ip_addresses = f'blocked_ip_addresses_mod_{vpn_type}'
        status = REDIS_CLIENT.hexists(hash_blocked_ip_addresses,ip_address)
        return status
    except Exception as err:
        return err

def del_ip_address(ip_address,vpn_type,REDIS_CLIENT):
    """ Deletes an IP address from the blocked IP addresses hash table. """
    try:
        hash_blocked_ip_addresses = f'blocked_ip_addresses_mod_{vpn_type}'
        REDIS_CLIENT.hdel(hash_blocked_ip_addresses,ip_address)
        return True
    except Exception as err:
        return err

def get_vpn_client_ip_address(vpn_type,REDIS_CLIENT):
    """ Obtains a valid IP address for an VPN client """
    try:
        result=0
        config = configparser.ConfigParser()
        config.read('config/config.ini')
        NETWORK_CIDR = config[vpn_type.upper()]['NETWORK_CIDR']

        maximum_attempts=len([str(ip) for ip in ipaddress.IPv4Network(NETWORK_CIDR)])
        while result < maximum_attempts:
            IP_ADDRESS=random.choice([str(ip) for ip in ipaddress.IPv4Network(NETWORK_CIDR)])
            if exists_ip_address(IP_ADDRESS,vpn_type,REDIS_CLIENT):
                result+=1
            else:
                add_ip_address(IP_ADDRESS,vpn_type,REDIS_CLIENT)
                return IP_ADDRESS
        return False
    except Exception as err:
        return err

def get_vpn_free_ip_address_space(vpn_type,REDIS_CLIENT):
    """ Returns True if there are free IPs to allocate. """

    try:
        config = configparser.ConfigParser()
        config.read('config/config.ini')
        NETWORK_CIDR = config[vpn_type.upper()]['NETWORK_CIDR']
        hash_blocked_ip_addresses = f'blocked_ip_addresses_mod_{vpn_type}'

        maximum_addresses=len([str(ip) for ip in ipaddress.IPv4Network(NETWORK_CIDR)])

        used_addresses=REDIS_CLIENT.hlen(hash_blocked_ip_addresses)

        free_addresses=maximum_addresses-used_addresses
        return free_addresses
    except Exception as err:
        return err

# PROFILE_NAME:IP_ADDRESS RELATIONSHIP
## We want to quickly obtain the IP from a profile name

hash_profile_name_ip_address='profile_name_ip_address'

def add_profile_ip_relationship(profile_name,ip_address,REDIS_CLIENT):
    """ Adds a profile:ip to the list. """
    try:
        REDIS_CLIENT.hsetnx(hash_profile_name_ip_address,profile_name,ip_address)
        return True
    except Exception as err:
        return err

def del_profile_ip_relationship(profile_name,REDIS_CLIENT):
    """ Deletes a profile:ip from the list. """
    try:
        REDIS_CLIENT.hdel(hash_profile_name_ip_address,profile_name)
        return True
    except Exception as err:
        return err

def get_ip_for_profile(profile_name,REDIS_CLIENT):
    """ Returns the IP address for a given profile name. """
    try:
        ip_address = REDIS_CLIENT.hget(hash_profile_name_ip_address,profile_name)
        return ip_address
    except Exception as err:
        return err

# PID:PROFILE_NAME RELATIONSHIP
## We want to quickly know which profile_name was associated with a defunct PID.
hash_pid_profile_name='pid_profile_name'

def add_pid_profile_name_relationship(pid,profile_name,REDIS_CLIENT):
    """ Adds a pid:profile_name to the list. """
    try:
        REDIS_CLIENT.hsetnx(hash_pid_profile_name,pid,profile_name)
        return True
    except Exception as err:
        return err

def del_pid_profile_name_relationship(pid,REDIS_CLIENT):
    """ Deletes a pid from the list. """
    try:
        REDIS_CLIENT.hdel(hash_pid_profile_name,pid)
        return True
    except Exception as err:
        return err

def get_pid_profile_name_relationship(pid,REDIS_CLIENT):
    """ Returns a profile_name from a given PID. """
    try:
        profile_name=REDIS_CLIENT.hget(hash_pid_profile_name,pid)
        return profile_name
    except Exception as err:
        return err

# PROFILE_NAME:PID RELATIONSHIP
## We want to stop the PID when de-provisioning a profile_name.
hash_profile_name_pid='profile_name_pid'

def add_profile_name_pid_relationship(profile_name,pid,REDIS_CLIENT):
    """ Adds a profile_name:pid to the list. """
    try:
        REDIS_CLIENT.hsetnx(hash_profile_name_pid,profile_name,pid)
        return True
    except Exception as err:
        return err

def del_profile_name_pid_relationship(profile_name,REDIS_CLIENT):
    """ Deletes a profile_name from the list. """
    try:
        REDIS_CLIENT.hdel(hash_profile_name_pid,profile_name)
        return True
    except Exception as err:
        return err

def get_profile_name_pid_relationship(profile_name,REDIS_CLIENT):
    """ Returns a pid from a given profile_name. """
    try:
        PID = REDIS_CLIENT.hget(hash_profile_name_pid,profile_name)
        return PID
    except Exception as err:
        return err

# PROFILE HANDLING
## The PROFILE_HANDLING are a series of functions associated with the
## generation on profile_names, storage, and other functions.

def gen_profile_name():
    """
    Generates a new profile_name based on a recipe.
    Profile name recipe: YYYYMMDDmmss_<word>_<word>
    """
    WORDS_JSON = 'common/words.json'
    try:
        # Import the word dictionary to be used for generating the profile_names
        with open(WORDS_JSON) as f:
            WORDS_DICT = json.load(f)

        string1 = random.choice(WORDS_DICT['data'])
        string2 = random.choice(WORDS_DICT['data'])
        date_now = time.strftime("%Y%m%d%H%M%S")
        profile_name = "{}-{}_{}".format(date_now, string1, string2)

        return profile_name
    except Exception as err:
        return err

hash_profile_names = "profile_names"
def add_profile_name(profile_name,msg_addr,REDIS_CLIENT):
    """ Stores the profile_name:msg_addr in Redis  """

    try:
        status = REDIS_CLIENT.hsetnx(hash_profile_names,profile_name,msg_addr)

        # status==1 if HSETNX created a field in the hash set
        # status==0 if the identity exists and no operation is done.
        return status
    except Exception as err:
        return err

def get_profile_name_address(profile_name,REDIS_CLIENT):
    """ Obtains a msg_addr given a profile_name """

    try:
        msg_addr = REDIS_CLIENT.hget(hash_profile_names,profile_name)
        return msg_addr
    except Exception as err:
        return err

def del_profile_name(profile_name,REDIS_CLIENT):
    """ Deletes a profile_name from Redis """

    try:
        REDIS_CLIENT.hdel(hash_profile_names,profile_name)
        return True
    except Exception as err:
        return err

### MAP profile_name:vpn_type for easy access
hash_profile_vpntypes = "profile_vpntype"

def add_profile_vpn_type(profile_name,msg_request,REDIS_CLIENT):
    """ Stores the profile_name:msg_request in Redis  """

    try:
        status = REDIS_CLIENT.hsetnx(hash_profile_vpntypes,profile_name,msg_request)

        # status==1 if HSETNX created a field in the hash set
        # status==0 if the identity exists and no operation is done.
        return status
    except Exception as err:
        return err

def get_profile_vpn_type(profile_name,REDIS_CLIENT):
    """ Obtains a msg_request for given a profile_name """

    try:
        msg_request = REDIS_CLIENT.hget(hash_profile_vpntypes,profile_name)
        return msg_request
    except Exception as err:
        return err

def del_profile_vpn_type(profile_name,REDIS_CLIENT):
    """ Deletes a profile_name vpn type from Redis """

    try:
        REDIS_CLIENT.hdel(hash_profile_vpntypes,profile_name)
        return True
    except Exception as err:
        return err

# FORCE EXPIRE QUEUE
## The force expire queue is a special redis queue where profiles get placed
## when we want to force them to expire before the expiration date arrived.

## We store simply the profile_name

def add_profile_to_force_expire(REDIS_CLIENT,profile_name):
    """ Function to add a new profile to the force expiration queue """

    try:
        redis_set = "force_expire_profile"
        score = time.time()

        # If new_request exists, ignore and do not update score.
        REDIS_CLIENT.zadd(redis_set,{profile_name:score},nx=True)
        return True
    except Exception as err:
        return err

def get_profile_to_force_expire(REDIS_CLIENT):
    """ Function to get a profile to expire from the queue """

    try:
        redis_set = "force_expire_profile"

        request = REDIS_CLIENT.zpopmin(redis_set,1)
        return request[0]
    except Exception as err:
        return err

def list_profiles_to_force_expire(REDIS_CLIENT):
    """ Function to list all profiles to expire from the queue """

    try:
        redis_set = "force_expire_profile"
        items_force_expire_queue = REDIS_CLIENT.zcard(redis_set)
        return items_force_expire_queue
    except Exception as err:
        return err

# PROVISIONING QUEUE
## The provisioning queue is where new requests are queued before being handled.
## We receive many types of requests, through many types of messaging apps.
## One client can do many requests.
## We store { "msg_id":45, "msg_type":"email", "msg_addr":"email@email.com", "msg_request":"openvpn" }

def add_item_provisioning_queue(REDIS_CLIENT,msg_id,msg_type,msg_addr,msg_request):
    """ Function to add an item to the provisioning_queue Redis SET"""

    try:
        redis_set = "provisioning_queue"
        score = time.time()

        # Build the JSON item to add to the set
        dataset = { "msg_id":int(msg_id), "msg_type":str(msg_type), "msg_addr":str(msg_addr), "msg_request":str(msg_request) }
        new_request = json.dumps(dataset)

        # If new_request exists, ignore and do not update score.
        REDIS_CLIENT.zadd(redis_set,{new_request:score},nx=True)

        return True
    except Exception as err:
        return err


def get_item_provisioning_queue(REDIS_CLIENT):
    """ Function to get the 'oldest' item (lowest score) from the
    provisioning_queue Redis SET. """

    try:
        redis_set = "provisioning_queue"
        request = REDIS_CLIENT.zpopmin(redis_set,1)
        return request[0]
    except Exception as err:
        return err

def list_items_provisioning_queue(REDIS_CLIENT):
    """ Retrieve all the items in the provisioning queue"""

    try:
        redis_set = "provisioning_queue"
        items_provisioning_queue = REDIS_CLIENT.zcard(redis_set)
        return items_provisioning_queue
    except Exception as err:
        return err

# ACTIVE PROFILES
## After the provisioning of profiles is completed, the active profiles are
## stored in the Redis hash table of 'active_profiles'. The profiles remain in
## this data structure unil the account is deprovisioned.

hash_active_profiles='active_profiles'
def add_active_profile(profile_name,REDIS_CLIENT):
    """ Adds a new active profile to the hash table. """
    try:
        creation_time=time.time()
        REDIS_CLIENT.hsetnx(hash_active_profiles,profile_name,creation_time)
        return True
    except Exception as err:
        return err

def get_active_profiles_keys(REDIS_CLIENT):
    """ Retrieve all the active profiles """

    try:
        list_of_active_profiles = REDIS_CLIENT.hkeys(hash_active_profiles)
        return list_of_active_profiles
    except Exception as err:
        return err

def get_active_profile_creation_time(profile_name,REDIS_CLIENT):
    """ Retrive the creation time (value) of a given profile name. """
    try:
        creation_time = REDIS_CLIENT.hget(hash_Active_profiles,profile_name)
        return creation_time
    except Exception as err:
        return err

def get_active_profiles_to_expire(EXPIRATION_THRESHOLD,REDIS_CLIENT):
    """ Find and return all accounts ready to expire given the Expiration_Threshold. """

    try:
        current_time = time.time()
        all_active_profiles = REDIS_CLIENT.hgetall(hash_active_profiles)
        result = {key for (key, value) in all_active_profiles.items() if ((current_time-float(value))/3600) > float(EXPIRATION_THRESHOLD)}
        # Expected output: {'20210412115031-neck_spooky', '20210309125031-neck_dog'}
        return result
    except Exception as err:
        return err

def exists_active_profile(profile_name,REDIS_CLIENT):
    """ Checks if a given profile name exists in the active profiles. """

    try:
        status = REDIS_CLIENT.hexists(hash_active_profiles,profile_name)
        return status
    except Exception as err:
        return err

def del_active_profile(profile_name,REDIS_CLIENT):
    """ Deletes a profile name from the active profiles. """
    try:
        REDIS_CLIENT.hdel(hash_active_profiles,profile_name)
        return True
    except Exception as err:
        return err

# EXPIRED PROFILES
## structure that keeps a history of expired profiles along with their creation
## and expiration times. Value:
expired_profiles_template = json.dumps({"creation_time":"","expiration_time":"","reported_time":"","deletion_time":""})

hash_expired_profiles='expired_profiles'
def add_expired_profile(profile_name,creation_time,REDIS_CLIENT):
    """ Function to add a profile into the list of expired profiles. """
    try:
        expiration_time=time.time()
        expiration_object = json.loads(expired_profiles_template)
        expiration_object['creation_time']=creation_time
        expiration_object['expiration_time']=expiration_time
        expiration_value=json.dumps(expiration_object)
        status = REDIS_CLIENT.hset(hash_expired_profiles,profile_name,expiration_value)

        return status
    except Exception as err:
        return err

def upd_reported_time_to_expired_profile(profile_name,REDIS_CLIENT):
    """ Function to add a profile into the list of expired profiles. """
    try:
        report_time=time.time()
        expiration_object = json.loads(expired_profiles_template)
        expiration_object['reported_time']=report_time
        expiration_value=json.dumps(expiration_object)
        status = REDIS_CLIENT.hset(hash_expired_profiles,profile_name,expiration_value)

        return status
    except Exception as err:
        return err

def del_expired_profile(profile_name,REDIS_CLIENT):
    """ Function to delete a profile from the list of expired profiles. """
    try:
        REDIS_CLIENT.hdel(hash_expired_profiles,profile_name)
        return True
    except Exception as err:
        return err

def get_expired_profile_information(profile_name,REDIS_CLIENT):
    """ Function to get a profile creation and expiration times from the list of expired profiles. """
    try:
        expiration_data = REDIS_CLIENT.hget(hash_expired_profiles,profile_name)
        return expiration_data
    except Exception as err:
        return err

def is_expired(profile_name,REDIS_CLIENT):
    """ Checks if the profile_name was expired. """
    try:
        status = REDIS_CLIENT.hexists(hash_expired_profiles,profile_name)
        # Returns a boolean indicating if key exists within hash name
        return status
    except Exception as err:
        return err

def get_expired_profiles_keys(REDIS_CLIENT):
    """ Retrieve all the expired profiles """

    try:
        list_of_expired_profiles = REDIS_CLIENT.hkeys(hash_expired_profiles)
        return list_of_expired_profiles
    except Exception as err:
        return err
# PROFILES TO REPORT
# Redis hash that keeps a list of profiles to report. Once reported, the report
# time is added to the expired_profiles information and the profile name is
# removed from here.
hash_profiles_to_report="profiles_to_report"

def add_profile_to_report(profile_name,REDIS_CLIENT):
    """ Adds a profile to the reports hash table. """
    try:
        REDIS_CLIENT.hsetnx(hash_profiles_to_report,profile_name,0)
        return True
    except Exception as err:
        return err

def exists_profile_to_report(profile_name,REDIS_CLIENT):
    """ Checks if a profile is in the reports hash table. """
    try:
        status = REDIS_CLIENT.hexists(hash_profiles_to_report,profile_name)
        return status
    except Exception as err:
        return err

def del_profile_to_report(profile_name,REDIS_CLIENT):
    """ Removes a profile from the reports hash table. """
    try:
        REDIS_CLIENT.hdel(hash_profiles_to_report,profile_name)
        return True
    except Exception as err:
        return err
