import redis

def redis_connect_to_db(REDIS_SERVER):
    """ Function to connect to a Redis database. Returns object publisher. """
    try:
        publisher = redis.Redis(REDIS_SERVER, port=6379, db=0)
        return publisher
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
    """ Function to subscribe a subscriber object to a given Redis channel"""
    try:
        subscriber.subscribe(CHANNEL)
        return True
    except Exception as err:
        return err
