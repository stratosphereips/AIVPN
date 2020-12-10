def redis_connect_to_db(REDIS_SERVER):
    try:
        publisher = redis.Redis(REDIS_SERVER, port=6379, db=0)
        return publisher
    except Exception as err:
        return err

def redis_create_subscriber(publisher):
    try:
        subscriber = publisher.pubsub()
        return subscriber
    except Exception as err:
        return err

def redis_subscribe_to_channel(subscriber,CHANNEL):
    try:
        subscriber.subscribe(CHANNEL)
        return True
    except Exception as err:
        return err

