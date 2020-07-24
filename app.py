#!/usr/bin/env python
import os
import json
import redis
import logging
from typing import *
import msgpack
from dotenv import load_dotenv

from crypto.reader import ChannelReader
from crypto.manager import ChannelManager
from crypto.channel import Channel

from crypto.data_pkg import EncryptedDataPackage


logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)
logger = logging.getLogger('WORKER:')


load_dotenv()

# OR, the same with increased verbosity
load_dotenv(verbose=True)

# OR, explicitly providing path to '.env'
from pathlib import Path  # Python 3.6+ only
env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)


class App(object):
    """
    Microservice which encrypts / decrypts messages using NuCypher
    """
    def __init__(self):

        import sys
        sys.stdout = sys.stderr

        print(os.getenv("REDIS_PORT"))

        # Setting up Redis connection
        self.redis = redis.Redis(host=os.getenv("REDIS_HOST"),
                                 port=os.getenv("REDIS_PORT"),
                                 username=os.getenv("REDIS_USER"),
                                 password=os.getenv("REDIS_PASSWORD"))

        self.pubsub_to_exchange = self.redis.pubsub()
        self.pubsub_to_exchange.subscribe(os.getenv("ENCRYPT_QUEUE"))

        self.pubsub_from_exchange = self.redis.pubsub()
        self.pubsub_from_exchange.subscribe(os.getenv("DECRYPT_QUEUE"))

        # Get a ChannelManager instance. For this version, Channel manager uses Singleton pattern
        self.manager = ChannelManager()
        self.channel = self.manager.create_new_channel()

        # Creating ChannelReader
        self.reader = ChannelReader()
        self.public_reader = self.reader.get_public_reader()
        self.public_reader_human = self.public_reader.to_human()

        # Grant access to specific ChannelReader for Channel
        self.manager.grant(self.public_reader, self.channel)

    def run(self) -> NoReturn:
        """
        Main cycle for Redis messages
        """
        print("Running worker with redis queue")
        while True:

            # Checking to exchange
            message = self.pubsub_to_exchange.get_message()
            if message and message['type'] == 'message':
                logger.info("MESSAGE RECEIVED: " + repr(message))
                data = json.loads(message['data'])
                if 'uuid' in data:
                    uuid = data.pop('uuid')
                    commit_number = data.pop('commitNumber')
                    logger.info("UUID" + str(uuid))
                    encrypted_body = self.encrypt(data)
                    encrypted_dict = {"uuid": uuid, "commitNumber": commit_number, "body": encrypted_body}
                    logger.info("Message was successfully encrypted " + repr(encrypted_dict))
                    self.redis.publish("to_exchange_encrypted", json.dumps(encrypted_dict))

            message = self.pubsub_from_exchange.get_message()
            if message and message['type'] == 'message':
                logger.info("MESSAGE RECEIVED: " + repr(message))
                data = json.loads(message['data'])
                if 'uuid' in data:
                    uuid = data.pop('uuid')
                    commit_number = data.pop('commitNumber')
                    logger.info("UUID" + str(uuid))
                    encrypted_msg = bytes.fromhex(data['body'])
                    decrypted_commit = self.decrypt(encrypted_msg)
                    if decrypted_commit:
                        decrypted_commit['uuid'] = uuid
                        decrypted_commit['commitNumber'] = commit_number
                        logger.info("Message was successfully decrypted " + repr(decrypted_commit))
                        self.redis.publish("from_exchange_decrypted", json.dumps(decrypted_commit))
                    else:
                        logger.warning("Unable to decrypt!")

    def encrypt(self, data: dict) -> str:
        """
        Encrypt message into human readable format
        :param data:
        :return: hex representation of encrypted message
        """
        try:
            msg = msgpack.dumps(data)
            encrypted_data_package = EncryptedDataPackage.from_channel(self.channel, msg)
            bytes_data = encrypted_data_package.to_bytes()
            return bytes_data.hex()

        except ValueError:
            return ""

    def decrypt(self, encrypted_msg: bytes) -> dict:
        """
        Decrypt messages
        :return: encrypted message
        """
        try:
            received_data_package = EncryptedDataPackage.from_bytes(encrypted_msg)
            retrieved_bytes = received_data_package.decrypt(self.reader)
            retrieved_text = msgpack.loads(retrieved_bytes[0], encoding="utf-8")
            return retrieved_text

        except Exception as e:
            logger.critical(e)


if __name__ == '__main__':
    app = App()
    app.run()
