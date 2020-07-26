#!/usr/bin/env python
import os
import logging
import msgpack
from dotenv import load_dotenv
from flask import Flask, request, jsonify

from crypto.reader import ChannelReader, ChannelReaderPublic
from crypto.manager import ChannelManager

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

# Get a ChannelManager instance. For this version, Channel manager uses Singleton pattern
manager = ChannelManager()
channel = manager.create_new_channel()

# Creating ChannelReader
reader = ChannelReader()
public_reader = reader.get_public_reader()
public_reader_human = public_reader.to_json()


# Flask setup
app = Flask(__name__)
gunicorn_logger = logging.getLogger('gunicorn.error')
app.logger.handlers = gunicorn_logger.handlers
app.logger.setLevel(gunicorn_logger.level)

# Returns public reader key
@app.route('/reader')
def reader_key():
    return public_reader_human


# Grant key
@app.route('/grant', methods=['POST'])
def grant_access():
    data = request.json
    print("=-==-=")
    print(data)
    p_reader = ChannelReaderPublic(signing_power_bytes=bytes.fromhex(data['signing_power']),
                                 decrypt_power_bytes=bytes.fromhex(data['decrypt_power']))
    manager.grant(p_reader, channel)
    return "ok"


# Ecnrypt message to channel
@app.route('/encrypt', methods=['POST'])
def encrypt():
    """
    Encrypt message into human readable format
    :param data:
    :return: hex representation of encrypted message
    """
    content = request.json
    data = content['data']
    print(data)

    try:
        msg = msgpack.dumps(data)
        encrypted_data_package = EncryptedDataPackage.from_channel(channel, msg)
        bytes_data = encrypted_data_package.to_bytes()
        return bytes_data.hex()

    except ValueError:
        return ""


# Decrypt message from channel
@app.route('/decrypt', methods=['POST'])
def decrypt() -> dict:
    """
    Decrypt messages
    :return: encrypted message

    """
    content = request.json
    data = content['data']
    print(data)

    encrypted_msg = bytes.fromhex(data)

    try:
        received_data_package = EncryptedDataPackage.from_bytes(encrypted_msg)
        retrieved_bytes = received_data_package.decrypt(reader)
        retrieved_text = msgpack.loads(retrieved_bytes[0], encoding="utf-8")
        return retrieved_text

    except Exception as e:
        logger.critical(e)
        return "Cant decrupt"


if __name__ == '__main__':
    app.run(port=os.getenv('PORT', 5000))


