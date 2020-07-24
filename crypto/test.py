import time
from .channel import Channel
from .data_pkg import EncryptedDataPackage
from .manager import ChannelManager
from .reader import ChannelReader


def test_crypto():
    # Get a ChannelManager instance. For this version, Channel manager uses Singleton pattern
    manager = ChannelManager()
    channel = manager.create_new_channel()

    # Creating ChannelReader
    reader = ChannelReader()
    reader_public = reader.get_public_reader()

    print(reader_public.to_human())
    # Grant access to specific ChannelReader for Channel
    manager.grant(reader_public, channel)

    # Serialize channels data into JSON to transfer
    channel_bytes = channel.to_bytes()

    # Restore channel data from JSON
    channel_received = Channel.from_bytes(channel_bytes)

    startTime = time.time()
    # Text & bytes information which we are going to send
    plaintext = "TESTing NuCypher Networks "
    plaintext_bytes = plaintext.encode("UTF-8")

    # Creating
    encrypted_data_package = EncryptedDataPackage.from_channel(channel_received, plaintext_bytes)
    json_data = encrypted_data_package.to_bytes()

    # Transferring JSON

    # Decrypt original message
    received_data_package = EncryptedDataPackage.from_bytes(json_data)
    retrieved_plaintexts = received_data_package.decrypt(reader)

    endTime = time.time()
    print("Duration: ", endTime - startTime)
    retrieved_text = retrieved_plaintexts[0].decode("UTF-8")
    print(retrieved_text + "vs" + plaintext)
    assert retrieved_text == plaintext