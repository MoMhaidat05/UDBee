import struct, os

def build_stun_attribute(message):
    if type(message) is not bytes:
        message = message.encode('utf-8')

    length = len(message)
    attr_type = 0x8022 # Unknown attribute type, to evade detection
    padded_length = (length + 3) & ~3  # Round up to the nearest multiple of 4
    padding = b'\x00' * (padded_length  - length)
    attribute = struct.pack('!HH', attr_type, length) + message + padding
    return attribute


def build_stun_message(message):
    message_type = 0x0001 # Binding Request
    magic_cookie = 0x2112A442
    transaction_id = os.urandom(12) # Random 12-byte transaction ID
    attribute = build_stun_attribute(message)
    attribute_length = len(attribute)
    header = struct.pack('!HHI12s', message_type, attribute_length, magic_cookie, transaction_id)
    pack = header + attribute
    return pack