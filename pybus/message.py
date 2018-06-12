import enum
import typing
from . import types


class MessageType(enum.IntEnum):
    INVALID = 0
    METHOD_CALL = 1
    METHOD_RETURN = 2
    ERROR = 3
    SIGNAL = 4


class HeaderField(enum.IntEnum):
    INVALID = 0
    PATH = 1
    INTERFACE = 2
    MEMBER = 3
    ERROR_NAME = 4
    REPLY_SERIAL = 5
    DESTINATION = 6
    SENDER = 7
    SIGNATURE = 8
    UNIX_FDS = 9

_next_serial = 0
def next_serial():
    global _next_serial
    _next_serial += 1
    return _next_serial


class Message:
    def __init__(self):
        self.headers = {}                                   # type: typing.Dict[HeaderField, object]
        self.message_type = None                             # type: MessageType
        self.payload = None
        self.serial = 1
        self.flags = 0


    def __str__(self):
        return 'Message(%s, %s, %s)' % (self.message_type, self.headers, self.payload)


def make_method_call(bus_name, interface_name, method_name, object_path, signature=None):
    m = Message()
    m.message_type = MessageType.METHOD_CALL
    m.serial = 10
    m.headers[HeaderField.DESTINATION] = bus_name
    m.headers[HeaderField.INTERFACE] = interface_name
    if signature:
        m.headers[HeaderField.SIGNATURE] = types.Signature(signature)
    m.headers[HeaderField.PATH] = types.ObjectPath(object_path)
    m.headers[HeaderField.MEMBER] = method_name
    m.serial = next_serial()
    return m