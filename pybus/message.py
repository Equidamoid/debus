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
        return 'Message(%s, [%s], %s)' % (
            self.message_type,
            ', '.join(['%s=%s' % (k.name, self.headers[k]) for k in sorted(self.headers)]),
            self.payload)


def make_mesage(m_type: MessageType,
                bus_name: bytes,
                interface_name: bytes,
                member: bytes,
                object_path: bytes,
                signature: bytes=None,
                data=None) -> Message:
    ret = Message()
    ret.message_type = m_type
    if not bus_name is None:
        ret.headers[HeaderField.DESTINATION] = bus_name
    if not interface_name is None:
        ret.headers[HeaderField.INTERFACE] = interface_name
    if signature is None:
        assert data is None
    else:
        ret.headers[HeaderField.SIGNATURE] = types.Signature(signature)
        ret.payload = data
    if not object_path is None:
        ret.headers[HeaderField.PATH] = types.ObjectPath(object_path)
    if not member is None:
        ret.headers[HeaderField.MEMBER] = member
    ret.serial = next_serial()
    return ret