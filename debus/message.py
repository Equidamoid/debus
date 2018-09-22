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

def _str_field_property(field: HeaderField, cast_to=None):
    def getter(msg):
        ret = msg.headers.get(field, None)
        return ret

    def setter(msg, value):
        if value is None:
            deleter(msg)
        else:
            if cast_to:
                value = cast_to(value)
            msg.headers[field] = value

    def deleter(msg):
        del msg.headers[field]

    return getter, setter, deleter

class Message:
    member = property(*_str_field_property(HeaderField.MEMBER))
    interface = property(*_str_field_property(HeaderField.INTERFACE))
    sender = property(*_str_field_property(HeaderField.SENDER))
    destination = property(*_str_field_property(HeaderField.DESTINATION))
    error_name = property(*_str_field_property(HeaderField.ERROR_NAME))
    path = property(*_str_field_property(HeaderField.PATH, types.ObjectPath))
    signature = property(*_str_field_property(HeaderField.SIGNATURE, types.Signature))

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

    @property
    def reply_serial(self) -> int:
        v = self.headers[HeaderField.REPLY_SERIAL]
        if isinstance(v, types.enforce_type):
            v = v.value
        return v

    @reply_serial.setter
    def reply_serial(self, v: int):
        if v:
            self.headers[HeaderField.REPLY_SERIAL] = types.enforce_type(v, b'u')
        else:
            del self.reply_serial

    @reply_serial.deleter
    def reply_serial(self):
        del self.headers[HeaderField.REPLY_SERIAL]


def make_mesage(m_type: MessageType,
                bus_name: str,
                interface_name: str,
                member: str,
                object_path: str,
                signature: str=None,
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