from pathlib import Path


class DBusType:
    signature = None


class Signature(bytes, DBusType):
    signature = b'g'

    def __new__(cls, arg):
        if isinstance(arg, str):
            arg = arg.encode('utf-8')
        return super().__new__(cls, arg)

    __str__ = bytes.decode


class ObjectPath(bytes, DBusType):
    signature = b'o'

    def __new__(cls, arg):
        if isinstance(arg, str):
            arg = arg.encode('utf-8')
        if arg[0] != ord(b'/') or b'//' in arg:
            raise ValueError("Invalid object path: %s" % arg)
        return super().__new__(cls, arg)

    __str__ = bytes.decode

class enforce_type:
    """
    To be used as a function, like `call_with_variant_argument(enforce_type(b'u', 42))`, thus function-style name
    """
    def __init__(self, value, signature: bytes):
        assert isinstance(signature, bytes)
        self._value = value
        self._signature = signature

    @property
    def signature(self):
        return self._signature

    @property
    def value(self):
        return self._value

    def __repr__(self):
        return '<enforce_type[%s](%r)>' % (self.signature.decode(), self._value)


def guess_signature(arg):
    ret = None
    if isinstance(arg, DBusType):
        return arg.signature
    elif isinstance(arg, int):
        ret = b'i'
    elif isinstance(arg, float):
        ret = b'd'
    elif isinstance(arg, Path):
        ret = b'o'
    elif isinstance(arg, str):
        ret = b's'
    elif isinstance(arg, bytes):
        ret = b's'
    elif isinstance(arg, list):
        ret = b'a' + guess_signature(arg[0])
    elif isinstance(arg, tuple):
        ret = b'('
        for i in arg:
            ret += guess_signature(i)
        ret += b')'
    else:
        raise ValueError("Can't guess dbus type for %s" % (type(arg),))
    return ret
