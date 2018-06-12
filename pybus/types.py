from pathlib import Path


class DBusType:
    signature = None


class Signature(bytes, DBusType):
    signature = b'g'


class ObjectPath(bytes, DBusType):
    signature = b'o'


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
