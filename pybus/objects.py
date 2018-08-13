import functools
import inspect
from pybus.message import Message
import pybus.pybus_struct
import pybus.types
import logging
import asyncio

logger = logging.getLogger(__name__)

def dbus_method(signature: str, return_signature: str, name: str=None, single_return_value=True):
    def dec(foo):
        method_name = name or foo.__name__
        foo._pybus_method_name = method_name
        foo._pybus_method_signature = signature
        foo._pybus_method_return_signature = return_signature
        foo._pybus_method_single_return = single_return_value
        return foo
    return dec


def dbus_signal(signature: str, name:str=None):
    def dec(foo):
        method_name = name or foo.__name__

        def _signal_wrapper(_self, obj, *args):
            assert isinstance(_self, DBusInterface)
            assert isinstance(obj, DBusObject)
            obj._bus.emit(obj.path, _self.name, method_name, signature, args)

        _signal_wrapper._pybus_signal_name = method_name
        _signal_wrapper._pybus_signal_signature = signature
        return _signal_wrapper
    return dec


class DBusInterface:
    name = None

    def __init__(self):
        self._dbus_methods = {}
        self._dbus_signals = []
        for i in inspect.getmembers(self.__class__, lambda x: hasattr(x, '_pybus_method_name')):
            self._dbus_methods[i[1]._pybus_method_name] = i[1]
        pass
        for i in inspect.getmembers(self.__class__, lambda x: hasattr(x, '_pybus_signal_name')):
            self._dbus_signals.append(i[1])

    def on_method_call(self, obj, msg: Message):
        if msg.member in self._dbus_methods:
            method = self._dbus_methods[msg.member]
            sig = method._pybus_method_return_signature
            args = [] if msg.payload is None else msg.payload
            ret = method(self, obj, *args)
            return pybus.types.enforce_type(ret, sig.encode())
        raise NotImplementedError('Unknown method %s, existing methods: %s' % (msg.member, self._dbus_methods.keys()))

    @property
    def methods(self):
        return list(self._dbus_methods.values())

    @property
    def signals(self):
        return list(self._dbus_signals)


class DBusObject:
    def __init__(self, conn, path):
        # type: (pybus.ManagedConnection)->None
        self._interfaces = {}
        if isinstance(conn, pybus.ClientConnection):
            self._bus = conn
        else:
            self._bus = conn._connection
        self._path = path

    @property
    def path(self):
        return self._path

    @property
    def interfaces(self):
        # type: ()->list[DBusInterface]
        return list(self._interfaces.values())

    def add_interface(self, iface):
        self._interfaces[iface.name] = iface

    def on_method_call(self, msg: Message):
        if msg.interface in self._interfaces:
            return self._interfaces[msg.interface].on_method_call(self, msg)
        raise NotImplementedError()


class ObjectManager:
    def __init__(self, bus):
        # type: (pybus.ClientConnection)->None
        # FIXME cyclic dependency :-/
        import pybus.freedesktop.introspect
        self._objects = {}
        self._bus = bus
        self.root_object = DBusObject(self._bus, '/')
        self.root_introspect = pybus.freedesktop.introspect.IntrospectInterface()
        self.root_object.add_interface(self.root_introspect)
        self.register_object(self.root_object)

    def register_object(self, obj: DBusObject):
        self._objects[obj.path] = obj
        self.root_introspect.child_objects.append(obj.path)

    async def send_return_async(self, method_call: pybus.message.Message, ret: pybus.types.enforce_type):
        try:
            ret._value = await ret.value
            self.send_return(method_call, ret)
        except Exception as ex:
            logger.exception("Exception during method call %s", method_call)
            self.send_error(method_call, ex)

    def send_error(self, method_call: pybus.message.Message, exc: Exception):
        err = pybus.Message()
        err.message_type = pybus.MessageType.ERROR
        err.destination = method_call.sender
        err.error_name = 'space.equi.pybus.Error.%s' % exc.__class__.__name__
        err.reply_serial = method_call.serial
        err.signature = 's'
        err.payload = (repr(exc),)
        logger.warning("Sending an error %s as a response to %s", err, method_call)
        self._bus.send_message(err)

    def send_return(self, method_call: pybus.message.Message, ret):
        if isinstance(ret, pybus.types.enforce_type):
            signature = ret.signature
            ret = ret._value
        else:
            signature = pybus.types.guess_signature(ret)
            logger.warning("Had to guess the signature, got %s for %r", signature, ret)
        ret_msg = pybus.Message()
        ret_msg.message_type = pybus.MessageType.METHOD_RETURN
        ret_msg.destination = method_call.sender
        ret_msg.reply_serial = method_call.serial
        ret_msg.signature = signature
        ret_msg.payload = ret
        logging.warning("Sending return value %s as a response to %s", ret_msg, method_call)
        self._bus.send_message(ret_msg)

    def handle_call(self, msg: pybus.message.Message):
        ret = None
        try:
            if msg.path in self._objects:
                ret = self._objects[msg.path].on_method_call(msg)      # type: pybus.types.enforce_type
                if isinstance(ret.value, asyncio.Future) or inspect.iscoroutine(ret.value):
                    asyncio.ensure_future(self.send_return_async(msg, ret))
                else:
                    self.send_return(msg, ret)
            else:
                raise NotImplementedError("Unknown path: %s, possible paths: %s" % (msg.path, sorted(self._objects.keys())))
        except Exception as ex:
            logging.exception('')
            self.send_error(msg, ex)
            pass

