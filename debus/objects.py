import inspect
from debus.message import Message
import debus.pybus_struct
import debus.types
import logging
import asyncio
import typing

logger = logging.getLogger(__name__)

class MethodInfo:
    def __init__(self, name, in_signature, out_signature, single_return):
        self.name: str = name
        self.in_signature: str = in_signature
        self.out_signature: str = out_signature
        self.single_return: bool = single_return

class SignalInfo:
    def __init__(self, name, arg_names, signature):
        self.name: str = name
        self.argument_names: typing.List[str] = arg_names
        self.signature: str = signature

class PropertyInfo:
    def __init__(self, name, readonly):
        self.name: str = name
        self.readonly: bool = readonly

def dbus_method(signature: str, return_signature: str, name: str=None, single_return_value=True):
    def dec(foo):
        method_name = name or foo.__name__
        foo._pybus_method = MethodInfo(method_name, signature, return_signature, single_return_value)
        return foo
    return dec


def dbus_signal(signature: str, name:str=None, arg_names:list=None):
    def dec(foo):
        method_name = name or foo.__name__
        _arg_names = arg_names
        if _arg_names is None:
            _arg_names = list(list(inspect.signature(foo).parameters)[1:])
        def _signal_wrapper(_self, *args):
            assert isinstance(_self, DBusInterface)
            _self._obj._bus.emit(_self._obj.path, _self.name, method_name, signature, args)
        _signal_wrapper._pybus_signal = SignalInfo(method_name, _arg_names, signature)
        return _signal_wrapper
    return dec


def dbus_property(signature: str, name:str=None):
    def dec(prop):
        prop._pybus_property = PropertyInfo(name, hasattr(prop, 'fset'))
        return prop
    return dec

class DBusInterface:
    name = None

    def __init__(self):
        self._dbus_methods = {}
        self._dbus_properties = {}
        self._dbus_signals = []
        self._obj: 'DBusObject' = None
        for name, m in inspect.getmembers(self.__class__, lambda x: hasattr(x, '_pybus_method')):
            self._dbus_methods[m._pybus_method.name] = m
        for name, p in inspect.getmembers(self.__class__, lambda x: hasattr(x, '_pybus_property')):
            # properties don't know their names
            p._pybus_property.name = p._pybus_property.name or name
            self._dbus_properties[p._pybus_property.name] = p
        for i in inspect.getmembers(self.__class__, lambda x: hasattr(x, '_pybus_signal')):
            self._dbus_signals.append(i[1])
    def set_object(self, obj: 'DBusObject'):
        self._obj = obj

    def on_method_call(self, msg: Message):
        if msg.member in self._dbus_methods:
            method = self._dbus_methods[msg.member]
            spec: MethodInfo = method._pybus_method
            args = [] if msg.payload is None else msg.payload
            ret = method(self, *args)
            return debus.types.enforce_type(ret, spec.out_signature.encode())
        raise NotImplementedError('Unknown method (%s.)%s, existing methods: %s' % (self.name, msg.member, self._dbus_methods.keys()))

    @property
    def methods(self):
        return list(self._dbus_methods.values())

    @property
    def signals(self):
        return list(self._dbus_signals)

    @property
    def properties(self):
        return list(self._dbus_properties)


class DBusObject:
    def __init__(self, conn, path):
        # type: (debus.ManagedConnection)->None
        self._interfaces = {}
        if isinstance(conn, debus.ClientConnection):
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

    def add_interface(self, iface: DBusInterface):
        self._interfaces[iface.name] = iface
        iface.set_object(self)

    def on_method_call(self, msg: Message):
        if msg.interface in self._interfaces:
            return self._interfaces[msg.interface].on_method_call(msg)
        raise NotImplementedError("Interface %r is not supported by object %r" % (msg.interface, self.path))


class ObjectManager:
    def __init__(self, bus):
        # type: (debus.ClientConnection)->None
        # FIXME cyclic dependency :-/
        import debus.freedesktop.introspect
        self._objects = {}
        self._bus = bus
        self.root_object = DBusObject(self._bus, '/')
        self.root_introspect = debus.freedesktop.introspect.IntrospectInterface()
        self.root_object.add_interface(self.root_introspect)
        self.register_object(self.root_object)

    def register_object(self, obj: DBusObject):
        self._objects[obj.path] = obj
        self.root_introspect.child_objects.append(obj.path)

    async def send_return_async(self, method_call: debus.message.Message, ret: debus.types.enforce_type):
        try:
            ret._value = await ret.value
            self.send_return(method_call, ret)
        except Exception as ex:
            logger.exception("Exception during method call %s", method_call)
            self.send_error(method_call, ex)

    def send_error(self, method_call: debus.message.Message, exc: Exception):
        err = debus.Message()
        err.message_type = debus.MessageType.ERROR
        err.destination = method_call.sender
        err.error_name = 'space.equi.debus.Error.%s' % exc.__class__.__name__
        err.reply_serial = method_call.serial
        err.signature = 's'
        err.payload = (repr(exc),)
        logger.warning("Sending an error %s as a response to %s", err, method_call)
        self._bus.send_message(err)

    def send_return(self, method_call: debus.message.Message, ret):
        if isinstance(ret, debus.types.enforce_type):
            signature = ret.signature
            ret = ret._value
        else:
            signature = debus.types.guess_signature(ret)
            logger.warning("Had to guess the signature, got %s for %r", signature, ret)
        ret_msg = debus.Message()
        ret_msg.message_type = debus.MessageType.METHOD_RETURN
        ret_msg.destination = method_call.sender
        ret_msg.reply_serial = method_call.serial
        ret_msg.signature = signature
        ret_msg.payload = ret
        logging.warning("Sending return value %s as a response to %s", ret_msg, method_call)
        self._bus.send_message(ret_msg)

    def handle_call(self, msg: debus.message.Message):
        try:
            path = str(msg.path)
            if path in self._objects:
                ret = self._objects[path].on_method_call(msg)      # type: debus.types.enforce_type
                if isinstance(ret.value, asyncio.Future) or inspect.iscoroutine(ret.value):
                    asyncio.ensure_future(self.send_return_async(msg, ret))
                else:
                    self.send_return(msg, ret)
            else:
                raise NotImplementedError("Unknown path: %s, possible paths: %r" % (path, sorted(self._objects.keys())))
        except Exception as ex:
            logging.exception('Failed to process message %s', msg)
            self.send_error(msg, ex)
            pass

