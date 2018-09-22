import asyncio
import logging
import debus.types
from debus.wire import WireConnection
import debus.objects
from .message import Message, make_mesage, MessageType, HeaderField
from lxml import etree
import io

try:
    import typing
    if typing.TYPE_CHECKING:
        StringOrBytes = typing.Union[str, bytes]
except:
    pass

logger = logging.getLogger(__name__)

class DBusError(RuntimeError):
    pass


class DBusMethod:
    def __init__(self, obj, iface, name, signature, output):
        # type: (IntrospectedObject, IntrospectedInterface, str, str, str) -> None
        self.obj = obj
        self.iface = iface
        self.name = name
        self.signature = signature
        self.signature_out = output

    def __call__(self, *args, **kwargs):
        return self.obj.bus.call(self.obj.bus_name, self.obj.object_path, self.iface.name, self.name, self.signature, args)

    def __str__(self):
        return '[%s].%s(%r)->%r' % (self.iface.name, self.name, self.signature, self.signature_out)


class IntrospectedSignal:
    def __init__(self, obj, iface, name, signature):
        self.obj = obj
        self.iface = iface
        self.name = name
        self.signature = signature

    def __str__(self):
        return '[%s].%s (%s)' % (self.iface.name, self.name, self.signature)


class IntrospectedInterface:
    def __init__(self, name):
        self.name = name
        self.signals = {}
        self.methods = {}

    def __getattr__(self, item):
        if item in self.methods:
            return self.methods[item]
        raise AttributeError(item)


class IntrospectedObject:
    def __init__(self, bus, bus_name, object_path, introspect_result):
        # type: (ClientConnection, str, str, str) -> None
        self.bus = bus              # type: ClientConnection
        self.bus_name = bus_name
        self.object_path = object_path
        self.interfaces = {}    # type: typing.Dict[str, IntrospectedInterface]
        tree = etree.parse(io.StringIO(introspect_result))
        for interface_node in tree.xpath('/node/interface'):
            interface = IntrospectedInterface(interface_node.get('name'))
            self.interfaces[interface.name] = interface
            for method_node in interface_node.xpath('./method'):
                signature_in = ''.join(method_node.xpath("./arg[@direction='in']/@type"))
                signature_out = ''.join(method_node.xpath("./arg[@direction='out']/@type"))
                method_name = method_node.get('name')
                method_obj = DBusMethod(self, interface, method_name, signature_in, signature_out)
                interface.methods[method_name] = method_obj

            for sig_node in interface_node.xpath('./signal'):
                args = ''.join(sig_node.xpath("./arg/@type"))
                name = sig_node.get('name')
                signal = IntrospectedSignal(self, interface, name, ''.join(args))
                interface.signals[name] = signal

    def log(self, logger):
        logger.warning('DBus object %s on %s:', self.object_path, self.bus_name)
        for ifname in sorted(self.interfaces):
            ifobj = self.interfaces[ifname]
            logger.warning("  Interface %s (%d methods, %d signals)", ifname, len(ifobj.methods), len(ifobj.signals))
            for mname in sorted(ifobj.methods):
                logger.warning("    %s", ifobj.methods[mname])
            for sname in sorted(ifobj.signals):
                logger.warning("    %s", ifobj.signals[sname])


async def get_freedesktop_interface(conn, name=None):
    # type: (debus.connection.ClientConnection, str) -> debus.connection.DBusInterface
    if name:
        name = 'org.freedesktop.DBus.%s' % name
    else:
        name = 'org.freedesktop.DBus'
    return await conn.get_object_interface('org.freedesktop.DBus', '/org/freedesktop/DBus', name)


class ClientConnection:
    def __init__(self, socket=None, uri=None):
        self._wire = WireConnection(socket=socket, uri=uri)
        self._futures = {}       # type: typing.Dict[int, asyncio.Future]
        self._freedesktop_interface = None

    async def connect(self):
        await self._wire.connect_and_auth()
        asyncio.ensure_future(self.run())
        await self.call('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'Hello', '', None)
        self._freedesktop_interface = await get_freedesktop_interface(self)

    async def run(self):
        while True:
            msgs = await self._wire.recv()
            for msg in msgs:
                try:
                    self.process_message(msg)
                except:
                    logger.exception("Failed to process message %s", msg)

    def process_message(self, msg: Message):
        mt = msg.message_type
        if mt in [MessageType.METHOD_RETURN, MessageType.ERROR]:
            reply_to = msg.reply_serial
            if reply_to in self._futures:
                logger.info("Got response to %d", reply_to)
                f = self._futures.pop(reply_to)  # type: asyncio.Future
                if mt == MessageType.METHOD_RETURN:
                    f.set_result(msg.payload)
                else:
                    f.set_exception(DBusError(msg.payload))
                return
            else:
                logging.warning("Received unexpected response message: %s", msg)
        elif mt == MessageType.SIGNAL:
            self.process_signal(msg)
        elif mt == MessageType.METHOD_CALL:
            self.process_method_call(msg)
        else:
            logger.error("Don't know what to do with this: %s", msg)

    def process_signal(self, msg):
        logger.error("Received a signal: %s", msg)

    def process_method_call(self, msg):
        logger.error("Received a method call: %s, don't know what to do, sending NotImplemented error", msg)
        err = Message()
        err.message_type = MessageType.ERROR
        err.headers[HeaderField.DESTINATION] = msg.headers[HeaderField.SENDER]
        err.headers[HeaderField.REPLY_SERIAL] = debus.types.enforce_type(msg.serial, b'u')
        err.headers[HeaderField.ERROR_NAME] = 'space.equi.debus.Error.NotImplemented'
        self.send_message(err)

    def call(self, bus_name, object_path, interface_name, method, signature=None, args=None, timeout=None):
        # type: (str, str, str, str, str, typing.Any, float) -> typing.Any

        msg = make_mesage(MessageType.METHOD_CALL, bus_name, interface_name, method, object_path, signature, args)
        f = asyncio.Future()
        self._futures[msg.serial] = f
        logger.info("Sending method call: %s", msg)
        if timeout:
            def on_timeout():
                if not f.done():
                    f.set_exception(TimeoutError("Method call timed out: %s.%s" % (interface_name, method)))
            asyncio.get_event_loop().call_later(timeout, on_timeout)
        self.send_message(msg)
        return f

    def emit(self, object_path: str, interface_name: str, signal_name: str, signature=None, args=None):
        msg = Message()
        msg.message_type = MessageType.SIGNAL
        msg.interface = interface_name
        msg.path = object_path
        msg.member = signal_name
        if not signature is None:
            assert args
            msg.signature = signature
            msg.payload = args
        # print(msg)
        logger.warning("Going to send %s", msg)
        self.send_message(msg)

    def send_message(self, msg: Message):
        self._wire.send(msg)

    async def introspect(self, bus_name, object_path):
        logger.info("Introspecting %s %s", bus_name, object_path)
        result = await self.call(bus_name, object_path, 'org.freedesktop.DBus.Introspectable', 'Introspect', timeout=10)
        obj = IntrospectedObject(self, bus_name, object_path, result[0])
        return obj

    async def get_object_interface(self, bus_name, object_path, interface) -> IntrospectedInterface:
        return (await self.introspect(bus_name, object_path)).interfaces[interface]

    async def request_name(self, name: str):
        await self._freedesktop_interface.RequestName(name, 0)

    @property
    def freedesktop_interface(self):
        return self._freedesktop_interface


class ManagedConnection(ClientConnection):
    def __init__(self, uri):
        super().__init__(uri=uri)
        self._sub_mgr = debus.subscription.SubscriptionManager(self)
        self._obj_mgr = debus.objects.ObjectManager(self)

    def process_signal(self, msg):
        return self._sub_mgr.handle_message(msg)

    def process_method_call(self, msg):
        return self._obj_mgr.handle_call(msg)

    @property
    def sub_mgr(self):
        return self._sub_mgr

    @property
    def obj_mgr(self):
        return self._obj_mgr
