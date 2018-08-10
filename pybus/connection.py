import asyncio
import logging
import binascii
import os
import pybus.types
from .pybus_struct import InputBuffer, OutputBuffer
from .message import Message, make_mesage, MessageType, HeaderField
logger = logging.getLogger(__name__)
from lxml import etree
import io
import inspect
try:
    import typing
    StringOrBytes = typing.Union[str, bytes]
except:
    pass
from pathlib import Path
import hashlib


class BusConnection:
    def __init__(self, socket=None, uri=None):
        assert (socket is None) != (uri is None)
        self.reader = None          # type: asyncio.StreamReader
        self.writer = None          # type: asyncio.StreamWriter
        self.parser = InputBuffer()
        self.server_guid = None     # type: bytes
        if uri:
            kind, params = uri.split(':')
            params = {k:v for k,v in [i.split('=') for i in params.split(',')]}
            logger.warning("Uri %r parsed, have to connect via %s with parameters %s", uri, kind, params)
            if kind == 'tcp':
                socket = (params['host'], int(params['port']))
            elif kind == 'unix':
                socket = params['path']
        self.socket_path = socket

    async def _check_auth_result(self):
        result = (await self.reader.readline())
        result_parts = result.split()
        status = result_parts[0]
        logger.warning("Auth result: %r", result)
        if status == b'OK':
            self.server_guid = binascii.unhexlify(result_parts[1])
            logger.warning("Auth ok, server guid: %s", self.server_guid)
            return True
        return False

    async def _do_auth_external(self):
        logger.warning("Attempting external auth")
        self.writer.write(b"AUTH EXTERNAL %s\r\n" % binascii.hexlify(os.environ['USER'].encode()))
        return await self._check_auth_result()

    async def _do_auth_anonymous(self):
        logger.warning("Attempting anonymous auth")
        self.writer.write(b"AUTH ANONYMOUS\r\n")
        return await self._check_auth_result()

    async def _do_auth_cookie(self):
        self.writer.write(b"AUTH DBUS_COOKIE_SHA1 %s\r\n" % binascii.hexlify(os.environ['USER'].encode()))
        resp = await self.reader.readline()
        resp_parts = resp.split()
        if resp_parts[0] == b'REJECTED':
            logger.warning("Dbus cookie auth rejected")
            return False
        elif resp_parts[0] == b'DATA':
            s_cookie_context, s_cookie_id, s_challenge = binascii.unhexlify(resp_parts[1]).split()
            cookie_file = Path(os.path.expanduser('~/.dbus-keyrings')) / s_cookie_context.decode()
            logger.warning("Cookie auth data: %r", binascii.unhexlify(resp_parts[1]))
            selected_cookie = None
            for line in cookie_file.open('rb'):
                cookie_id, cookie_ts, cookie = line.split()
                if int(s_cookie_id) == int(cookie_id):
                    logging.warning("Found cookie %s", cookie)
                    selected_cookie = cookie
                    break

            assert not selected_cookie is None

            cli_challenge = b'a' * (len(s_challenge) // 2)
            response = b'%s:%s:%s' % (s_challenge, cli_challenge, cookie)
            response_hash = hashlib.sha1(response).hexdigest().encode()

            response = binascii.hexlify(b'%s %s' % (cli_challenge, response_hash))
            self.writer.write(b'DATA %s\r\n' % response)
            logger.warning("Response to hash: %s, hash: %s, response: %s", response, response_hash, response)
            return await self._check_auth_result()
        else:
            raise RuntimeError("Unexpected response during DBUS_COOKIE_SHA1 auth: %r", resp)

    async def connect_and_auth(self):
        if isinstance(self.socket_path, str):
            self.reader, self.writer = await asyncio.open_unix_connection(self.socket_path)
        else:
            self.reader, self.writer = await asyncio.open_connection(self.socket_path[0], self.socket_path[1])
        self.writer.write(b"\0")
        self.writer.write(b"AUTH\r\n")
        response = await self.reader.readline()
        auth_available = response.split()[1:]
        logger.warning("Auth types available: %s", auth_available)
        if False:
            pass
        elif await self._do_auth_cookie():
            pass
        elif await self._do_auth_external():
            pass
        elif await self._do_auth_anonymous():
            pass
        else:
            logger.error("Can't authenticate with the server")
        self.writer.write(b'BEGIN\r\n')

    async def recv(self):
        # type: () -> typing.List[Message]
        msgs = []
        while len(msgs) == 0:
            data = await self.reader.read(1024)
            if len(data) == 0:
                logger.error("Connection closed, buffer content: %s", self.parser)
                raise RuntimeError("Connection closed")
            msgs = self.parser.feed_data(data)
        return msgs

    async def send(self, message):
        # type: (Message) -> None
        buf = OutputBuffer()
        try:
            buf.put_message(message)

        except:
            logger.error("Unable to serialize message %s", message)
            raise
        data = buf.get()
        assert len(InputBuffer().feed_data(data)) == 1
        self.writer.write(data)


class DBusError(RuntimeError):
    pass


class DBusMethod:
    def __init__(self, obj, iface, name, signature, output):
        # type: (DBusObject, DBusInterface, str, str, str) -> None
        self.obj = obj
        self.iface = iface
        self.name = name
        self.signature = signature
        self.signature_out = output

    def __call__(self, *args, **kwargs):
        return self.obj.bus.call(self.obj.bus_name, self.obj.object_path, self.iface.name, self.name, self.signature, args)

    def __str__(self):
        return '[%s].%s(%r)->%r' % (self.iface.name, self.name, self.signature, self.signature_out)


class DBusSignal:
    def __init__(self, obj, iface, name, signature):
        self.obj = obj
        self.iface = iface
        self.name = name
        self.signature = signature

    def __str__(self):
        return '[%s].%s (%s)' % (self.iface.name, self.name, self.signature)


class DBusInterface:
    def __init__(self, name):
        self.name = name
        self.signals = {}
        self.methods = {}

    def __getattr__(self, item):
        if item in self.methods:
            return self.methods[item]
        raise AttributeError(item)


class DBusObject:
    def __init__(self, bus, bus_name, object_path, introspect_result):
        # type: (ClientConnection, str, str, str) -> None
        self.bus = bus              # type: ClientConnection
        self.bus_name = bus_name
        self.object_path = object_path
        self.interfaces = {}    # type: typing.Dict[str, DBusInterface]
        tree = etree.parse(io.BytesIO(introspect_result))
        for interface_node in tree.xpath('/node/interface'):
            interface = DBusInterface(interface_node.get('name'))
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
                signal = DBusSignal(self, interface, name, ''.join(args))
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
    # type: (pybus.connection.ClientConnection, str) -> pybus.connection.DBusInterface
    if name:
        name = 'org.freedesktop.DBus.%s' % name
    else:
        name = 'org.freedesktop.DBus'
    return await conn.get_object_interface('org.freedesktop.DBus', b'/org/freedesktop/DBus', name)


class ClientConnection:
    def __init__(self, socket=None, uri=None):
        self.bus = BusConnection(socket=socket, uri=uri)
        self.futures = {}       # type: typing.Dict[int, asyncio.Future]
        self.freedesktop_interface = None

    async def connect(self):
        await self.bus.connect_and_auth()
        asyncio.ensure_future(self.run())
        await self.call('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'Hello', '', None)
        self.freedesktop_interface = await get_freedesktop_interface(self)

    async def run(self):
        while True:
            msgs = await self.bus.recv()
            for msg in msgs:
                try:
                    mt = msg.message_type
                    if mt in [MessageType.METHOD_RETURN, MessageType.ERROR]:
                        reply_to = msg.headers[HeaderField.REPLY_SERIAL]
                        if reply_to in self.futures:
                            logger.info("Got response to %d", reply_to)
                            f = self.futures.pop(reply_to)  # type: asyncio.Future
                            if mt == MessageType.METHOD_RETURN:
                                f.set_result(msg.payload)
                            else:
                                f.set_exception(DBusError(msg.payload))
                            continue
                        else:
                            logging.warning("Received unexpected response message: %s", msg)
                    elif mt == MessageType.SIGNAL:
                        self.process_signal(msg)
                    elif mt == MessageType.METHOD_CALL:
                        self.process_method_call(msg)
                    else:
                        logger.error("Don't know what to do with this: %s", msg)

                except:
                    logger.exception("Failed to process message %s", msg)

    def process_signal(self, msg):
        logger.error("Received a signal: %s", msg)

    def process_method_call(self, msg):
        logger.error("Received a method call: %s, don't know what to do, sending NotImplemented error", msg)
        err = Message()
        err.message_type = MessageType.ERROR
        err.headers[HeaderField.DESTINATION] = msg.headers[HeaderField.SENDER]
        err.headers[HeaderField.REPLY_SERIAL] = pybus.types.enforce_type(msg.serial, b'u')
        err.headers[HeaderField.ERROR_NAME] = b'space.equi.pybus.Error.NotImplemented'
        asyncio.ensure_future(self.bus.send(err))

    def call(self, bus_name, object_path, interface_name, method, signature=None, args=None, timeout=None):
        # type: (StringOrBytes, StringOrBytes, StringOrBytes, StringOrBytes, StringOrBytes, typing.Any, float) -> typing.Any
        if isinstance(bus_name, str):
            bus_name = bus_name.encode()
        if isinstance(interface_name, str):
            interface_name = interface_name.encode()
        if isinstance(method, str):
            method = method.encode()
        if isinstance(signature, str):
            signature = signature.encode()
        if isinstance(object_path, str):
            object_path = object_path.encode()
        msg = make_mesage(MessageType.METHOD_CALL, bus_name, interface_name, method, object_path, signature, args)
        f = asyncio.Future()
        self.futures[msg.serial] = f
        logger.info("Sending method call: %s", msg)
        if timeout:
            def on_timeout():
                if not f.done():
                    f.set_exception(TimeoutError("Method call timed out: %s.%s" % (interface_name, method)))
            asyncio.get_event_loop().call_later(timeout, on_timeout)
        asyncio.ensure_future(self.bus.send(msg))
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
        asyncio.ensure_future(self.bus.send(msg))

    def send_message(self, msg: Message):
        asyncio.ensure_future(self.bus.send(msg))

    async def introspect(self, bus_name, object_path):
        logger.info("Introspecting %s %s", bus_name, object_path)
        result = await self.call(bus_name, object_path, 'org.freedesktop.DBus.Introspectable', 'Introspect', timeout=10)
        obj = DBusObject(self, bus_name, object_path, result[0])
        return obj

    async def get_object_interface(self, bus_name, object_path, interface) -> DBusInterface:
        return (await self.introspect(bus_name, object_path)).interfaces[interface]

    async def request_name(self, name: str):
        await self.freedesktop_interface.RequestName(name)