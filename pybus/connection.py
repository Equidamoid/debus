import asyncio
import logging
import binascii
import os
from .pybus_struct import InputBuffer, OutputBuffer
from .message import Message, make_method_call, MessageType, HeaderField
logger = logging.getLogger(__name__)
from lxml import etree
import io
import typing
from pathlib import Path
import hashlib


class BusConnection:
    def __init__(self, socket_path):
        self.reader = None          # type: asyncio.StreamReader
        self.writer = None          # type: asyncio.StreamWriter
        self.parser = InputBuffer()
        self.server_guid = None     # type: bytes
        self.socket_path = socket_path

    async def check_auth_result(self):
        result = (await self.reader.readline())
        result_parts = result.split()
        status = result_parts[0]
        logger.warning("Auth result: %r", result)
        if status == b'OK':
            self.server_guid = binascii.unhexlify(result_parts[1])
            logger.warning("Auth ok, server guid: %s", self.server_guid)
            return True
        return False

    async def do_auth_external(self):
        logger.warning("Attempting external auth")
        self.writer.write(b"AUTH EXTERNAL %s\r\n" % binascii.hexlify(os.environ['USER'].encode()))
        return await self.check_auth_result()

    async def do_auth_anonymous(self):
        logger.warning("Attempting anonymous auth")
        self.writer.write(b"AUTH ANONYMOUS\r\n")
        return await self.check_auth_result()

    async def do_auth_cookie(self):
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
            return await self.check_auth_result()
        else:
            raise RuntimeError("Unexpected response during DBUS_COOKIE_SHA1 auth: %r", resp)

    async def connect_and_auth(self):
        self.reader, self.writer = await asyncio.open_unix_connection(self.socket_path)
        self.writer.write(b"\0")
        self.writer.write(b"AUTH\r\n")
        response = await self.reader.readline()
        auth_available = response.split()[1:]
        logger.warning("Auth types available: %s", auth_available)
        if False:
            pass
        elif await self.do_auth_cookie():
            pass
        elif await self.do_auth_external():
            pass
        elif await self.do_auth_anonymous():
            pass
        else:
            logger.error("Can't authenticate with the server")
        self.writer.write(b'BEGIN\r\n')

    async def recv(self):
        msgs = []
        while len(msgs) == 0:
            data = await self.reader.read(1024)
            if len(data) == 0:
                raise RuntimeError("Connection closed")
            msgs = self.parser.feed_data(data)
        return msgs

    async def send(self, message):
        # type: (Message) -> None
        buf = OutputBuffer()
        buf.put_message(message)
        data = buf.get()
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
        return self.obj.bus.call(self.obj.bus_name, self.iface.name, self.obj.object_path, self.name, self.signature, args)

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
        raise AttributeError


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


class ClientConnection:
    def __init__(self, socket_path):
        self.bus = BusConnection(socket_path)
        self.futures = {}

    async def connect(self):
        await self.bus.connect_and_auth()

    async def run(self):
        while True:
            msgs = await self.bus.recv()    # type: typing.List[Message]
            for msg in msgs:
                try:
                    mt = msg.message_type
                    if mt in [MessageType.METHOD_RETURN, MessageType.ERROR]:
                        reply_to = msg.headers[HeaderField.REPLY_SERIAL]
                        logger.warning("Got response to %s", reply_to)
                        f = self.futures[reply_to]  # type: asyncio.Future
                        if mt == MessageType.METHOD_RETURN:
                            f.set_result(msg.payload)
                        else:
                            f.set_exception(DBusError(msg.payload))

                except:
                    logger.exception("Failed to process message %s", msg)

    def call(self, bus_name, interface_name, object_path, method, signature=None, args=None):
        if isinstance(bus_name, str):
            bus_name = bus_name.encode()
        if isinstance(interface_name, str):
            interface_name = interface_name.encode()
        if isinstance(method, str):
            method = method.encode()
        msg = make_method_call(bus_name, interface_name, method, object_path, signature)

        if signature is not None:
            msg.payload = args
        f = asyncio.Future()
        self.futures[msg.serial] = f
        logger.warning("Sending method call: %s", msg)
        asyncio.ensure_future(self.bus.send(msg))
        return f

    async def introspect(self, bus_name, object_path):
        logger.warning("Introspecting %s %s", bus_name, object_path)
        result = await self.call(bus_name, 'org.freedesktop.DBus.Introspectable', object_path, 'Introspect')
        obj = DBusObject(self, bus_name, object_path, result[0])
        return obj

    async def get_object_interface(self, bus_name, object_path, interface):
        return (await self.introspect(bus_name, object_path)).interfaces[interface]

