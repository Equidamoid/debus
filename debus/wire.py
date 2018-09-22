import asyncio
import binascii
import hashlib
import logging
import os
from pathlib import Path
import debus
from debus.pybus_struct import InputBuffer, OutputBuffer
try:
    import typing
except:
    pass

logger = logging.getLogger(__name__)


class WireConnection:
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

    async def _do_auth_external(self, user_id: bytes):
        logger.warning("Attempting external auth (user %r)",  user_id.decode())
        self.writer.write(b"AUTH EXTERNAL %s\r\n" % binascii.hexlify(user_id))
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
            response = b'%s:%s:%s' % (s_challenge, cli_challenge, selected_cookie)
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
        elif await self._do_auth_external(b'%d' % os.getuid()):
            pass
        elif await self._do_auth_external(os.environ['USER'].encode()):
            pass
        elif await self._do_auth_anonymous():
            pass
        else:
            logger.error("Can't authenticate with the server")
        self.writer.write(b'BEGIN\r\n')

    async def recv(self) -> 'typing.List[debus.Message]':
        msgs = []
        while len(msgs) == 0:
            data = await self.reader.read(1024)
            if len(data) == 0:
                logger.error("Connection closed, buffer content: %s", self.parser)
                raise RuntimeError("Connection closed")
            msgs = self.parser.feed_data(data)
        return msgs

    def send(self, message: 'debus.Message'):
        buf = OutputBuffer()
        try:
            buf.put_message(message)
        except:
            logger.error("Unable to serialize message %s", message)
            raise
        data = buf.get()
        assert len(InputBuffer().feed_data(data)) == 1
        self.writer.write(data)
