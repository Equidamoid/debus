import asyncio
import pybus.connection
import logging
import os

systembus = '/opt/local/var/run/dbus/system_bus_socket'
sessionbus = os.environ['DBUS_LAUNCHD_SESSION_BUS_SOCKET']


async def try_dbus():
    c = pybus.connection.ClientConnection(systembus)
    await c.connect()
    asyncio.ensure_future(c.run())
    await c.call(b'org.freedesktop.DBus', b'org.freedesktop.DBus', b'/org/freedesktop/DBus', b'Hello', b'', None)
    int_result = await c.introspect(b'org.freedesktop.DBus', b'/org/freedesktop/DBus')
    int_result.log(logging)
    stats_if = await c.get_object_interface(b'org.freedesktop.DBus', b'/org/freedesktop/DBus', 'org.freedesktop.DBus.Debug.Stats')
    logging.warning("Method: %s", stats_if.GetStats)
    logging.warning("stats: %s", await stats_if.GetStats())

if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s - %(message)s')
    asyncio.get_event_loop().run_until_complete(try_dbus())