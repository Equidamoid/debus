import asyncio
import pybus.connection
import pybus.message
import pybus
import logging
import os

systembus = '/opt/local/var/run/dbus/system_bus_socket'
sessionbus = os.environ['DBUS_LAUNCHD_SESSION_BUS_SOCKET']

async def try_dbus():
    # Let's connect to a bus first
    c = pybus.connection.ClientConnection(sessionbus)
    await c.connect()

    # Method calls, low-level way:
    machine_id = await c.call('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetId', '', None)
    logging.warning("GetMachineId result: %s", machine_id)

    # Introspection
    int_result = await c.introspect('org.freedesktop.DBus', '/org/freedesktop/DBus')
    logging.warning("Introspection results for org.freedesktop.DBus:")
    int_result.log(logging)

    # Getting an object interface for more convenient calls
    freedesktop_dbus_if = await c.get_object_interface('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus')

    # and using it to make some calls
    all_names = await freedesktop_dbus_if.ListNames()

    for i in all_names[0]:
        try:
            pid = await freedesktop_dbus_if.GetConnectionUnixProcessID(i)
            # Note that the result of function call is an iterable
            # because DBus functions can have multiple "out arguments"
            pid = pid[0]
        except pybus.DBusError as ex:
            # DBus errors result in a python exception coming from a future
            pid = None
            logging.warning("No data for %s: %s", i.decode(), ex.args)
        logging.warning("pid of '%s' is %s", i.decode(), pid)


if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s - %(message)s')
    asyncio.get_event_loop().run_until_complete(try_dbus())
