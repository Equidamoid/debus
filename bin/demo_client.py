import asyncio
import logging
import os
import sys

import pybus
import pybus.objects
import pybus.freedesktop.introspect

logger = logging.getLogger(__name__)

async def try_dbus():
    # Let's connect to a bus first
    c = pybus.ManagedConnection(uri=pybus.SESSION)
    # c = pybus.connection.ClientConnection(('192.168.1.13', 33333))
    await c.connect()

    ## Low-level interface: ClientConnection class
    # Here I will use "private" field c._connection for simplicity,
    # but if you need you can create an instance of ClientConnection yourself
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
            logging.warning("No data for %s: %s", i, ex.args)
        logging.warning("pid of '%s' is %s", i, pid)

    # Signals!
    # get a subscription manager
    sm = c.sub_mgr

    # create a callback
    def on_signal(msg):
        logging.warning("Callback called for %s", msg)
        # hacky way to get a boolean to outer scope
        on_signal.ok = True
        # we only want one signal, so let's unsubscribe immediately
        sm.unsubscribe(on_signal)

    # and subsctribe
    sm.subscribe(pybus.MatchRule(member='NameAcquired'), on_signal)

    # Now let's cause a signal and wait a bit
    await freedesktop_dbus_if.RequestName('space.equi.pybustest_bus', 0)
    await asyncio.sleep(2)
    # ... and we got our signal
    assert on_signal.ok

    # Exposing objects
    om = c.obj_mgr

    # Define an interface
    class TestIface(pybus.objects.DBusInterface):
        name = 'space.equi.pybustest'

        @pybus.objects.dbus_method('i', 'i')
        def Test(self, i):
            logging.info("Adding 42 to %d", i)
            self.TestReceived(i)
            # DBus can have multiple "out arguments", so here we return a tuple of one
            return i + 42,

        # You can also expose coroutines
        @pybus.objects.dbus_method('i', 'i')
        async def TestAsync(self, i):
            logging.info("Adding 42 to %d asyncronously", i)
            await asyncio.sleep(2)
            self.TestReceived(i)
            return i + 42,

        @pybus.objects.dbus_signal('i')
        def TestReceived(self, i):
            pass

    # Create an object
    obj = pybus.objects.DBusObject(c, '/test/path')

    # Add interface to your object
    obj.add_interface(TestIface())
    # Also add the standard Introspect interface
    obj.add_interface(pybus.freedesktop.introspect.IntrospectInterface())
    # register the object
    om.register_object(obj)

    # Now, let's call a method and see what happens
    remote_if = await c.get_object_interface('space.equi.pybustest_bus', '/test/path', 'space.equi.pybustest')
    ret = await remote_if.Test(4200)
    logger.warning("Response: %d", ret[0])
    ret = await remote_if.TestAsync(424200)
    logger.warning("Async response: %d", ret[0])


if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s - %(message)s')
    asyncio.get_event_loop().run_until_complete(try_dbus())
