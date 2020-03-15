import asyncio
import logging
import os
import sys

import debus
import debus.objects
import debus.freedesktop.introspect

logger = logging.getLogger(__name__)

async def try_dbus():
    # Some constants to be used

    # The "bus name", a.k.a. the connection name, not to be confused with names of interfaces.
    # This is an optional way to give your connection a persistent human-friendly name
    # Only needed if you expect others to call your methods or listen to your signals, not needed for "clients".
    bus_name = 'net.shapranov.debus.demo_client'

    # Name of the test interface we will implement
    interface_name = 'net.shapranov.debus.demo'


    # Let's connect to a bus first
    c = debus.ManagedConnection(uri=debus.SESSION)
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
        except debus.DBusError as ex:
            # DBus errors result in a python exception coming from a future
            pid = None
            logging.warning("No data for %s: %s", i, ex.args)
        logging.warning("pid of '%s' is %s", i, pid)

    # Signals!
    # take subscription manager
    sm = c.sub_mgr

    # create a callback
    signal_data = asyncio.Future()
    def on_signal(msg: debus.Message):
        logging.warning("Callback called for %s", msg)

        # Notify our "main" that we got the signal and it can proceed
        signal_data.set_result(msg.payload)

        # we only want one signal, so let's unsubscribe immediately
        asyncio.ensure_future(sm.unsubscribe(on_signal))

    # subscribe for a signal
    await sm.subscribe(debus.MatchRule(interface='org.freedesktop.DBus', member='NameAcquired'), on_signal)

    # RequestName() causes NameAcquired to be broadcasted, let's call it and wait for the signal
    await freedesktop_dbus_if.RequestName(bus_name, 0)

    # using wait_for to nicely crash if something goes wrong and we don't get the signal in 5 sec
    await asyncio.wait_for(signal_data, 5000)
    logger.warning("Data from the signal: %r", signal_data.result())

    # Exposing objects
    om = c.obj_mgr

    # Define an interface
    class TestIface(debus.objects.DBusInterface):
        name = interface_name

        @debus.objects.dbus_method('i', 'i')
        def Test(self, i):
            logging.info("Adding 42 to %d", i)
            self.TestReceived(i)
            # DBus can have multiple "out arguments", so here we return a tuple of one
            return i + 42,

        # You can also expose coroutines
        @debus.objects.dbus_method('i', 'i')
        async def TestAsync(self, i):
            logging.info("Adding 42 to %d asyncronously", i)
            await asyncio.sleep(2)
            self.TestReceived(i)
            return i + 42,

        @debus.objects.dbus_signal('i')
        def TestReceived(self, i):
            pass

    # Create an object
    obj = debus.objects.DBusObject(c, '/test/path')

    # Add interface to your object
    obj.add_interface(TestIface())
    # Also add the standard Introspect interface
    obj.add_interface(debus.freedesktop.introspect.IntrospectInterface())
    # register the object
    om.register_object(obj)

    # Now, let's call a method and see what happens
    remote_if = await c.get_object_interface(bus_name, '/test/path', interface_name)
    ret = await remote_if.Test(4200)
    logger.warning("Response: %d", ret[0])
    ret = await remote_if.TestAsync(424200)
    logger.warning("Async response: %d", ret[0])


if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s - %(message)s')
    asyncio.get_event_loop().run_until_complete(try_dbus())
