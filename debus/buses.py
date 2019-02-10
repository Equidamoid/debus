import sys
import os

if sys.platform.startswith('darwin'):
    SYSTEM = 'unix:path=/opt/local/var/run/dbus/system_bus_socket'
    try:
        SESSION = 'unix:path=%s' % (os.environ['DBUS_LAUNCHD_SESSION_BUS_SOCKET'],)
    except KeyError:
        SESSION = None
elif sys.platform.startswith('linux'):
    SYSTEM = 'unix:path=/var/run/dbus/system_bus_socket'
    SESSION = os.environ.get('DBUS_SESSION_BUS_ADDRESS', None)
