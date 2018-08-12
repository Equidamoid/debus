from pybus.objects import DBusObject, DBusInterface, dbus_method
from lxml import etree
from pybus.pybus_struct import split_signature


class IntrospectInterface(DBusInterface):
    name = 'org.freedesktop.DBus.Introspectable'

    @dbus_method('', 's')
    def Introspect(self, obj):
        assert isinstance(obj, DBusObject)
        root = etree.Element('node', name=obj.path)
        for iface in obj.interfaces:
            iface_node = etree.Element('interface', name=iface.name)
            for m in iface.methods:
                name = m._pybus_method_name
                sign = m._pybus_method_signature
                out_sign = m._pybus_method_return_signature

                method_node = etree.Element('method', name=name)
                in_args = split_signature(sign.encode())
                out_args = split_signature(out_sign.encode())
                for i in in_args:
                    arg_node = etree.Element('arg', type=i, direction='in')
                    method_node.append(arg_node)
                for i in out_args:
                    arg_node = etree.Element('arg', type=i, direction='out')
                    method_node.append(arg_node)
                iface_node.append(method_node)
            root.append(iface_node)
            for m in iface.signals:
                name = m._pybus_signal_name
                out_sign = m._pybus_signal_signature
                signal_node = etree.Element('signal', name=name)
                out_args = split_signature(out_sign.encode())
                for i in out_args:
                    arg_node = etree.Element('arg', type=i, direction='out')
                    signal_node.append(arg_node)
                iface_node.append(signal_node)
            root.append(iface_node)
        return etree.tostring(root, pretty_print=True),
