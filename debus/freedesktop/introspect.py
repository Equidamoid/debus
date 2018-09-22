from debus.objects import DBusObject, DBusInterface, dbus_method, MethodInfo, PropertyInfo, SignalInfo
from lxml import etree
from debus.marshalling import split_signature
import logging

logger = logging.getLogger(__name__)

class IntrospectInterface(DBusInterface):
    name = 'org.freedesktop.DBus.Introspectable'

    def __init__(self):
        super().__init__()
        self.child_objects = []

    @dbus_method('', 's')
    def Introspect(self):
        root = etree.Element('node', name=self._obj.path)
        for iface in self._obj.interfaces:
            iface_node = etree.Element('interface', name=iface.name)
            for m in iface.methods:
                m_info: MethodInfo = m._pybus_method

                method_node = etree.Element('method', name=m_info.name)
                in_args = split_signature(m_info.in_signature.encode())
                out_args = split_signature(m_info.out_signature.encode())
                for i in in_args:
                    arg_node = etree.Element('arg', type=i, direction='in')
                    method_node.append(arg_node)
                for i in out_args:
                    arg_node = etree.Element('arg', type=i, direction='out')
                    method_node.append(arg_node)
                iface_node.append(method_node)
            root.append(iface_node)
            for m in iface.signals:
                s_info: SignalInfo = m._pybus_signal
                signal_node = etree.Element('signal', name=s_info.name)
                out_args = split_signature(s_info.signature.encode())
                out_arg_names = s_info.argument_names
                if len(out_args) != len(out_arg_names):
                    logger.error("Argument names don't match signature: %s vs %s", out_arg_names, out_args)
                for n, i in enumerate(out_args):
                    arg_node = etree.Element('arg', type=i, name=out_arg_names[n], direction='out')
                    signal_node.append(arg_node)
                iface_node.append(signal_node)
            root.append(iface_node)
        for i in self.child_objects:
            root.append(etree.Element('node', name=i))
        return etree.tostring(root, pretty_print=True),
