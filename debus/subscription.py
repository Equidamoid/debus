import functools
from debus.message import Message, MessageType, HeaderField
import debus.connection

import logging
try:
    import typing
except:
    pass

logger = logging.getLogger(__name__)


def _equals_or_none(requirement, value):
    return requirement is None or requirement == value


@functools.total_ordering
class MatchRule:
    def __init__(self, msg_type:str='signal', sender:str=None, interface:str=None, member:str=None, path:str=None):
        self.msg_type = msg_type
        self.sender = sender
        self.interface = interface
        self.member = member
        self.path = path

    @property
    def rule_str(self):
        field2name = {
            'msg_type': 'type'
        }
        fields = {field2name.get(k, k): v for k,v in self.__dict__.items() if not v is None}
        return ','.join("%s='%s'" % (k, fields[k]) for k in sorted(fields))

    def match(self, msg: Message):
        return \
            _equals_or_none(self.msg_type, msg.message_type.name.lower()) and \
            _equals_or_none(self.sender, msg.headers[HeaderField.SENDER]) and \
            _equals_or_none(self.interface, msg.headers[HeaderField.INTERFACE]) and \
            _equals_or_none(self.member, msg.headers[HeaderField.MEMBER]) and \
            _equals_or_none(self.path, msg.headers[HeaderField.PATH])

    def __hash__(self):
        return self.rule_str.__hash__()

    def __eq__(self, other):
        if not isinstance(other, MatchRule): return False
        return self.rule_str == other.rule_str

    def __lt__(self, other):
        if not isinstance(other, MatchRule): return NotImplemented
        return self.rule_str.__lt__(other.rule_str)


class SubscriptionManager:
    def __init__(self, connection: debus.connection.ClientConnection):
        self._connection = connection
        self._matches = {}              # type: typing.Dict[MatchRule, list]

    def handle_message(self, m: debus.message.Message):
        # first build a list, then call, so user can subscribe/unsubscribe in message handler
        all_callbacks = []
        for rule, callbacks in self._matches.items():
            if rule.match(m):
                all_callbacks += callbacks
        for i in all_callbacks:
            i(m)
        return bool(all_callbacks)

    def subscribe(self, match: MatchRule, callback):
        if match in self._matches:
            cbl = self._matches[match]
        else:
            cbl = []
            self._matches[match] = cbl
            rule = match.rule_str
            logger.info("Subscribing with rule '%s'", rule)
            self._connection.freedesktop_interface.AddMatch(rule)
        cbl.append(callback)

    def unsubscribe(self, cb):
        for match in list(self._matches):
            v = self._matches[match]
            if cb in v:
                v.remove(cb)
            if not v:
                self._connection.freedesktop_interface.RemoveMatch(match.rule_str)
                del self._matches[match]

