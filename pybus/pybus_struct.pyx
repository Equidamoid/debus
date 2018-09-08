import binascii
from libc cimport stdint
import logging
from . import message
from . import types
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

cdef int parser_logging = 0

# Can't do constants in cython :(
cdef char dbus_char = 'y'   # a.k.a. uint8
cdef char dbus_bool = 'b'
cdef char dbus_int16 = 'n'
cdef char dbus_uint16 = 'q'
cdef char dbus_int32 = 'i'
cdef char dbus_uint32 = 'u'
cdef char dbus_int64 = 'x'
cdef char dbus_uint64 = 't'
cdef char dbus_double = 'd'

cdef char dbus_array = 'a'
cdef char dbus_variant = 'v'
cdef char dbus_path = 'o'
cdef char dbus_string = 's'
cdef char dbus_signature = 'g'

cdef bytes header_signature = b'yyyyuua(yv)'

assert sizeof(double) == 8

cdef int alignments[256]
p_alignments = {
    dbus_char: 1,
    dbus_bool: 4,
    dbus_int16: 2,
    dbus_uint16: 2,
    dbus_int32: 4,
    dbus_uint32: 4,
    dbus_int64: 8,
    dbus_uint64: 8,
    dbus_double: 8,
}

cdef array_from_dict(dict kv, int array[]):
    cdef int _k
    for k, v in kv.items():
        _k = k
        array[_k] = v

array_from_dict(p_alignments, alignments)
primitives = set([i for i in p_alignments])

ctypedef fused dbus_numbers:
    stdint.uint8_t
    stdint.int16_t
    stdint.uint16_t
    stdint.int32_t
    stdint.uint32_t
    stdint.int64_t
    stdint.uint64_t
    double


cdef int get_alignment_offset(int current_offset, int alignment):
    if alignment <= 1:
        return 0
    cdef int ret = 0
    cdef int n = current_offset / alignment
    if current_offset > n * alignment:
        ret = (n + 1) * alignment - current_offset
    return ret


cdef class RecursiveLogger:
    cdef int level
    cdef logger

    def __init__(self, logger):
        self.logger = logger
        self.level = 0

    def __enter__(self):
        self.level += 1

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.level -= 1

    def warning(RecursiveLogger self, str msg, *args, **kw):
        if parser_logging:
            msg = (' ' * self.level) + msg
            self.logger.warning(msg, *args, **kw)


class BufferIsTooShort(IndexError):
    pass

cdef class InputBuffer:
    cdef bytearray buffer
    cdef int offset
    cdef int message_length
    cdef RecursiveLogger log
    cdef current_message    # type: message.Message

    def __init__(self):
        self.log = RecursiveLogger(logger)
        self.buffer = bytearray()
        self.offset = 0
        self.message_length = 0
        self.current_message = message.Message()

    cdef read_header(InputBuffer self):
        # Header must be in the beginning, right?
        assert self.offset == 0
        cdef:
            char endianness
            char message_type
            char flags
            char major_version
            stdint.uint32_t body_length
            stdint.uint32_t serial
        with self.log:
            endianness, message_type, flags, major_version, body_length, serial, fields = self.pop_multiple(header_signature)
            self.log.warning("E: %d, MT: %d", endianness, message_type)
            assert major_version == 1

            # Should be pretty easy to implement, just rearrange the bytes it in pop_primitive
            assert endianness == 'l', "Sorry, can't read big endian messages yet"
            self.current_message.serial = serial
            self.current_message.message_type = message.MessageType(message_type)
            self.current_message.flags = flags
            for k, v in fields:
                # Skip unknown header fields
                try:
                    self.current_message.headers[message.HeaderField(k)] = v
                except ValueError:
                    pass

            self.align(8)
            if body_length:
                # We have some payload in the message, let's align to 8 bytes and compute required buffer length
                self.log.warning("Header read successfully, body: %d", body_length)
                self.message_length = self.offset + body_length
            else:
                # No payload, so we're done!
                self.consume_buffer()
                return True

    cdef consume_buffer(InputBuffer self):
        self.log.warning("Consumed first %d bytes", self.offset)
        self.buffer = self.buffer[self.offset:]
        self.offset = 0
        self.message_length = 0
        # self.current_message = message.Message()


    cdef try_reading_message(InputBuffer self):
        msg = None
        if self.message_length == 0:
            # Message length unknown, still have to read header
            message_ready = False
            try:
                message_ready = self.read_header()
            except BufferIsTooShort:
                self.log.warning("Can't read header (yet), len: %d", len(self.buffer))
                self.offset = 0
            except:
                logger.exception('')
                raise
            if message_ready:
                msg = self.current_message
                self.current_message = message.Message()
        if self.message_length != 0:
            if len(self.buffer) < self.message_length:
                self.log.warning("Haven't received the whole message yet")
                return
            else:
                self.current_message.payload = self.pop_multiple(self.current_message.headers[message.HeaderField.SIGNATURE])
                self.consume_buffer()
                msg = self.current_message
                self.current_message = message.Message()
        return msg

    cpdef feed_data(InputBuffer self, bytes data):
        self.buffer.extend(data)
        if len(self.buffer) < 10:
            return []
        messages = []
        while True:
            msg = self.try_reading_message()
            if msg is None:
                break
            else:
                messages.append(msg)
        return messages


    cdef bytes pop(InputBuffer self, int size, int alignment):
        self.align(alignment)
        if self.offset + size > len(self.buffer):
            raise BufferIsTooShort("Tried to pop [%d:%d], buffer len: %d" % (self.offset, self.offset + size, len(self.buffer)))
        cdef bytearray ret = self.buffer[self.offset: self.offset + size]
        self.offset += size
        return bytes(ret)

    cdef void align(InputBuffer self, int alignment) except *:
        cdef int n = get_alignment_offset(self.offset, alignment)
        if n > 0:
            with self.log:
                dropped_data = self.buffer[self.offset: self.offset + n]
                self.offset += n
                self.log.warning('Dropping due to alignment (%d): %s' % (alignment, binascii.hexlify(dropped_data)))
                # TODO why direct iteration gives false positives?
                for i in list(dropped_data):
                    if i:
                        raise ValueError("Tried to drop non-zero bytes: %s" % (binascii.hexlify(dropped_data)))


    cpdef to_str(InputBuffer self):
        return '[+%02d:%d] %s (%s)' % (self.offset, len(self.buffer), binascii.hexlify(self.buffer[self.offset:]), self.buffer[self.offset:])

    def __str__(self):
        return self.to_str()

    cdef pop_primitive(InputBuffer self, char signature):
        cdef char* raw_data
        with self.log:
            primitive_size = alignments[signature]
            primitive_data = self.pop(primitive_size, primitive_size)
            raw_data = <char*>primitive_data
            i = -1
            if signature == dbus_char:
                i = int((<stdint.uint8_t*>raw_data)[0])
            elif signature == dbus_bool:
                i = int((<stdint.uint32_t*>raw_data)[0])
                assert i in [0,1]
                i = bool(i)
            elif signature == dbus_int16:
                i = int((<stdint.int16_t*>raw_data)[0])
            elif signature == dbus_uint16:
                i = int((<stdint.uint16_t*>raw_data)[0])
            elif signature == dbus_int32:
                i = int((<stdint.int32_t*>raw_data)[0])
            elif signature == dbus_uint32:
                i = int((<stdint.uint32_t*>raw_data)[0])
            elif signature == dbus_int64:
                i = int((<stdint.int64_t*>raw_data)[0])
            elif signature == dbus_uint64:
                i = int((<stdint.uint64_t*>raw_data)[0])
            elif signature == dbus_double:
                i = float((<double*>raw_data)[0])
            else:
                raise ValueError("Primitive signature not supported: %s" % signature)
            self.log.warning('Reading primitive %s (size %d): %r -> %s %s', chr(signature), primitive_size, binascii.hexlify(
                primitive_data), i, alignments)
            return i

    cdef pop_single(InputBuffer self, signature):
        cdef char datatype = signature[0]
        with self.log:
            if datatype == ord('('):
                assert signature[-1] == ord(')')
                self.align(8)
                return self.pop_multiple(signature[1:-1])
            elif datatype == dbus_array:
                return self.pop_array(signature[1:])
            elif datatype == dbus_variant:
                assert len(signature) == 1
                return self.pop_variant()
            elif datatype == dbus_string:
                assert len(signature) == 1
                return self.pop_string().decode('utf-8')
            elif datatype == dbus_path:
                assert len(signature) == 1
                return types.ObjectPath(self.pop_string())
            elif datatype == dbus_signature:
                assert len(signature) == 1
                return types.Signature(self.pop_signature())
            elif datatype in primitives:
                assert len(signature) == 1
                return self.pop_primitive(datatype)
            else:
                raise NotImplementedError()

    cdef pop_multiple(InputBuffer self, signature):
        # FIXME real dict entry handling
        signature = signature.replace(b'{', b'(').replace(b'}', b')')
        with self.log:
            ret = []
            for i in split_signature(signature):
                ret.append(self.pop_single(i))
            return ret

    cpdef int pop_int32(InputBuffer self) except*:
        cdef bytes data
        with self.log:
            self.align(4)
            data = self.pop(4, 4)
            return (<stdint.int32_t*><char*>data)[0]

    cpdef list pop_array(InputBuffer self, signature):
        cdef int array_len = self.pop_int32()
        cdef int expected_end_offset
        with self.log:
            self.log.warning("Popping array from %s", self)
            self.align(get_alignment(signature[0]))
            expected_end_offset = self.offset + array_len
            self.log.warning("Reading array %s, len %d, item alignment %d" % (signature, array_len, get_alignment(signature[0])))
            ret = []
            while self.offset < expected_end_offset:
                self.log.warning("Next array item, offset %d/%d", self.offset, expected_end_offset)
                item = self.pop_single(signature)
                ret.append(item)
            self.log.warning("End of array, expected %d, buffer %s", expected_end_offset, self)
            return ret
        # assert buffer.offset == expected_end_offset

    cdef pop_string(InputBuffer self):
        # self.log.warning(buf)
        cdef int str_l
        cdef bytes data
        with self.log:
            self.log.warning("Pop string, buffer: %s", self)
            str_l = self.pop_int32()
            self.log.warning("Reading string of len %d, %s", str_l, self)
            if str_l:
                data = self.pop(str_l, 1)
            else:
                data = b''

            # zero byte after string
            b = self.pop(1, 1)
            assert b == b'\0'
            self.log.warning("Popped string %s", data)
            return data

    cdef bytes pop_signature(InputBuffer self):
        cdef int l
        cdef bytes data
        with self.log:
            self.log.warning("Popping signature from %s", self)
            l = self.pop(1, 1)[0]
            data = self.pop(l, 1)
            self.pop(1, 1)
            self.log.warning("Popped signature %s", data)
            return data

    cdef pop_variant(InputBuffer self):
        with self.log:
            self.log.warning("Popping variant from %s", self)
            sgn = self.pop_signature()
            sgn_b = bytes(sgn)
            assert len(split_signature(sgn)) == 1, "Variant 'will have the signature of a single complete type'"
            self.log.warning("Variant signature %s", sgn)
            res = self.pop_single(sgn)
            self.log.warning("Popped variant %s: %s" % (sgn, res))
            return res


cdef class OutputBuffer:
    cdef bytearray buffer
    cdef RecursiveLogger log

    def __init__(self):
        self.log = RecursiveLogger(logger)
        self.buffer = bytearray()

    cpdef get(OutputBuffer self):
        return bytes(self.buffer)

    cdef void put_aligned(OutputBuffer self, data, alignment=1) except *:
        cdef int offset = get_alignment_offset(len(self.buffer), alignment)
        if offset > 0:
            self.log.warning("Aligning to %d with %d zeros", alignment, offset)
            self.buffer.extend(b'\0' * offset)
        self.buffer.extend(data)

    cdef void serialize_primitive(OutputBuffer self, dbus_numbers value):
        cdef dbus_numbers* ptr = &value
        cdef int len = sizeof(dbus_numbers)
        cdef bytes data = (<char*>ptr)[:len]
        with self.log:
            self.put_aligned(data, len)

    cdef void put_string(OutputBuffer self, bytes data) except *:
        with self.log:
            self.serialize_primitive[stdint.uint32_t](len(data))
            self.put_aligned(data)
            self.put_aligned(b'\0')

    cdef void put_signature(OutputBuffer self, signature) except *:
        with self.log:
            self.log.warning("Putting signature %s", signature)
            assert len(signature) < 255, "Your signature is too long"
            self.serialize_primitive[stdint.uint8_t](len(signature))
            self.put_aligned(signature)
            self.put_aligned(b'\0')

    cdef void put_variant(OutputBuffer self, signature, arg) except *:
        with self.log:
            self.put_signature(signature)
            self.put_single(signature, arg)

    cdef void put_array(OutputBuffer self, signature, arg) except *:
        cdef int length_offset = -1
        cdef int payload_alignment = get_alignment(signature[0])
        cdef int payload_start = -1
        cdef int payload_end = -1
        cdef stdint.uint32_t payload_len = -1
        self.log.warning("Array of %s: %s", signature, arg)
        self.serialize_primitive[stdint.uint32_t](0)
        length_offset = len(self.buffer) - 4
        self.put_aligned(b'', payload_alignment)
        payload_start = len(self.buffer)
        for i in arg:
            self.put_single(signature, i)

        payload_end = len(self.buffer)
        payload_len = payload_end - payload_start
        self.log.warning("Array items recorded, len=%d [%d:%d], length offset: %d", payload_len, payload_start, payload_end, length_offset)
        data = bytes((<char*>&(payload_len))[:4])
        self.buffer[length_offset: length_offset + 4] = data

    cdef void put_single(OutputBuffer self, bytes signature, arg) except *:
        cdef char dtype = signature[0]
        cdef int t_size = 0
        with self.log:
            self.log.warning("Putting single: %r, %r", chr(dtype), arg)
            if False:
                pass
            elif dtype == '(':
                self.put_aligned(b'', 8)
                self.put_multiple(signature[1:-1], arg)
            elif dtype == dbus_array:
                self.put_array(signature[1:], arg)
            elif dtype == dbus_string:

                if isinstance(arg, str):
                    arg = arg.encode('utf-8')
                self.put_string(arg)
            elif dtype == dbus_path:
                if isinstance(arg, str):
                    # From dbus spec:
                    # > Each element must only contain the ASCII characters "[A-Z][a-z][0-9]_"
                    arg = arg.encode('ascii')
                else:
                    arg = bytes(arg)
                assert_valid_path(arg)
                self.put_string(arg)
            elif dtype == dbus_signature:
                if isinstance(arg, str):
                    arg = arg.encode('ascii')
                else:
                    arg = bytes(arg)
                split_signature(arg)
                self.put_signature(arg)
            elif dtype == dbus_variant:
                if isinstance(arg, types.enforce_type):
                    variant_sign, arg = arg._signature, arg._value
                else:
                    variant_sign = types.guess_signature(arg)
                    self.log.warning("Guessed variant signature for %r: %s", arg, variant_sign)
                self.put_variant(variant_sign, arg)
            elif dtype in primitives:
                try:
                    t_size = alignments[dtype]
                    if dtype == dbus_bool:
                        arg = 1 if arg else 0
                        self.serialize_primitive[stdint.uint32_t](arg)
                    elif dtype == dbus_char: self.serialize_primitive[stdint.uint8_t](arg)
                    elif dtype == dbus_int16: self.serialize_primitive[stdint.int16_t](arg)
                    elif dtype == dbus_uint16: self.serialize_primitive[stdint.uint16_t](arg)
                    elif dtype == dbus_int32: self.serialize_primitive[stdint.int32_t](arg)
                    elif dtype == dbus_uint32: self.serialize_primitive[stdint.uint32_t](arg)
                    elif dtype == dbus_int64: self.serialize_primitive[stdint.int64_t](arg)
                    elif dtype == dbus_uint64: self.serialize_primitive[stdint.uint64_t](arg)
                    elif dtype == dbus_double: self.serialize_primitive[double](arg)
                    else:
                        raise NotImplementedError("Unknown primitive signature %s", dtype)
                except TypeError:
                    logger.error("Invalid value for primitive %s: %r", dtype, arg)
                    raise
            else:
                raise NotImplementedError("Don't know what to do with %s", signature)

    cdef put_multiple(OutputBuffer self, signature, args):
        # FIXME real dict entry handling
        if isinstance(signature, str):
            signature = signature.encode(ascii)
        signature = signature.replace(b'{', b'(').replace(b'}', b')')

        with self.log:
            parts = split_signature(signature)
            if len(parts) != len(args):
                raise ValueError("Args length doesn't match signature length: %d vs %d" % (len(parts), len(args)))

            for sgn_item, data_item in zip(parts, args):
                try:
                    self.put_single(sgn_item, data_item)
                except:
                    logger.error("Failed to put %r as type %s while serializing args: %r as %r", data_item, sgn_item, parts, args)
                    raise


    cpdef put_message(OutputBuffer self, msg):
        # type: (message.Message)->None
        cdef int payload_start = -1
        cdef int payload_end = -1
        cdef stdint.uint32_t payload_len = 0
        assert not msg.message_type is None
        assert not msg.serial is None
        with self.log:
            self.log.warning('Writing header')
            self.put_multiple(
                header_signature, (
                    b'l'[0],
                    msg.message_type,
                    0,
                    1,
                    0,      # We don't know neither length of the header nor the length of the payload yet
                    msg.serial,
                    [(k, msg.headers[k]) for k in sorted(msg.headers)]
                )
            )
            self.put_aligned(b'', 8)
        with self.log:
            signature = msg.headers.get(message.HeaderField.SIGNATURE, b'')
            if len(signature):
                self.log.warning("Writing payload")
                self.put_aligned(b'', 8)
                payload_start = len(self.buffer)
                self.put_multiple(signature, msg.payload)
                payload_end = len(self.buffer)
                payload_len = payload_end - payload_start
                self.buffer[4:8] = (<char*>&payload_len)[:4]
            else:
                self.log.warning("No payload")
        pass


cpdef dump_struct(signature, args):
    buf = OutputBuffer()
    buf.put_single(signature, args)
    return buf.buffer

cpdef load_struct(signature, bytes data):
    buf = InputBuffer(data)
    return buf.pop_single(signature)

cpdef read_message(bytes buffer):
    buf = InputBuffer()
    return buf.feed_data(buffer)

cpdef serialize_message(msg):
    b = OutputBuffer()
    b.put_message(msg)
    return bytes(b.buffer)


cdef int get_alignment(char t) except *:
    if t in primitives:
        return alignments[t]
    elif t == b'(':
        return 8
    elif t == b'v':
        return 1
    elif t == b's':
        return 4
    elif t == b'a':
        return 4
    raise NotImplementedError("Don't know alignment for %s", chr(t))

# Parsing dbus signatures

cdef int get_structure_length(signature, int offset) except *:
    logger.warning("struct len %s %d", signature, offset)
    assert signature[offset] == ord('(')
    cdef int depth = 1
    cdef int current_idx = offset + 1
    cdef char ch
    while current_idx < len(signature):
        ch = signature[current_idx]
        if ch == ord('('):
            depth += 1
        if ch == ord(')'):
            depth -= 1
        current_idx += 1
        if depth == 0:
            break
    if depth:
        raise ValueError("Invalid signature %s: one or more ')' missing", signature)
    return current_idx - offset

cdef int get_array_length(signature: bytes, int offset) except *:
    assert signature[offset] == ord('a')
    cdef int pl_len = get_next_item_length(signature, offset + 1)
    return pl_len + 1


cdef int get_next_item_length(bytes signature, int offset) except *:
    cdef char ch = signature[offset]
    if ch == ord('('):
        return get_structure_length(signature, offset)
    elif ch == ord('a'):
        return get_array_length(signature, offset)
    elif ch == ord(')'):
        raise ValueError("Invalid signature %s: mismatched ')' at position %d" % (signature, offset))
    else:
        return 1

cpdef list split_signature(bytes signature):
    cdef int sign_len = len(signature)
    cdef int sign_idx = 0
    cdef list ret = []
    cdef int l = 0
    while sign_idx < sign_len:
        l = get_next_item_length(signature, sign_idx)
        subsign = signature[sign_idx: sign_idx + l]
        ret.append(subsign)
        sign_idx += l
    return ret

cpdef void assert_valid_path(bytes path) except *:
    if path[0] != ord(b'/'):
        raise ValueError("Object path does not start with '/': %r (%d)" % (path, path[0]))
    # TODO check for '[A-Z][a-z][0-9]_'
    assert not b'//' in path, "Object path contains empty element ('//')"
    if len(path) > 1:
        assert path[-1] != ord(b'/'), "Object path ends with '/'"

