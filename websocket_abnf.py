# encoding=UTF-8

import os
import struct
import array

from websocket_exceptions import *
from websocket_utils import validate_utf8

STATUS_NORMAL = 1000
STATUS_GOING_AWAY = 1001
STATUS_PROTOCOL_ERROR = 1002
STATUS_UNSUPPORTED_DATA_TYPE = 1003
STATUS_STATUS_NOT_AVAILABLE = 1005
STATUS_ABNORMAL_CLOSED = 1006
STATUS_INVALID_PAYLOAD = 1007
STATUS_POLOCY_VIOLATION = 1008
STATUS_MESSAGE_TOO_BIG = 1009
STATUS_INVALID_EXTENSION = 1010
STATUS_UNEXPECTED_CONDITION = 1011
STATUS_TLS_HANDSHAKE_ERROR = 1015

VALID_CLOSE_STATUS = (STATUS_NORMAL,
                      STATUS_GOING_AWAY,
                      STATUS_PROTOCOL_ERROR,
                      STATUS_UNSUPPORTED_DATA_TYPE,
                      STATUS_INVALID_PAYLOAD,
                      STATUS_POLOCY_VIOLATION,
                      STATUS_MESSAGE_TOO_BIG,
                      STATUS_INVALID_EXTENSION,
                      STATUS_UNEXPECTED_CONDITION,)

class ABNF(object):

    OPCODE_CONT = 0x0
    OPCODE_TEXT = 0x1
    OPCODE_BINARY = 0x2
    OPCODE_CLOSE = 0x8
    OPCODE_PING = 0x9
    OPCODE_PONG = 0xa

    OPCODES = (OPCODE_CONT, OPCODE_TEXT, OPCODE_BINARY, OPCODE_CLOSE, OPCODE_PING, OPCODE_PONG)

    LENGTH_7 = 0x7e
    LENGTH_16 = 1 << 16
    LENGTH_63 = 1 << 63

    def __init__(self, fin = 0, rsv1 = 0, rsv2 = 0, rsv3 = 0,
                 opcode = OPCODE_TEXT, mask = 1, data = ''):
        self.fin = fin
        self.rsv1 = rsv1
        self.rsv2 = rsv2
        self.rsv3 = rsv3
        self.opcode = opcode
        self.mask = mask
        self.data = data
        self.get_mask_key = os.urandom

    @staticmethod
    def create_frame(data, opcode,fin = 1):
        if opcode == ABNF.OPCODE_TEXT and isinstance(data, str):
            data = data.encode('utf-8')

        return ABNF(fin, 0, 0, 0, opcode, 1, data)

    @staticmethod
    def mask(mask_key, data):
        if isinstance(mask_key, str):
            mask_key = mask_key.encode('latin-1')
        if isinstance(data, str):
            data = data.encode('latin-1')

        _m = array.array('B', mask_key)
        _d = array.array('B', data)
        for i in range(len(_d)):
            _d[i] ^= _m[i % 4]

        return _d.tobytes()

    def _get_masked(self, mask_key):
        s = ABNF.mask(mask_key, self.data)

        if isinstance(mask_key, str):
            mask_key = mask_key.encode('utf-8')

        return mask_key + s

    def format(self):
        if any(x not in (0, 1) for x in [self.fin, self.rsv1, self.rsv2, self.rsv3]):
            raise ValueError('not 0 or 1')
        if self.opcode not in ABNF.OPCODES:
            raise ValueError('Invalid OPCODE')
        length = len(self.data)
        if length >= ABNF.LENGTH_63:
            raise ValueError('data is too long')

        frame_header = chr(self.fin << 7 |
                           self.rsv1 << 6 | self.rsv2 << 5 | self.rsv3 << 4 |
                           self.opcode)
        if length < ABNF.LENGTH_7:
            frame_header += chr(self.mask << 7 | length)
            frame_header = frame_header.encode('latin-1')
        elif length < ABNF.LENGTH_16:
            frame_header += chr(self.mask << 7 | 0x7e)
            frame_header = frame_header.encode('latin-1')
            frame_header += struct.pack('!H', length)
        else:
            frame_header += chr(self.mask << 7 | 0x7f)
            frame_header = frame_header.encode('latin-1')
            frame_header += struct.pack('!Q', length)

        if not self.mask:
            return frame_header + self.data
        else:
            mask_key = self.get_mask_key(4)
            return frame_header + self._get_masked(mask_key)

    def _is_invalid_close_status(self, code):
#should be a static method
        global VALID_CLOSE_STATUS

        return code in VALID_CLOSE_STATUS or (3000 <= code < 5000)

    def validate(self):
        if self.rsv1 or self.rsv2 or self.rsv3:
            raise WebSocketProtocolException('rsv is not implemented, yet')

        if self.opcode not in ABNF.OPCODES:
            raise WebSocketProtocolException('Invalid opcode ' + self.opcode)

        if self.opcode == ABNF.OPCODE_PING and not self.fin:
            raise WebSocketProtocolException('Invalid ping frame')

        if self.opcode == ABNF.OPCODE_CLOSE:
            l = len(self.data)
            if not l:
                return
            if l == 1 or l >= 126:
                raise WebSocketProtocolException('Invalid close frame')
            if l > 2 and not validate_utf8(self.data[2]):
                raise WebSocketProtocolException('Invalid close frame')

            code= 256 * self.data[0] + self.data[1]
            if not self._is_invalid_close_status(code):
                raise WebSocketProtocolException('Invalid close opcode')

    def __str__(self):
        return 'fin=' + str(self.fin) + ' opcode=' + str(self.opcode) + ' data=' + str(self.data)
