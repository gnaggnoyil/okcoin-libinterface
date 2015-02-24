# encoding=UTF-8

import struct
import threading
import socket
from urllib.parse import urlparse
import os
import errno
import logging
from base64 import encodebytes as base64encode
import ssl
import uuid
import hashlib

from websocket_utils import NoLock, validate_utf8
from websocket_exceptions import *
from websocket_abnf import *

DEFAULT_SOCKET_OPTION = [(socket.SOL_TCP, socket.TCP_NODELAY, 1),
                         (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
                         (socket.SOL_TCP, socket.TCP_KEEPIDLE, 30),
                         (socket.SOL_TCP, socket.TCP_KEEPINTVL, 10),
                         (socket.SOL_TCP, socket.TCP_KEEPCNT, 3)]

logger = logging.getLogger()

VERSION = 13

_HEADERS_TO_CHECK = {'upgrade': 'websocket',
                     'connection': 'upgrade',}

def _parse_url(url):
    if ':' not in url:
        raise ValueError('url is invalid')

    scheme, url = url.split(':', 1)

    parsed = urlparse(url, scheme = 'ws')
    if parsed.hostname:
        hostname = parsed.hostname
    else:
        raise ValueError("hostname is invalid")

    port = parsed.port if parsed.port else 0

    is_secure = False
    if scheme == 'ws':
        if not port:
            port = 80
    elif scheme == 'wss':
        is_secure = True
        if not port:
            port = 443
    else:
        raise ValueError('scheme %s is invalid' % scheme)

    if parsed.path:
        resource = parsed.path
    else:
        resource = '/'

    if parsed.query:
        resource += '?' + parsed.query

    return (hostname, port, resource, is_secure)

DEFAULT_NO_PROXY_HOST = ['localhost', '127.0.0.1']

def _is_no_proxy_host(hostname, no_proxy):
    global DEFAULT_NO_PROXY_HOST

    if not no_proxy:
        v = os.environ.get('no_proxy', '').replace(' ', '')
        no_proxy = v.split(',')
    if not no_proxy:
        no_proxy = DEFAULT_NO_PROXY_HOST

    return hostname in no_proxy

def _get_proxy_info(hostname, is_secure, **options):
    if _is_no_proxy_host(hostname, options.get('http_no_proxy', None)):
        return None, 0, None

    http_proxy_host = options.get('http_proxy_host', None)
    if http_proxy_host:
        return http_proxy_host, options.get('http_proxy_port', 0), options.get('http_proxy_auth', None)

    env_keys = ['http_proxy']
    if is_secure:
        env_keys.insert(0, 'https_proxy')

    for key in env_keys:
        value = os.environ.get(key, None)
        if value:
            proxy = urlparse(value)
            auth = (proxy.username, proxy.password) if proxy.username else None
            return proxy.hostname, proxy.port, auth

    return None, 0, None

trace_enabled = False

def enableTrace(tracable):
    global trace_enabled, logger

    trace_enabled = tracable
    if tracable:
        if not logger.handlers:
            logger.addHandler(logging.StreamHandler())
        logger.setLevel(logging.DEBUG)

def _dump(title, message):
    global trace_enabled, logger

    if trace_enabled:
        logger.debug('--- ' + title + ' ---')
        logger.debug(message)
        logger.debug('-----------------------')

def _extract_err_message(exception):
    message = getattr(exception, 'strerror', '')
    if not message:
        message = getattr(exception, 'message', '')

    return message

def _create_sec_websocket_key():
    uid = uuid.uuid4()
    return base64encode(uid.bytes).decode('utf-8').strip()

default_timeout = None

def getdefaulttimeout():
    global default_timeout

    return default_timeout

class _FrameBuffer(object):
    _HEADER_MASK_INDEX = 5
    _HEADER_LENGTH_INDEX = 6

    def __init__(self):
        self.clear()

    def clear(self):
        self.header = None
        self.length = None
        self.mask = None

    def has_received_header(self):
        return self.header is None

    def recv_header(self, recv_fn):
        header = recv_fn(2)
        b1 = header[0]

        fin = b1 >> 7 & 1
        rsv1 = b1 >> 6 & 1
        rsv2 = b1 >> 5 & 1
        rsv3 = b1 >> 4 & 1
        opcode = b1 & 0xf
        b2 = header[1]
        has_mask = b2 >> 7 & 1
        length_bits = b2 & 0x7f

        self.header = (fin, rsv1, rsv2, rsv3, opcode, has_mask, length_bits)

    def has_mask(self):
        if not self.header:
            return False
        return self.header[_FrameBuffer._HEADER_MASK_INDEX]

    def has_received_length(self):
        return self.length is None

    def recv_length(self, recv_fn):
        bits = self.header[_FrameBuffer._HEADER_LENGTH_INDEX]
        length_bits = bits & 0x7f
        if length_bits == 0x7e:
            v = recv_fn(2)
            self.length = struct.unpack('!H', v)[0]
        elif length_bits == 0x7f:
            v = recv_fn(8)
            self.length = struct.unpack('!Q', v)[0]
        else:
            self.length = length_bits

    def has_received_mask(self):
        return self.mask is None

    def recv_mask(self, recv_fn):
        if self.has_mask():
            self.mask = recv_fn(4)

class WebSocket(object):

    def __init__(self, get_mask_key = None, sockopt = None, sslopt = None,
                 fire_cont_frame = False, enable_multithread = False):
        if sockopt is None:
            sockopt = []
        if sslopt is None:
            sslopt = {}
        self.connected = False
        self.sock = None
        self._timeout = None
        self.sockopt = sockopt
        self.sslopt = sslopt
        self.get_mask_key = get_mask_key
        self.fire_cont_frame = fire_cont_frame

        self._recv_buffer = []
        self._frame_buffer = _FrameBuffer()
        self._cont_data = None
        self._recving_frames = None
        if enable_multithread:
            self.lock = threading.Lock()
        else:
            self.lock = NoLock()
        self.subprotocol = None

    def fileno(self):
        return self.sock.fileno()

    def set_mask_key(self, func):
        self.get_mask_key = func

    def gettimeout(self):
        return self._timeout

    def settimeout(self, timeout):
        self._timeout = timeout
        if self.sock:
            self.sock.settimeout(timeout)

    timeout = property(gettimeout, settimeout)

    def _send(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')

        if not self.sock:
            raise WebSocketConnectionClosedException()

        try:
            return self.sock.send(data)
        except socket.timeout as e:
            message = _extract_err_message(e)
            raise WebSocketTimeoutException(message)
        except Exception as e:
            message = _extract_err_message(e)
# WTF is this shit
            if message and 'timed out' in message:
                raise WebSocketTimeoutException(message)
            else:
                raise

    def _recv(self, bufsize):
        if not self.sock:
            raise WebSocketConnectionClosedException('socket is already closed.')

        try:
            bytestream = self.sock.recv(bufsize)
        except socket.timeout as e:
            message = _extract_err_message(e)
            raise WebSocketTimeoutException(message)
        except ssl.SSLError as e:
            message = _extract_err_message(e)
            if message == 'The read operation timed out':
                raise WebSocketTimeoutException(message)
            else:
                raise

        if not bytestream:
            self.sock.close()
            self.sock = None
            self.connected = False
            raise WebSocketConnectionClosedException()

        return bytestream

    def _recv_line(self):
# We should make a buffer to accerlate this method
        line = []
        while True:
            c = self._recv(1)
            line.append(c)
            if c == b'\n':
                break
        return b''.join(line)

    def _read_headers(self):
        global trace_enabled, logger

        status = None
        headers = {}
        if trace_enabled:
            logger.debug('--- response header ---')

        while True:
            line = self._recv_line()
            line = line.decode('utf-8').strip()
            if not line:
                break

            if trace_enabled:
                logger.debug(line)

            if not status:
                status_info = line.split(' ', 2)
                status = int(status_info[1])
            else:
                kv = line.split(':', 1)
                if len(kv) == 2:
                    key, value = kv
                    headers[key.lower()] = value.strip().lower()
                else:
                    raise WebSocketException('Invalid header')

        if trace_enabled:
            logger.debug('-----------------------')

        return status, headers

    def _tunnel(self, host, port, auth):
        global logger

        logger.debug('Conncting proxy...')
        connect_header = 'CONNECT %s:%d HTTP/1.0\r\n' % (host, port)

        if auth and auth[0]:
            auth_str = auth[0]
            if auth[1]:
                auth_str += ':' + auth[1]
            encoded_str = base64encode(auth_str.encode()).strip().decode()
            connect_header += 'Proxy-Authorization: Basic %s\r\n' % encoded_str
        connect_header += '\r\n'
        _dump('request header', connect_header)

        self._send(connect_header)

        status, resp_headers = self._read_headers()
        if status != 200:
            raise WebSocketException('failed CONNECT via proxy')

    def _get_handshake_headers(self, resource, host, port, options):
        global VERSION

        headers = ['GET %s HTTP/1.1' % resource,
                   'Upgrade: websocket',
                   'Connection: Upgrade']
        if port == 80:
            hostport = host
        else:
            hostport = '%s:%d' % (host, port)
        headers.append('Host: %s' % hostport)

        if 'origin' in options:
            headers.append('Origin: %s' % options['origin'])
        else:
            headers.append('Origin: http://%s' % hostport)

        key = _create_sec_websocket_key()
        headers.append('Sec-WebSocket-Key: %s' % key)
        headers.append('Sec-WebSocket-Version: %s' % VERSION)

        subprotocols = options.get('subprotocols')
        if subprotocols:
            headers.append('Sec-WebSocket-Protocol: %s' % ','.join(subprotocols))

        if 'header' in options:
            headers.extend(options['header'])

        cookie = options.get('cookie', None)
        if cookie:
            headers.append('Cookie: %s' % cookie)

        headers.append('')
        headers.append('')

        return headers, key

    def _get_resp_headers(self, success_status = 101):
        status, resp_headers = self._read_headers()
        if status != success_status:
            self.close()
            raise WebSocketException('Handshake status %d' % status)
        return resp_headers

    def _validate_header(self, headers, key, subprotocols):
        global _HEADERS_TO_CHECK, logger

        for k, v in _HEADERS_TO_CHECK.items():
            r = headers.get(k, None)
            if not r:
                return False
            r = r.lower()
            if v != r:
                return False

        if subprotocols:
            subproto = headers.get('sec-websocket-protocol', None)
            if not subproto or subproto not in subprotocols:
                logger.error('Invalid subprotocol: ' + str(subprotocols))
                return False
            self.subprotocol = subproto

        result = headers.get('sec-websocket-accept', None)
        if not result:
            return False
        result = result.lower()

        if isinstance(result, str):
            result = result.encode('utf-8')

        value = (key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode('utf-8')
        hashed = base64encode(hashlib.sha1(value).digest()).strip().lower()
        return hashed == result

    def send_frame(self, frame):
        """
        >>> ws = create_connection('ws://foo.bar')
        >>> frame = ABNF.create_frame('Hello', ABNF.OPCODE_TEXT)
        >>> ws.send_frame(frame)

        """
        global trace_enabled, logger

        if self.get_mask_key:
            frame.get_mask_key = self.get_mask_key
        data = frame.format()
        length = len(data)
        if trace_enabled:
            logger.debug('send: ' + repr(data))

        with self.lock:
            while data:
                l = self._send(data)
                data = data[l:]

        return length

    def send(self, payload, opcode = ABNF.OPCODE_TEXT):
        frame = ABNF.create_frame(payload, opcode)
        return self.send_frame(frame)

    def _recv_strict(self, bufsize):
        shortage = bufsize - sum(len(x) for x in self._recv_buffer)
        while shortage > 0:
            byte = self._recv(shortage)
            self._recv_buffer.append(byte)
            shortage -= len(byte)

        unified = b''.join(self._recv_buffer)

        if shortage == 0:
            self._recv_buffer = []
            return unified
        else:
            self._recv_buffer = [unified[bufsize:]]
            return unified[:bufsize]

    def recv_frame(self):
        frame_buffer = self._frame_buffer

        if frame_buffer.has_received_header():
            frame_buffer.recv_header(self._recv_strict)
        (fin, rsv1, rsv2, rsv3, opcode, has_mask, _) = frame_buffer.header

        if frame_buffer.has_received_length():
            frame_buffer.recv_length(self._recv_strict)
        length = frame_buffer.length

        if frame_buffer.has_received_mask():
            frame_buffer.recv_mask(self._recv_strict)
        mask = frame_buffer.mask

        payload = self._recv_strict(length)
        if has_mask:
            payload = ABNF.mask(mask, payload)

        frame_buffer.clear()

        frame = ABNF(fin, rsv1,rsv2, rsv3, opcode, has_mask, payload)
        frame.validate()

        return frame

    def shutdown(self):
        if self.sock:
            self.sock.close()
            self.sock = None
            self.connected = False

    def close(self, status = STATUS_NORMAL, reason = b''):
        global logger

        if self.connected:
            if status < 0 or status >= ABNF.LENGTH_16:
                raise ValueError('code is invalid range')

            try:
                self.connected = False
                self.send(struct.pack('!H', status) + reason, ABNF.OPCODE_CLOSE)
                timeout = self.sock.gettimeout()
                self.sock.settimeout(3)
                try:
                    frame = self.recv_frame()
                    if logger.isEnabledFor(logging.ERROR):
                        recv_status = struct.unpack("!H", frame.data)[0]
                        if recv_status != STATUS_NORMAL:
                            logger.error('close status: ' + repr(recv_status))
                except:
                    pass
                self.sock.settimeout(timeout)
                self.sock.shutdown(socket.SHUT_RDWR)
            except:
                pass

        self.shutdown()

    def _handshake(self, host, port, resource, **options):
        headers, key = self._get_handshake_headers(resource, host, port, options)

        header_str = '\r\n'.join(headers)
        self._send(header_str)
        _dump('request header', header_str)

        resp_headers = self._get_resp_headers()
        success = self._validate_header(resp_headers, key, options.get('subprotocols'))
        if not success:
            self.close()
            raise WebSocketException('Invalid WebSocketHeader')

        self.connected = True

    def connect(self, url, **options):
        global DEFAULT_SOCKET_OPTION

        hostname, port, resource, is_secure = _parse_url(url)
        proxy_host, proxy_port, proxy_auth = _get_proxy_info(hostname, is_secure, **options)
        if not proxy_host:
            addrinfo_list = socket.getaddrinfo(hostname, port, 0, 0, socket.SOL_TCP)
        else:
            proxy_port = proxy_port and proxy_port or 80
            addrinfo_list = socket.getaddrinfo(proxy_host, proxy_port, 0, 0, socket.SOL_TCP)

        if not addrinfo_list:
            raise WebSocketException('Host not found.: ' + hostname + ':' + str(port))

        err = None
        for addrinfo in addrinfo_list:
            family = addrinfo[0]
            self.sock = socket.socket(family)
            self.sock.settimeout(self.timeout)
            for opts in DEFAULT_SOCKET_OPTION:
                self.sock.setsockopt(*opts)
            for opts in self.sockopt:
                self.sock.setsockopt(*opts)

            address= addrinfo[4]
            try:
                self.sock.connect(address)
            except socket.error as error:
                error.remote_ip = str(address[0])
                if error.errno in (errno.ECONNREFUSED, ):
                    err = error
                    continue
                else:
                    raise
            else:
                break
        else:
            raise err

        if proxy_host:
            self._tunnel(hostname, port, proxy_auth)

        if is_secure:
            sslopt = dict(cert_reqs = ssl.CERT_REQUIRED)
            cert_path = os.path.join(os.path.dirname(__file__), 'cacert.pem')
            if os.path.isfile(cert_path):
                sslopt['ca_certs'] = cert_path
            sslopt.update(self.sslopt)
            check_hostname = sslopt.pop('check_hostname', True)
            self.sock = ssl.wrap_socket(self.sock, **sslopt)
            if sslopt['cert_reqs'] != ssl.CERT_NONE and check_hostname:
                ssl.match_hostname(self.sock.getpeercert(), hostname)

        self._handshake(hostname, port, resource, **options)

    def ping(self, payload = ''):
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        self.send(payload, ABNF.OPCODE_PING)

    def send_close(self, status = STATUS_NORMAL, reason = b''):
        if status < 0 or status > ABNF.LENGTH_16:
            raise ValueError('code is invalid range')
        self.connected = False
        self.send(struct.pack('!H', status) + reason, ABNF.OPCODE_CLOSE)

    def pong(self, payload):
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        self.send(payload, ABNF.OPCODE_PONG)

    def recv_data_frame(self, control_frame = False):
        while True:
            frame = self.recv_frame()
            if not frame:
                raise WebSocketProtocolException('Not a valid frame %s' % frame)
            elif frame.opcode in (ABNF.OPCODE_TEXT, ABNF.OPCODE_BINARY, ABNF.OPCODE_CONT):
                if not self._recving_frames and frame.opcode == ABNF.OPCODE_CONT:
                    raise WebSocketProtocolException('Illegal frame')
                if self._recving_frames and frame.opcode in (ABNF.OPCODE_TEXT, ABNF.OPCODE_BINARY):
                    raise WebSocketProtocolException('Illegal frame')

                if self._cont_data:
                    self._cont_data[1] += frame.data
                else:
                    if frame.opcode in (ABNF.OPCODE_TEXT, ABNF.OPCODE_BINARY):
                        self._recving_frames = frame.opcode
                    self._cont_data = [frame.opcode, frame.data]

                if frame.fin:
                    self._recving_frames = None

                if frame.fin or self.fire_cont_frame:
                    data = self._cont_data
                    self._cont_data = None
                    frame.data = data[1]
                    if not self.fire_cont_frame and data[0] == ABNF.OPCODE_TEXT and not validate_utf8(frame.data):
                        raise WebSocketPayloadException('cannot decode: ' + repr(frame.data))
                    return [data[0], frame]
            elif frame.opcode == ABNF.OPCODE_CLOSE:
                self.send_close()
                return (frame.opcode, frame)
            elif frame.opcode == ABNF.OPCODE_PING:
                if len(frame.data) < 126:
                    self.pong(frame.data)
                else:
                    raise WebSocketProtocolException('Ping message is too long')
                if control_frame:
                    return (frame.opcode, frame)
            elif frame.opcode == ABNF.OPCODE_PONG:
                if control_frame:
                    return (frame.opcode, frame)

    def send_binary(self, payload):
        return self.send(payload, ABNF.OPCODE_BINARY)

    def recv_data(self, control_frame = False):
        opcode, frame = self.recv_data_frame(control_frame)
        return opcode, frame.data

    def recv(self):
        opcode, data = self.recv_data()
        if opcode == ABNF.OPCODE_TEXT:
            return data.decode('utf-8')
        elif opcode == ABNF.OPCODE_BINARY:
            return data
        else:
            return ''

    def abort(self):
        """
        low-level asynchonous abort, wakes up other threads that are waiting
        """
        if self.connected:
            self.sock.shutdown(socket.SHUT_RDWR)

def create_connection(url, timeout = None, **options):
    """
    connect to url and return websocket object.
    Connect to url and return the WebSocket object.
    Passing optional timeout parameter will set the timeout on the socket.
    If no timeout is supplied, the global default timeout setting returned by getdefauttimeout() is used.
    You can customize using 'options'.
    If you set "header" list object, you can set your own custom header.

    >>> conn = create_connection("ws://echo.websocket.org/",
         ...     header=["User-Agent: MyProgram",
         ...             "x-custom: header"])

    timeout: socket timeout time. This value is integer.
             if you set None for this value, it means "use default_timeout value"
    options: "header" -> custom http header list.
             "cookie" -> cookie value.
             "http_proxy_host" - http proxy host name.
             "http_proxy_port" - http proxy port. If not set, set to 80.
             "http_no_proxy" - host names, which doesn't use proxy.
             "http_proxy_auth" - http proxy auth infomation. tuple of username and password.
                                    defualt is None
             "enable_multithread" -> enable lock for multithread.
             "sockopt" -> socket options
             "sslopt" -> ssl option
             "subprotocols" - array of available sub protocols. default is None.
    """
    global default_timeout

    sockopt = options.get('sockopt', [])
    sslopt = options.get('sslopt', {})
    fire_cont_frame = options.get('fire_cont_frame', False)
    enable_multithread = options.get('enable_multithread', False)
    websock = WebSocket(sockopt = sockopt, sslopt = sslopt,
                        fire_cont_frame = fire_cont_frame, enable_multithread = enable_multithread)
    websock.settimeout(timeout if timeout is not None else default_timeout)
    websock.connect(url, **options)
    return websock

if __name__ == '__main__':
    ws = create_connection('ws://echo.websocket.org/')
    print('Sending \'Hello, World\'...')
    ws.send('Hello, World')
    print('Sent')
    print('Receivng...')
    result = ws.recv()
    print('Received \'%s\'' % result)
    ws.close()
