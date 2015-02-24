# encoding=UTF-8

import threading
import time
import sys
import traceback
import select
import inspect
import logging

from websocket_abnf import ABNF
from websocket_exceptions import *
from websocket_core import WebSocket, getdefaulttimeout, logger

class WebSocketApp(object):

    def __init__(self, url, header = [],
                 on_open = None, on_message = None, on_error = None,
                 on_close = None, on_ping = None, on_pong = None,
                 on_cont_message = None,
                 keep_running = True, get_mask_key = None, cookie = None,
                 subprotocols = None):
        """
        url: websocket url.
        header: custom header for websocket handshake.
        on_open: callable object which is called at opening websocket.
          this function has one argument. The arugment is this class object.
        on_message: callbale object which is called when received data.
          on_message has 2 arguments.
          The 1st arugment is this class object.
          The passing 2nd arugment is utf-8 string which we get from the server.
        on_error: callable object which is called when we get error.
          on_error has 2 arguments.
          The 1st arugment is this class object.
          The passing 2nd arugment is exception object.
        on_close: callable object which is called when closed the connection.
          this function has one argument. The arugment is this class object.
        on_cont_message: callback object which is called when recieve continued frame data.
          on_message has 3 arguments.
          The 1st arugment is this class object.
          The passing 2nd arugment is utf-8 string which we get from the server.
          The 3rd arugment is continue flag. if 0, the data continue to next frame data
        keep_running: a boolean flag indicating whether the app's main loop should
          keep running, defaults to True
        get_mask_key: a callable to produce new mask keys, see the WebSocket.set_mask_key's
          docstring for more information
        subprotocols: array of available sub protocols. default is None.
        """
        self.url = url
        self.header = header
        self.cookie = cookie
        self.on_open = on_open
        self.on_message = on_message
        self.on_error = on_error
        self.on_close = on_close
        self.on_ping = on_ping
        self.on_pong = on_pong
        self.on_cont_message = on_cont_message
        self.keep_running = keep_running
        self.get_mask_key = get_mask_key
        self.sock = None
        self.last_ping_tm = 0
        self.subprotocols = subprotocols

    def send(self, data, opcode = ABNF.OPCODE_TEXT):
        if not self.sock or self.sock.send(data, opcode) == 0:
            raise WebSocketConnectionClosedException()

    def close(self):
        self.keep_running = False
        if self.sock:
            self.sock.close()

    def _send_ping(self, interval, event):
        while not event.wait(interval):
            self.last_ping_tm = time.time()
            if self.sock:
                self.sock.ping()

    def _callback(self, callback, *args):
        if callback:
            try:
                callback(self, *args)
            except Exception as e:
                logger.error(e)
                if logger.isEnabledFor(logging.DEBUG):
                    _, _, tb = sys.exc_info()
                    traceback.print_tb(tb)

    def _get_close_args(self, data):
        if not self.on_close or len(inspect.getargspec(self.on_close).args):
            return []

        if data and len(data) >= 2:
            code = 256 * data[0] + data[1]
            reason = data[2:].decode('utf-8')
            return [code, reason]

        return [None, None]

    def run_forever(self, sockopt = None, sslopt = None, ping_interval = 0, ping_timeout = None,
                    http_proxy_host = None, http_proxy_port = None, http_no_proxy = None, http_proxy_auth = None):
        if not ping_timeout or ping_timeout <= 0:
            ping_timeout = None
        if sockopt is None:
            sockopt = []
        if sslopt is None:
            sslopt = {}
        if self.sock:
            raise WebSocketException('socket is already opened')
        thread = None
        close_frame = None

        try:
            self.sock = WebSocket(self.get_mask_key, sockopt = sockopt, sslopt = sslopt,
                                  fire_cont_frame = self.on_cont_message and True or False)
            self.sock.settimeout(getdefaulttimeout())
            self.sock.connect(self.url, header = self.header, cookie = self.cookie,
                              http_proxy_host = http_proxy_host, http_proxy_port = http_proxy_port,
                              http_no_proxy = http_no_proxy, http_proxy_auth = http_proxy_auth,
                              subprotocols = self.subprotocols)
            self._callback(self.on_open)

            if ping_interval:
                event= threading.Event()
                thread = threading.Thread(target = self._send_ping, args = (ping_interval, event))
                thread.setDeamon(True)
                thread.start()

            while self.sock.connected:
                r, w, e = select.select((self.sock.sock, ), (), (), ping_timeout)
                if not self.keep_running:
                    break
                if ping_timeout and self.last_ping_tm and time.time() - self.last_ping_tm > ping_timeout:
                    self.last_ping_tm = 0
                    raise WebSocketTimeoutException()

                if r:
                    op_code, frame = self.sock.recv_data_frame(True)
                    if op_code ==  ABNF.OPCODE_CLOSE:
                        close_frame = frame
                        break
                    elif op_code == ABNF.OPCODE_PING:
                        self._callback(self.on_ping, frame.data)
                    elif op_code == ABNF.OPCODE_PONG:
                        self._callback(self.on_pong, frame.data)
                    elif op_code == ABNF.OPCODE_CONT and self.on_cont_message:
                        self._callback(self.on_cont_message, frame.data, frame.fin)
                    else:
                        data = frame.data
                        if frame.opcode == ABNF.OPCODE_TEXT:
                            data = data.decode('utf-8')
                            self._callback(self.on_message, data)
        except Exception as e:
            self._callback(self.on_error, e)
        finally:
            if thread:
                event.set()
                thread.join()
                self.keep_running = False
            self.sock.close()
            tmpdata = close_frame.data if close_frame else None
            self._callback(self.on_close, *self._get_close_args(tmpdata))
            self.sock = None
