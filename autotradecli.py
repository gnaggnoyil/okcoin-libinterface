# encoding=UTF-8

import json
import threading
import traceback
import sys
import logging
import hashlib
import collections
import queue

from const import CONST
import websocket_app
import websocket_core
import kbhit

import pdb

def _buildMySign(params, secretKey):
    sign = ''
    for key in sorted(params.keys()):
        sign += key + '=' + str(params[key]) + '&'
    return hashlib.md5((sign + 'secret_key=' + secretKey).encode('UTF-8')).hexdigest().upper()

def _clearQueue(theQueue):
    try:
        while True:
            theQueue.get(block = False)
    except queue.Empty:
        pass

class _Invoke(object):
    def __init__(self, logger):
        self.__logger = logger

    def __call__(self, callable, *args):
        if callable:
            try:
                return callable(*args)
            except Exception as e:
                self.__logger.error(e)
                _, _, tb = sys.exc_info()
                traceback.print_tb(tb)

def _joinThread(theThread):
    flag = False
    while not flag:
        try:
            theThread.join()
            flag = True
        except KeyboardInterrupt:
            continue

class AutoTradeCLI(object):

    def __init__(self, onDecision = None,
                 url = CONST.WEBSOCKET_API_URL,
                 sslopt = CONST.SSL_OPT,
                 apiKey = CONST.APIKEY,
                 secretKey = CONST.SECRETKEY,
                 currencyType = CONST.CURRENCY_BTC,
                 windowSize = CONST.WINDOW_SIZE,
                 infoLog = CONST.INFO_LOG,
                 errLog = CONST.ERR_LOG):
        self.__url = url
        self.__sslopt = sslopt
        self.__windowSize = windowSize
        self.__decideFn = onDecision
        self.__apiKey = apiKey
        self.__secretKey = secretKey
        self.__currencyType = currencyType

        self.__tradeQueue = None
        self.__productQueue = None

        self.__productSock = None
        self.__cosumeSock = None

        self.__productThread = None
        self.__cosumeThread = None

        self.__infoLog = infoLog
        self.__errLog = errLog

        self.__fileLogger = logging.getLogger(name = CONST.FILE_LOGGER_NAME)
        self.__fileLogger.setLevel(logging.INFO)
        infoHandler = logging.FileHandler(self.__infoLog)
        infoHandler.setLevel(logging.INFO)
        errHandler = logging.FileHandler(self.__errLog)
        errHandler.setLevel(logging.ERROR)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s: %(message)s')
        infoHandler.setFormatter(formatter)
        errHandler.setFormatter(formatter)
        self.__fileLogger.addHandler(infoHandler)
        self.__fileLogger.addHandler(errHandler)

        self.__invoke = _Invoke(self.__fileLogger)

        self.__consoleLogger = logging.getLogger(name = CONST.CONSOLE_LOGGER_NAME)
        self.__consoleLogger.setLevel(logging.INFO)
        consoleHandler = logging.StreamHandler()
        consoleHandler.setLevel(logging.INFO)
        self.__consoleLogger.addHandler(consoleHandler)

        self.__tradeReceived = 0
        self.__decisionMade = 0

        '''control flags'''
        self.__pending = False
        self.__stopped = True

    def __on_message(self, wsApp, message):
        respond = json.loads(message)
        data = sorted(respond[0]['data'], key = lambda x: x[0])
        for datum in data:
            self.__fileLogger.info('Receiving data: ' + str(datum))
            self.__tradeReceived += 1
            if (self.__tradeReceived % CONST.TRADE_HINT_NUM) == 0:
                self.__consoleLogger.info('%s trades received.' % self.__tradeReceived)
            self.__tradeQueue.append((datum[1], datum[4]))
        assert len(self.__tradeQueue) <= self.__tradeQueue.maxlen
        assert not self.__stopped
        if self.__pending:
            return None
        if len(self.__tradeQueue) >= self.__tradeQueue.maxlen:
            self.__productQueue.put(item = list(self.__tradeQueue), block = True)

    def __on_open(self, wsApp):
        if self.__currencyType == CONST.CURRENCY_BTC:
            wsApp.send("{'event': 'addChannel', 'channel': 'ok_btcusd_trades_v1'}")
        else:
            wsApp.send("{'event': 'addChannel', 'channel': 'ok_ltcusd_trades_v1'}")

    def __on_error(self, wsApp, error):
        self.__consoleLogger.error(error)
        self.__fileLogger.error(error)
        _, _, tb = sys.exc_info()
        traceback.print_tb(tb)

    def __productTradeInfo(self):
        '''websocket.enableTrace(True)'''
        if self.__productSock is not None:
            return None
        self.__productSock = websocket_app.WebSocketApp(url = self.__url,
                                                        on_open = self.__on_open,
                                                        on_message = self.__on_message,
                                                        on_error = self.__on_error)
        self.__productSock.run_forever(sslopt = self.__sslopt)

        '''on close'''
        assert self.__productSock is not None
        self.__productSock.close()
        self.__productSock = None

    def __startResponse(self, response):
        self.__decisionMade += 1
        self.__fileLogger.info('making decision No.' + str(self.__decisionMade) + ' : ' + str(response))
        if (self.__decisionMade * self.__windowSize) % CONST.TRADE_HINT_NUM == 0:
            self.__consoleLogger.info('%s decisions made' % self.__decisionMade)

        symbol = None
        if self.__currencyType == CONST.CURRENCY_BTC:
            symbol = 'btc_usd'
        if self.__currencyType == CONST.CURRENCY_LTC:
            symbol = 'ltc_usd'
        assert symbol is not None
        params = { 'api_key': self.__apiKey,
                   'symbol': symbol,
                   'type': response[0] }
        if response[0] == 'buy_market':
            params['price'] = response[1]
        elif response[0] == 'sell_market':
            params['amount'] = response[1]
        else:
            assert (response[0] == 'buy') or (response[0] == 'sell')
            params['price'] = response[1]
            params['amount'] = response[2]
        sign = _buildMySign(params, self.__secretKey)
        params['sign'] = sign
        obj = { 'event': 'addChannel',
                'channel': 'ok_spotusd_trade',
                'parameters': params }
        message = json.dumps(obj)
        self.__cosumeSock.send(message)

        result = self.__cosumeSock.recv()
        result = json.loads(result)[0]
        assert result['channel'] == 'ok_spotusd_trade'
        if result['success'] == 'true':
            data = json.loads(result['data'])
            return (True, data)
        else:
            return (False, result['errorcode'])

    def __cosumeTradeInfo(self):
        if self.__cosumeSock is not None:
            return None
        self.__cosumeSock = websocket_core.create_connection(self.__url, sslopt = self.__sslopt)
        while True:
            if self.__pending:
                continue
            if self.__stopped:
                break
            try:
                l = self.__productQueue.get(block = False)
            except queue.Empty:
                continue
            self.__invoke(self.__decideFn, l, self.__startResponse)
            '''self.__productQueue.task_done()'''
        '''on close'''
        assert self.__cosumeSock is not None
        self.__cosumeSock.close()
        self.__cosumeSock = None

    def __stopCLI(self):
        if self.__stopped:
            self.__consoleLogger.warning('Program already closed.')
            return None

        self.__stopped = True
        self.__pending = False

        assert self.__productSock is not None
        assert self.__cosumeSock is not None

        self.__consoleLogger.info('Stopping program')
        self.__fileLogger.info('Stopping program')

        self.__productSock.close()
        _joinThread(self.__productThread)
        self.__productThread = None
        _joinThread(self.__cosumeThread)
        self.__cosumeThread = None

        self.__tradeQueue.clear()
        self.__tradeQueue = None
        _clearQueue(self.__productQueue)
        self.__productQueue = None

        self.__consoleLogger.info('Program stopped.')
        self.__fileLogger.info('Program stopped.')

    def __pendCLI(self):
        if self.__stopped:
            self.__consoleLogger.warning('Program already closed.')
            return None
        if self.__pending:
            self.__consoleLogger.warning('Program already paused.')
            return None

        assert not self.__stopped
        assert not self.__pending

        self.__consoleLogger.info('Pausing program...')
        self.__fileLogger.info('Pausing program...')

        self.__pending = True
        '''wait till self.__productSock REALLY gets an on_message callback, to ensure thread safety'''
        '''while self.__productSock is None:
            pass
        self.__productSock.on_message = lambda message: None'''
        '''self.__productQueue = None'''
        ''' set __pending before set Queue to None'''
        _clearQueue(self.__productQueue)

        self.__consoleLogger.info('Program paused.')
        self.__fileLogger.info('Program paused.')

    def __resumeCLI(self):
        if self.__stopped:
            self.__consoleLogger.warning('Program already closed.')
            return None
        if not self.__pending:
            self.__consoleLogger.warning('Program already running.')
            return None

        assert not self.__stopped
        assert self.__pending

        self.__consoleLogger.info('Resuming program...')
        self.__fileLogger.info('Resuming program...')

        self.__pending = False

        self.__consoleLogger.info('Program resumed.')
        self.__fileLogger.info('Program resumed.')

    def __startCLI(self):
        #websocket.enableTrace(True)
        if not self.__stopped:
            self.__consoleLogger.warning('Program already running.')
            return None
        assert not self.__pending
        self.__consoleLogger.info('Starting program...')
        self.__fileLogger.info('Starting program...')

        self.__stopped = False
        self.__pending = False

        self.__tradeQueue = collections.deque(maxlen = self.__windowSize)
        self.__productQueue = queue.Queue()

        self.__productThread = threading.Thread(target = self.__productTradeInfo)
        self.__cosumeThread = threading.Thread(target = self.__cosumeTradeInfo)

        self.__productThread.start()
        self.__cosumeThread.start()

        self.__consoleLogger.info('Program started.')
        self.__fileLogger.info('Program started.')

    def runCLI(self):
        self.__consoleLogger.info(("Press '%s' to start the program.\n" +
                                  "Press '%s' to exit the program.\n" +
                                  "Press '%s' to pause the program (while still receiving data).\n" +
                                  "Press ''%s to resume the program (to continue processing inpit).")
                                  % (CONST.START_C, CONST.CLOSE_C, CONST.PAUSE_C, CONST.RESUME_C))
        self.__consoleLogger.info('Logs are written in file ' + self.__infoLog + ' and file ' + self.__errLog)

        kb = kbhit.KBHit()
        try:
            while True:
                try:
                    if not kb.kbhit():
                        continue
                    ch = kb.getch()
                    if ch == CONST.START_C:
                        self.__startCLI()
                        continue
                    if ch == CONST.CLOSE_C:
                        break
                    if ch == CONST.PAUSE_C:
                        self.__pendCLI()
                        continue
                    if ch == CONST.RESUME_C:
                        self.__resumeCLI()
                        continue
                except KeyboardInterrupt:
                    self.__consoleLogger.warning('Ctrl-C press, exiting...')
                    self.__fileLogger.warning('Ctrl-C press caught.')
                    break
        except Exception as e:
            self.__consoleLogger.error('Exception caught, stop running.')
            self.__fileLogger.error(e)
            _, _, tb = sys.exc_info()
            traceback.print_tb(tb)
        finally:
            kb.set_normal_term()
            self.__stopCLI()
            return None

if __name__ == "__main__":
# simple tests
    def __makeTrade(input, response):
        decision = ('buy_market', 0.0)
        result = response(decision)
        print(result)

    autoTrade = AutoTradeCLI(onDecision = __makeTrade)
    autoTrade.runCLI()
