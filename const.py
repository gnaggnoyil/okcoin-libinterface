# encoding=UTF-8

import ssl

class CONST:
    WEBSOCKET_API_URL = 'wss://real.okcoin.com:10440/websocket/okcoinapi'
    SSL_OPT = {'cert_reqs': ssl.CERT_NONE}

    CURRENCY_BTC = 'btc'
    CURRENCY_LTC = 'ltc'

    INFO_LOG = 'data.log'
    ERR_LOG = 'error.log'
    FILE_LOGGER_NAME = 'trade_file'
    CONSOLE_LOGGER_NAME = 'trade_console'

    TRADE_HINT_NUM = 100

    WINDOW_SIZE = 50
    LOOKAHEAD = 10

    APIKEY = '46d84e75-8d39-4d6e-9ddf-5def2d6b3945'
    SECRETKEY = 'B6C37910BA2FF0B2D610DE4F88D2DA20'

    START_C = 's'
    CLOSE_C = 'c'
    PAUSE_C = 'p'
    RESUME_C = 'r'
