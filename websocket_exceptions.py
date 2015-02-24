# encoding=UTF-8

class WebSocketException(Exception):
    pass

class WebSocketConnectionClosedException(WebSocketException):
    pass

class WebSocketTimeoutException(WebSocketException):
    pass

class WebSocketProtocolException(WebSocketException):
    pass

class WebSocketPayloadException(WebSocketException):
    pass
