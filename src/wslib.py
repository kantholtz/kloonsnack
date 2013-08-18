#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   This is an implementation for the websocket protocol as
#   described in RFC 6455 (https://tools.ietf.org/html/rfc6455).
#
#   As of this writing not all functionality of the protocol
#   is implemented. More functionality will get incorporated
#   from time to time.
#
#   The project is hosted here:
#   https://github.com/dreadworks/kloonsnack
#
#   Contact me under nvri@dreadworks.de
#
#   This document is licensed under the GPL v2.
#

#
#   constants
#
MAX_HTTP_HEADER_SIZE = 2**13


#
#   websocket connection states
#
STATE_CONNECTING = 'connecting'
STATE_OPEN = 'open'
STATE_TIME_WAIT = 'time wait'
STATE_CLOSING = 'closing'
STATE_CLOSED = 'closed'


#
#   exception classes
#
class WSRequestError(Exception):
    """
        Base class for all Websocket Exceptions.
    """
    def __init__(self, msg):
        Exception.__init__(self, msg)
