#!/usr/bin/env python3
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
import http


#
#   Websocket HTTP request initiation. Altough the rfc does
#   not define a maximum header length for http requests,
#   most web servers do. This implementation defines the
#   maximum header size as 8k. The websocket initiation
#   does not carry a payload and a large headers should
#   be very unusual. 8k should be sufficient.
#
MAX_HTTP_HEADERSIZE = 2**13


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
class WSError(Exception):
    """
        Base class for all Websocket Exceptions.
    """
    def __init__(self, msg):
        Exception.__init__(self, msg)


class WSRequestError(WSError):
    """
        All errors regarding websocket client requests.
        If such an exception gets thrown, it is usually
        an error produced by the client.
    """
    def __init__(self, msg):
        WSError.__init__(self, msg)


class WSResponseError(WSError):
    """
        All errors regarding websocket server faults.
        Usually state errors.
    """
    def __init__(self, msg):
        WSError.__init__(self, msg)


#
#   HTTP Request Modeling
#
#   It should be discussed if it is necessary
#   to model http requests to the server.
#   While it is (from the programmers view) a
#   very convenient way to retrieve arbitrary
#   information about the request, it may be to
#   much effort regarding performance.
#
#   For now it stays the way it is, because high
#   performance is not the main goal at the moment.
#
class HTTPRequest():
    """
        Every websocket communications starts
        with an http request. Objects of this
        class are modeling these requests and
        provide an easy interface to interact
        with these requests.
    """
    def _parse_reqline(self, statusline):
        """
            Check the first HTTP line.
        """
        try:
            meth, res, prot = statusline.split()
            return meth, res, prot
        except ValueError:
            raise http.BadStatusLine(statusline)

    def _parse_header(self, headerlines):
        """
            Maps all key-value http header
            pairs to a dictionary.
        """
        for headerline in headerlines:
            if not headerline:
                break
            key, val = re.split(':', headerline, maxsplit=1)
            self.header[key.lower().strip()] = val.strip()

    def _parse_protocol(self, protocolstr):
        """
            Determine the HTTP protocol version and return
            it as a number. 9 stands for version 0.9, 10
            for 1.0, 11 for 1.1 and so on.
        """
        #
        #   As per rfc 2616, section 3.1.
        #   However, to determine a sub-version
        #   is not required since the WebSocket
        #   protocol only requires the http version
        #   to be greater or equal to 1.1.
        #
        regex = r'HTTP/(\d+)\.(\d)(\d)*'
        match = re.match(regex, protocolstr).groups()
        return int(match[0]) * 10 + int(match[1])

    def __init__(self, asock):
        self._msg = asock.recv(MAX_HTTPHEADER_SIZE)
        header, body = re.split('\r\n\r\n', self._msg, maxsplit=1)
        header = header.splitlines()

        #   get the requests statusline and determine
        #   the http protocol version
        m, r, p = self._parse_reqline(header[0])
        self.version = self._parse_protocol(p)

        self.method = m
        self.resource = r
        self.protocol = p

        self.header = {}
        self._parse_header(header[1:])