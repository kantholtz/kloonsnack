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
import logging

#
#   All optional initialization that is not
#   part of the base functionality
#
log = logging.StreamHandler()
log.setFormatter(
    logging.Formatter(
        ' '.join([
            '$(asctime)s: ',
            '[wslib] [$(levelname)s] ',
            '[$(threadName)s] [$(funcName)s:$(lineno)s]',
            '$(message)s'
        ])
    )
)
log.setLevel(logging.ERROR)


def setVerbose(verbose=True):
    if verbose:
        log.setLevel(logging.INFO)
    else:
        log.setLevel(logging.ERROR)


def setQuiet(quiet=True):
    if quiet:
        log.disable(logging.CRITICAL)
    else:
        log.disable(logging.NOTSET)


#
#   Websocket HTTP request initiation. Altough the rfc does
#   not define a maximum header length for http requests,
#   most web servers do. This implementation defines the
#   maximum header size as 8k. The websocket initiation
#   does not carry a payload and a large header should
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
        log.info('HTTP parsing %s' % statusline)
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
        log.info('HTTP parsing header')
        for headerline in headerlines:
            if not headerline:
                break
            key, val = re.split(':', headerline, maxsplit=1)
            self.header[key.lower().strip()] = val.strip()
            log.info('HTTP got %d header lines' % len(self.header))

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
        log.info('HTTP parsing protocol version')
        regex = r'HTTP/(\d+)\.(\d)(\d)*'
        match = re.match(regex, protocolstr).groups()
        prot = int(match[0]) * 10 + int(match[1])

        log.info('HTTP protocol version %d detected' % prot)
        return prot

    def __init__(self, asock):
        log.info('HTTP create request object')
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


class WSConnection():
    """
        Handles all stages of a WebSocket connection.
    """
    def _greeting(self):
        """
            Handle the opening handshake.
            http://tools.ietf.org/html/rfc6455 Section 1.3
        """
        log.info('WS handling the handshake')

        # wrap the incoming request into
        # an http request object
        req = HTTPRequest(self)

        # check validity as per
        # rfc 6455, section 4.1
        if req.version < 11:
            raise WSRequestError('http version is lower than 1.1')

        # check host header field
        # as per rfc 3986, sections 3.2.2 & 3.2.3;
        # luckily urlparse (urllib.parse) is conform
        # to that specification.
        key = 'host'
        if not key in req.header:
            raise WSRequestError('missing host header field')

        try:
            url = urlparse.urlparse(req.header[key])
        except ValueError:
            raise WSRequestError('invalid host header field')

        # check upgrade header field
        key = 'upgrade'
        if key not in req.header:
            raise WSRequestError('missing upgrade header field')
        elif req.header[key].lower() != 'websocket':
            raise WSRequestError('invalid upgrade header field')

        # check connection header field
        key = 'connection'
        if key not in req.header:
            raise WSRequestError('missing connection header field')
        # TODO firefox sends "keep-alive, Upgrade"
        elif not req.header[key].lower().endswith('upgrade'):
            raise WSRequestError('invalid connection header field')

        # check origin header field
        key = 'origin'
        if key not in req.header:
            # TODO This means that it is a non-browser
            # connection. Not sure how to handle
            # that at the moment. Maybe a property can
            # be set to indicate the lack of this field.
            pass

        key = 'sec-websocket-version'
        if key not in req.header:
            raise WSRequestError('missing sec-websocket-version header field')
        elif req.header[key] != '13':
            raise WSRequestError('invalid sec-websocket-version header field')

        # check sec-websocket-key header field
        key = 'sec-websocket-key'
        if key not in req.header:
            raise WSRequestError('no sec-websocket-key header field')

        # craft the response key
        log.info('WS crafting the response key')
        guid = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
        key = req.header[key] + guid
        key = hashlib.sha1(key).digest()
        key = base64.b64encode(key)

        # high five to the client
        response = []
        response.append('%s %d %s' % (
            req.protocol,
            httplib.SWITCHING_PROTOCOLS,
            httplib.responses[httplib.SWITCHING_PROTOCOLS]
        ))
        headers = map(lambda s: ': '.join(s), {
            'Upgrade': 'websocket',
            'Connection': 'Upgrade',
            'Sec-WebSocket-Accept': key
        }.items())
        response.extend(headers)

        response = '\r\n'.join(response) + '\r\n\r\n'
        log.info('WS sending a high five to the client')
        self.send(response)

        self._state = STATE_OPEN
        log.info('WS state is now OPEN')

    def _read_header(self):
        """
            Every WebSocket frame has a header field of variable
            length based on the payload size. This method gathers
            all information from these header fields.
            http://tools.ietf.org/html/rfc6455 Section 5.2
        """
        log.info('WS reading frame header')
        buf = self.recv(2)
        fop, length = struct.unpack('BB', buf)

        # check if FIN is set (bit 7)
        fin = True if 2**7 & fop else False

        # get rsv values (bit 4-6)
        rsv = (0x70 & fop) >> 0x4

        # get op code (bit 0-3)
        opcode = (0xF & fop)

        # lets assume, for the moment,
        # that these flags must never be set
        # TODO implement rsv handling
        if rsv != 0:
            raise WSRequestError('one of the rsv bits is set')

        # masking
        masked = True if 2**7 & length else False
        if not masked:
            raise WSRequestError('incoming request is not masked')

        # determine payload length
        length -= 2**7
        if length == 126:
            buf = self.recv(2)
            length = struct.unpack('!H', buf)[0]
        elif length == 127:
            buf = self.recv(8)
            length = struct.unpack('!Q', buf)[0]

        # mask
        buf = self.recv(4)
        mask = struct.unpack('I', buf)[0]

        print('ws request:')
        print('fin: %s, rsv: %d, opcode %d' % (str(fin), rsv, opcode))
        print('masked: %s, length: %d' % (str(masked), length))
        print('masking key: 0x%x' % mask)

        log.info('WS analyzed frame header')
        self._handler(WSPayload(self, length, mask))

    def __init__(self):
        pass
