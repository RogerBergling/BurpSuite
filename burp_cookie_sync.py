
# Burp Suite Community - Cookie Sync
# Jython 2.7
#
# Captures all cookie names from:
# - Browser Cookie request headers
# - Server Set-Cookie response headers
#
# Injects all stored cookies for the matching host.
# Does not manually refresh authentication.

from burp import IBurpExtender, IHttpListener
from java.io import PrintWriter
from java.util import ArrayList, Arrays
from java.util.concurrent.locks import ReentrantLock
from email.utils import parsedate_tz, mktime_tz
import time


# ==========================================
# CONFIGURATION
# ==========================================

# True = also update browser/Proxy requests
# False = only observe Proxy requests
INJECT_PROXY = True

# True = inject into all other Burp tools
INJECT_OTHER_TOOLS = True

# False = allow HTTP and HTTPS hosts
# Secure cookies remain HTTPS-only
HTTPS_ONLY = False

# Print cookie names and counts, never values
DEBUG = True


# ==========================================
# PARSE SET-COOKIE
# ==========================================

def parse_set_cookie(line):
    parts = [p.strip() for p in line.split(';')]

    if not parts or '=' not in parts[0]:
        return None

    name, value = parts[0].split('=', 1)
    name = name.strip()

    if not name:
        return None

    attrs = {}

    for part in parts[1:]:
        k, _, v = part.partition('=')
        attrs[k.strip().lower()] = v.strip()

    now = time.time()
    expires_at = None
    expired = False

    if 'max-age' in attrs:
        try:
            age = int(attrs['max-age'])
            expired = age <= 0

            if not expired:
                expires_at = now + age
        except (TypeError, ValueError):
            pass

    elif 'expires' in attrs:
        try:
            date_parts = parsedate_tz(
                attrs['expires']
            )

            if date_parts:
                expires_at = float(
                    mktime_tz(date_parts)
                )
                expired = expires_at <= now

        except (TypeError, ValueError, OverflowError):
            pass

    return (
        name,
        value,
        'secure' in attrs,
        expires_at,
        expired
    )


# ==========================================
# BURP EXTENSION
# ==========================================

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self.cb = callbacks
        self.helpers = callbacks.getHelpers()

        self.out = PrintWriter(
            callbacks.getStdout(), True
        )

        self.err = PrintWriter(
            callbacks.getStderr(), True
        )

        self.lock = ReentrantLock()

        # hostname -> cookie name -> cookie data
        self.jar = {}

        # Track explicitly deleted cookies
        self.deleted = {}

        callbacks.setExtensionName(
            'All Hosts Cookie Sync'
        )

        callbacks.registerHttpListener(self)

        self.out.println(
            '[CookieSync] Loaded - all hosts'
        )

    # ======================================
    # HOST COOKIE STORAGE
    # ======================================

    def _scope(self, host):

        if host not in self.jar:
            self.jar[host] = {}
            self.deleted[host] = set()

        return (
            self.jar[host],
            self.deleted[host]
        )

    # ======================================
    # CAPTURE REQUEST COOKIES
    # ======================================

    def _learn_request(
        self, host, headers, https, browser
    ):

        jar, deleted = self._scope(host)

        for line in headers:
            line = str(line)

            if not line.lower().startswith('cookie:'):
                continue

            raw = line.split(':', 1)[1]

            for pair in raw.split(';'):

                if '=' not in pair:
                    continue

                name, value = pair.strip().split(
                    '=', 1
                )

                name = name.strip()

                if not name:
                    continue

                # Do not revive deleted cookies
                if name in deleted:
                    continue

                old = jar.get(name)

                if old is None:
                    jar[name] = {
                        'value': value,
                        'secure': https,
                        'expires': None,
                        'source': 'request'
                    }

                elif (
                    browser and
                    old['source'] == 'request'
                ):
                    old['value'] = value

    # ======================================
    # CAPTURE RESPONSE COOKIES
    # ======================================

    def _learn_response(self, host, headers):

        jar, deleted = self._scope(host)
        count = 0

        for line in headers:
            line = str(line)

            if not line.lower().startswith(
                'set-cookie:'
            ):
                continue

            parsed = parse_set_cookie(
                line.split(':', 1)[1].strip()
            )

            if parsed is None:
                continue

            name, value, secure, expires_at, expired = parsed

            count += 1

            if expired:

                jar.pop(name, None)
                deleted.add(name)

            else:

                jar[name] = {
                    'value': value,
                    'secure': secure,
                    'expires': expires_at,
                    'source': 'response'
                }

                deleted.discard(name)

        return count

    # ======================================
    # INJECT ALL HOST COOKIES
    # ======================================

    def _inject(
        self,
        message,
        request,
        request_info,
        host,
        https,
        tool
    ):

        jar, deleted = self._scope(host)
        now = time.time()

        cookie_pairs = []
        cookie_names = []

        for name in sorted(jar.keys()):

            cookie = jar[name]

            expires = cookie['expires']

            if (
                expires is not None and
                expires <= now
            ):
                deleted.add(name)
                continue

            if cookie['secure'] and not https:
                continue

            cookie_pairs.append(
                name + '=' + cookie['value']
            )

            cookie_names.append(name)

        # Rebuild headers, excluding old Cookie
        headers = ArrayList()

        for header in request_info.getHeaders():

            line = str(header)

            if not line.lower().startswith(
                'cookie:'
            ):
                headers.add(line)

        # Add every stored applicable cookie
        if cookie_pairs:

            headers.add(
                'Cookie: ' + '; '.join(cookie_pairs)
            )

        # Preserve binary request body
        body = Arrays.copyOfRange(
            request,
            request_info.getBodyOffset(),
            len(request)
        )

        message.setRequest(
            self.helpers.buildHttpMessage(
                headers,
                body
            )
        )

        if DEBUG:
            self.out.println(
                '[CookieSync] SENT %s [%s]: %d cookies (%s)' % (
                    host,
                    tool,
                    len(cookie_pairs),
                    ', '.join(cookie_names)
                )
            )

    # ======================================
    # HTTP LISTENER
    # ======================================

    def processHttpMessage(
        self,
        toolFlag,
        messageIsRequest,
        message
    ):

        try:
            service = message.getHttpService()

            if service is None:
                return

            host = str(
                service.getHost()
            ).lower().rstrip('.')

            protocol = str(
                service.getProtocol()
            ).lower()

            if not host:
                return

            if protocol not in ('http', 'https'):
                return

            if HTTPS_ONLY and protocol != 'https':
                return

            https = protocol == 'https'

            tool = str(
                self.cb.getToolName(toolFlag)
            )

            # ------------------------------
            # REQUEST
            # ------------------------------

            if messageIsRequest:

                request = message.getRequest()

                if request is None:
                    return

                info = self.helpers.analyzeRequest(
                    message
                )

                browser = (
                    toolFlag == self.cb.TOOL_PROXY
                )

                self.lock.lock()

                try:

                    # Learn cookies from the request
                    self._learn_request(
                        host,
                        info.getHeaders(),
                        https,
                        browser
                    )

                    if browser and not INJECT_PROXY:
                        return

                    if (
                        not browser and
                        toolFlag not in (
                            self.cb.TOOL_REPEATER,
                            self.cb.TOOL_INTRUDER
                        ) and
                        not INJECT_OTHER_TOOLS
                    ):
                        return

                    # Insert all captured host cookies
                    self._inject(
                        message,
                        request,
                        info,
                        host,
                        https,
                        tool
                    )

                finally:
                    self.lock.unlock()

            # ------------------------------
            # RESPONSE
            # ------------------------------

            else:

                response = message.getResponse()

                if response is None:
                    return

                info = self.helpers.analyzeResponse(
                    response
                )

                self.lock.lock()

                try:

                    count = self._learn_response(
                        host,
                        info.getHeaders()
                    )

                finally:
                    self.lock.unlock()

                if DEBUG and count:

                    self.out.println(
                        '[CookieSync] CAPTURED %s: %d Set-Cookie headers' % (
                            host,
                            count
                        )
                    )

        except Exception as exc:

            self.err.println(
                '[CookieSync] ERROR: ' + str(exc)
            )
