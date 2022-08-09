import functools
import hashlib
import json
import secrets
from decimal import Decimal
from time import time

import boto3
from pyramid.interfaces import ISession, ISessionFactory
from zope.interface import implementer


class RaceConditionException(Exception):
    pass


@implementer(ISessionFactory)
class DynamoDBSessionFactory:
    def __init__(
            self,
            table,
            cookie_name='session_id',
            max_age=None,
            path='/',
            domain=None,
            secure=None,
            httponly=True,
            samesite='Strict',
            timeout=1200,
            reissue_time=120,
    ):
        """
    A Pyramid session factory which will provide DynamoDB-backed
    sessions.

    The DynamoDB table must have a hash key ``sid`` of binary (B) type and a
    time-to-live on the ``exp`` attribute.

    :param table:  The DynamoDB table to use.  Can be a string or a boto3 Table
        object.
    :type table:  ``str`` or ``Table``
    :param cookie_name:  The name of the cookie used to store the session ID.
        Defaults to ``session_id``.
    :type cookie_name: str
    :param max_age:  The expiration time for the cookie in seconds.  Defaults
        to ``None`` (session-only cookie).
    :type max_age:  int
    :param path:  The path for the cookie.  Defaults to ``/``.
    :type path:  str
    :param domain:  The domain for the cookie.  Defaults to no domain.
    :type domain:  str
    :param secure:  If true, sets the ``secure`` flag for the cookie.  Defaults
        to ``None``, which will set the flag if the request is made via HTTPS.
    :type secure:  bool
    :param httponly:  If true, hide the cookie from Javascript by setting the
        ``HttpOnly`` flag.  Defaults to true.
    :type httponly:  bool
    :param samesite:  The SameSite property for the cookie, or ``None`` to
        disable the SameSite option.  Defaults to ``Strict``.
    :type samesite:  str
    :param timeout:  The number of seconds of inactivity before the session
        times out.  Defaults to ``1200``.  (20 minutes)
    :type timeout:  int
    :param reissue_time:  The number of seconds before the session is
        "reissued," meaning that the activity timeout is reset.  Reissuing
        performs a write to DynamoDB, so it is recommended to set this to a
        reasonably high value, such as 1/10 of the timeout.  Defaults to
        ``120``.  (2 minutes)
    :type reissue_time:  int

    """
        if isinstance(table, str):
            dynamodb = boto3.resource('dynamodb')
            table = dynamodb.Table(table)
        self.table = table

        self.cookie_name = cookie_name
        self.max_age = int(max_age) if max_age is not None else None
        self.path = path
        self.domain = domain
        self.secure = secure
        self.httponly = httponly
        self.samesite = samesite
        self.timeout = int(timeout) if timeout is not None else None
        self.reissue_time = (
            int(reissue_time) if reissue_time is not None else None
        )

    def __call__(self, request):
        session = self._load(request)
        callback = functools.partial(self._response_callback, session)
        request.add_response_callback(callback)
        return session

    def _hashed_id(self, session_id):
        return hashlib.sha256(session_id.encode('utf8')).digest()

    def _load(self, request):
        cookie_val = request.cookies.get(self.cookie_name)
        if not cookie_val:
            return DynamoDBSession.new_session()
        split = cookie_val.split('/')
        if len(split) < 2:
            return DynamoDBSession.new_session()
        session_id = split[0]
        version = Decimal(split[1])
        r = self.table.get_item(
            Key={'sid': self._hashed_id(session_id)},
            ConsistentRead=False,
        )
        if 'Item' not in r or r['Item']['ver'] < version:
            # If read fails, try again as a consistent read.
            r = self.table.get_item(
                Key={'sid': self._hashed_id(session_id)},
                ConsistentRead=True,
            )
        if 'Item' not in r:
            return DynamoDBSession.new_session()
        if r['Item']['exp'] < time():
            return DynamoDBSession.new_session()
        version = r['Item']['ver']
        issued_at = int(r['Item']['iss'])
        state = json.loads(r['Item']['dat'])
        return DynamoDBSession(session_id, state, version, issued_at)

    def _response_callback(self, session, request, response):
        if session.dirty:
            if session.new:
                self._create(session)
            else:
                self._update(session)
            self._set_cookie(request, response, session)
        elif not session.new and (
            self.reissue_time is None
            or time() - session.issued_at > self.reissue_time
        ):
            self._reissue(session)
            self._set_cookie(request, response, session)

    def _set_cookie(self, request, response, session):
        val = '/'.join([
            session.session_id,
            str(session.version),
        ])
        if self.secure is None:
            secure = request.scheme == 'https'
        else:
            secure = self.secure
        response.set_cookie(
            self.cookie_name,
            value=val,
            max_age=self.max_age,
            path=self.path,
            domain=self.domain,
            secure=secure,
            httponly=self.httponly,
            samesite=self.samesite,
        )

    def _update(self, session):
        old_version = session.version
        session.version += 1
        session.issued_at = Decimal(int(time()))
        try:
            self.table.put_item(
                Item={
                    'sid': self._hashed_id(session.session_id),
                    'dat': json.dumps(session.state),
                    'ver': session.version,
                    'iss': session.issued_at,
                    'exp': session.issued_at + self.timeout,
                },
                Expected={
                    'ver': {'Value': old_version},
                },
            )
        except (
                self.table.meta.client.exceptions
                .ConditionalCheckFailedException
        ):
            raise RaceConditionException(
                'Session was updated since last read.'
            )

    def _create(self, session):
        session.session_id = secrets.token_urlsafe()
        session.version = Decimal('1')
        session.issued_at = Decimal(int(time()))
        self.table.put_item(
            Item={
                'sid': self._hashed_id(session.session_id),
                'dat': json.dumps(session.state),
                'ver': session.version,
                'iss': session.issued_at,
                'exp': session.issued_at + self.timeout,
            },
            Expected={
                'sid': {'Exists': False},
            },
        )

    def _reissue(self, session):
        self.table.update_item(
            Key={'sid': self._hashed_id(session.session_id)},
            AttributeUpdates={
                'iss': {'Value': int(time())},
                'exp': {'Value': int(time()) + self.timeout},
            },
        )


def proxy(func):
    "Proxy dict functions to state dictionary."
    @functools.wraps(func)
    def wrapped(self, *args, **kwargs):
        return func(self.state, *args, **kwargs)

    return wrapped


def proxy_persist(func):
    "Proxy dict functions and mark session as dirty."
    @functools.wraps(func)
    def wrapped(self, *args, **kwargs):
        self.dirty = True
        return func(self.state, *args, **kwargs)

    return wrapped


@implementer(ISession)
class DynamoDBSession:
    def __init__(self, session_id, state, version, issued_at):
        self.session_id = session_id
        self.version = version
        self.issued_at = issued_at
        self.state = state
        self.dirty = False

    @classmethod
    def new_session(cls):
        return cls(None, dict(), None, None)

    @property
    def new(self):
        return self.session_id is None

    def changed(self):
        self.dirty = True

    def invalidate(self):
        self.dirty = True
        self.state = dict()

    # non-modifying dictionary methods
    get = proxy(dict.get)
    __getitem__ = proxy(dict.__getitem__)
    items = proxy(dict.items)
    values = proxy(dict.values)
    keys = proxy(dict.keys)
    __contains__ = proxy(dict.__contains__)
    __len__ = proxy(dict.__len__)
    __iter__ = proxy(dict.__iter__)

    # modifying dictionary methods
    clear = proxy_persist(dict.clear)
    update = proxy_persist(dict.update)
    setdefault = proxy_persist(dict.setdefault)
    pop = proxy_persist(dict.pop)
    popitem = proxy_persist(dict.popitem)
    __setitem__ = proxy_persist(dict.__setitem__)
    __delitem__ = proxy_persist(dict.__delitem__)

    # flash API methods
    def flash(self, msg, queue='', allow_duplicate=True):
        storage = self.setdefault('_f_' + queue, [])
        if allow_duplicate or (msg not in storage):
            storage.append(msg)

    def pop_flash(self, queue=''):
        # We check if the queue is in the session first, because we don't want
        # to needlessly mutate the session.
        name = '_f_' + queue
        if name in self:
            return self.pop(name)
        else:
            return []

    def peek_flash(self, queue=''):
        return self.get('_f_' + queue, [])

    # CSRF API methods
    def new_csrf_token(self):
        token = secrets.token_hex()
        self['_csrft_'] = token
        return token

    def get_csrf_token(self):
        token = self.get('_csrft_', None)
        if token is None:
            token = self.new_csrf_token()
        return token
