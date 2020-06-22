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
            serializer=json,
            max_age=None,
            path='/',
            domain=None,
            secure=None,
            httponly=True,
            samesite='Strict',
            timeout=1200,
            reissue_time=120,
            set_on_exception=True,
    ):
        """
    Configure a :term:`session factory` which will provide DynamoDB-backed
    sessions.  The return value of this function is a :term:`session factory`,
    which may be provided as the ``session_factory`` argument of a
    :class:`pyramid.config.Configurator` constructor, or used as the
    ``session_factory`` argument of the
    :meth:`pyramid.config.Configurator.set_session_factory` method.

    Parameters:

    ``serializer``
      An object with two methods: ``loads`` and ``dumps``.  The ``loads``
      method should accept bytes and return a Python object.  The ``dumps``
      method should accept a Python object and return bytes.  A ``ValueError``
      should be raised for malformed inputs.

    ``cookie_name``
      The name of the cookie used for sessioning. Default: ``'session'``.

    ``max_age``
      The maximum age of the cookie used for sessioning (in seconds).
      Default: ``None`` (browser scope).

    ``path``
      The path used for the session cookie. Default: ``'/'``.

    ``domain``
      The domain used for the session cookie.  Default: ``None`` (no domain).

    ``secure``
      The 'secure' flag of the session cookie. Default: ``False``.

    ``httponly``
      Hide the cookie from Javascript by setting the 'HttpOnly' flag of the
      session cookie. Default: ``False``.

    ``samesite``
      The 'samesite' option of the session cookie. Set the value to ``None``
      to turn off the samesite option.  Default: ``'Lax'``.

    ``timeout``
      A number of seconds of inactivity before a session times out. If
      ``None`` then the cookie never expires. This lifetime only applies
      to the *value* within the cookie. Meaning that if the cookie expires
      due to a lower ``max_age``, then this setting has no effect.
      Default: ``1200``.

    ``reissue_time``
      The number of seconds that must pass before the cookie is automatically
      reissued as the result of a request which accesses the session. The
      duration is measured as the number of seconds since the last session
      cookie was issued and 'now'.  If this value is ``0``, a new cookie
      will be reissued on every request accessing the session. If ``None``
      then the cookie's lifetime will never be extended.

      A good rule of thumb: if you want auto-expired cookies based on
      inactivity: set the ``timeout`` value to 1200 (20 mins) and set the
      ``reissue_time`` value to perhaps a tenth of the ``timeout`` value
      (120 or 2 mins).  It's nonsensical to set the ``timeout`` value lower
      than the ``reissue_time`` value, as the ticket will never be reissued.
      However, such a configuration is not explicitly prevented.

      Default: ``0``.

    ``set_on_exception``
      If ``True``, set a session cookie even if an exception occurs
      while rendering a view. Default: ``True``.

    """
        if isinstance(table, str):
            dynamodb = boto3.resource('dynamodb')
            table = dynamodb.Table(table)
        self.table = table

        self.cookie_name = cookie_name
        self.serializer = serializer
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
        self.set_on_exception = set_on_exception

    def __call__(self, request):
        session = self._load(request)
        callback = functools.partial(self._response_callback, session)
        request.add_response_callback(callback)
        return session

    def _hashed_id(self, session_id):
        return hashlib.sha256(session_id.encode('utf8')).digest()

    def _load(self, request):
        session_id = request.cookies.get(self.cookie_name)
        if not session_id:
            return DynamoDBSession.new_session()
        r = self.table.get_item(
            Key={'sid': self._hashed_id(session_id)},
        )
        if 'Item' not in r:
            return DynamoDBSession.new_session()
        if r['Item']['exp'] < time():
            return DynamoDBSession.new_session()
        version = r['Item']['ver']
        issued_at = int(r['Item']['iss'])
        state = self.serializer.loads(r['Item']['dat'])
        return DynamoDBSession(session_id, state, version, issued_at)

    def _response_callback(self, session, request, response):
        if session.dirty:
            if session.new:
                session_id = self._create(session)
            else:
                self._update(session)
                session_id = session.session_id
            self._set_cookie(request, response, session_id)
        elif not session.new and (
            self.reissue_time is None
            or time() - session.issued_at > self.reissue_time
        ):
            self._reissue(session)
            self._set_cookie(request, response, session.session_id)

    def _set_cookie(self, request, response, session_id):
        if self.secure is None:
            secure = request.scheme == 'https'
        else:
            secure = self.secure
        response.set_cookie(
            self.cookie_name,
            value=session_id,
            max_age=self.max_age,
            path=self.path,
            domain=self.domain,
            secure=secure,
            httponly=self.httponly,
            samesite=self.samesite,
        )

    def _update(self, session):
        try:
            self.table.put_item(
                Item={
                    'sid': self._hashed_id(session.session_id),
                    'dat': self.serializer.dumps(session.state),
                    'ver': session.version + 1,
                    'iss': int(time()),
                    'exp': int(time()) + self.timeout,
                },
                Expected={
                    'ver': {'Value': session.version},
                },
            )
        except(
                self.table.meta.client.exceptions
                .ConditionalCheckFailedException
        ):
            raise RaceConditionException(
                'Session was updated since last read.'
            )

    def _create(self, session):
        session_id = secrets.token_urlsafe()
        self.table.put_item(
            Item={
                'sid': self._hashed_id(session_id),
                'dat': self.serializer.dumps(session.state),
                'ver': Decimal('1'),
                'iss': int(time()),
                'exp': int(time()) + self.timeout,
            },
            Expected={
                'sid': {'Exists': False},
            },
        )
        return session_id

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
        return self.pop('_f_' + queue, [])

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
