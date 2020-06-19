import boto3
from pyramid.session import manage_accessed, manage_changed


class RaceConditionException(Exception):
    pass


def proxy_refresh(func):
    @functool.wraps(func)
    def wrapped(self, *args, **kwargs):
        self.accessed = True
        return func(self.state, *args, **kwargs)

    return wrapped

def proxy_persist(func):
    @functool.wraps(func)
    def wrapped(self, *args, **kwargs):
        self.dirty = True
        self.accessed = True
        return func(self.state, *args, **kwargs)

    return wrapped


class DynamoDBSessionFactory:
    def __init__(
            self,
    table,
    cookie_name='session_id',
    serializer=None,
    max_age=None,
    path='/',
    domain=None,
    secure=False,
    httponly=False,
    samesite='Lax',
    timeout=1200,
    reissue_time=0,
        consistent_read=True,
        hash_alg=hashlib.sha256,
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

    if serializer is None:
        serializer = JSONSerializer()

    def __call__(self, request):
        session = self._load(request)
        callback = functools.partial(self._response_callback, session)
        request.set_response_callback(callback)
        return session

    def _load(self, request):
        _session_id = request.cookies.get(self._cookie_name)
        if not self.session_id:
            return DynamoDBSession()
        hashed_id = hash_alg(_session_id).digest()
        r = table.get_item(
            Key={'sid': hashed_id},
            ConsistentRead=self._consistent_read,
        )
        item = r['Item']
        if not item:
            return DynamoDBSession()
        if r['Item']['exp'] > now():
            return DynamoDBSession()
        version = r['Item']['ver']
        state = serializer.loads(r['Item']['dat'])
        return DynaomDBSession(session_id, version, state)

    def _response_callback(self, session, request, response):
        if session.dirty:
            if session.new:
                session_id = self._create(session)
                self._set_cookie(response, session_id)
            else:
                self._update(session)
                self._set_cookie(response, session.session_id)
        elif not session.new and session.accessed:
            if(
                    reissue_timeout is None
                    or time() - session.issued > reissue_timeout
            ):
                self._reissue(session)
                self._set_cookie(session.session_id)

    def _set_cookie(self, response, session_id)
        response.set_cookie(
            self._cookie_name,
            value=self._session_id,
            max_age=self._cookie_max_age,
            path=self._cookie_path,
            domain=self._cookie_domain,
            secure=self._cookie_secure,
            httponly=self._cookie_httponly,
            samesite=self._cookie_samesite,
        )

    def _update(self, session):
        hashed_id = hashalg(session.session_id).digest()
        try:
            table.put_item(
                Item={
                    'sid': hashed_id,
                    'dat': serializer.dumps(session.state),
                    'ver': session.version + 1,
                    'iss': int(time()),
                    'exp': int(time()) + timeout,
                },
                Expected={
                    'ver': {'Value': session.version},
                },
            )
        except table.ConditionCheckFailedException:
            raise RaceConditionException(
                'Session was updated since last read.'
            )

    def _create(self, session):
        session_id = secrets.token_urlsafe()
        hashed_id = hashalg(session_id).digest()
        try:
            table.put_item(
                Item={
                    'sid': hashed_id,
                    'dat': serializer.dumps(session.state),
                    'ver': Decimal('1'),
                    'iss': int(time()),
                    'exp': int(time()) + timeout,
                },
                Expected={
                    'sid': {'Exists': False},
                },
            )
        except table.ConditionCheckFailedException:
            raise RaceConditionException(
                'Session already exists.'
            )

    def _reissue(self, session):
        hashed_id = hashalg(session_id).digest()
        table.update_item(
            Key={'sid': hashed_id},
            AttributeUpdates={
                'iss': int(time()),
                'exp': int(time()) + timeout,
            },
        )



class DynamoDBSesssion:
    def __init__(self, session_id, version, state):
        self.session_id = session_id
        self.version = version
        self.state = state
        self.dirty = False
        self.accessed = False

    @classmethod
    def fresh(cls):
        return cls(None, None dict())

    def new(self):
        return self.session_id is None

    def changed(self):
        self.dirty = True
        self.accessed = True

    def invalidate(self):
        self.dirty = True
        self.accessed = True
        self.state = dict()

    # non-modifying dictionary methods
    get = proxy_refresh(dict.get)
    __getitem__ = proxy_refresh(dict.__getitem__)
    items = proxy_refresh(dict.items)
    values = proxy_refresh(dict.values)
    keys = proxy_refresh(dict.keys)
    __contains__ = proxy_refresh(dict.__contains__)
    __len__ = proxy_refresh(dict.__len__)
    __iter__ = proxy_refresh(dict.__iter__)

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
