import hashlib
from decimal import Decimal
from time import time
from unittest.mock import Mock

from pyramid.response import Response
from pyramid.testing import DummyRequest

from pyramid_dynamodb_sessions import DynamoDBSession, DynamoDBSessionFactory


def test_factory_init():
    table = object()
    factory = DynamoDBSessionFactory(
        table,
        cookie_name='cook',
        max_age=123,
        path='/foo',
        domain='example.com',
        secure=True,
        httponly=False,
        samesite='Lax',
        timeout=123,
        reissue_time=12,
        set_on_exception=False,
    )
    assert factory.table is table
    assert factory.cookie_name == 'cook'
    assert factory.max_age == 123
    assert factory.path == '/foo'
    assert factory.domain == 'example.com'
    assert factory.secure
    assert not factory.httponly
    assert factory.samesite == 'Lax'
    assert factory.timeout == 123
    assert factory.reissue_time == 12
    assert not factory.set_on_exception


def test_factory_new_session():
    "No session cookie."
    factory = DynamoDBSessionFactory(None)
    request = DummyRequest()
    session = factory(request)
    assert session.new


def test_factory_existing_session():
    "Fetch session from DynamoDB."
    table = Mock()
    table.get_item = Mock(return_value={
        'Item': {
            'dat': '{"a": "b"}',
            'ver': Decimal('1'),
            'iss': Decimal('1000000'),
            'exp': Decimal(int(time() + 100)),
        },
    })
    factory = DynamoDBSessionFactory(table, cookie_name='cook')
    request = DummyRequest()
    request.cookies['cook'] = 'a/1'
    hashed_id = hashlib.sha256(b'a').digest()
    session = factory(request)
    table.get_item.assert_called_once_with(
        Key={'sid': hashed_id},
        ConsistentRead=False,
    )
    assert session.session_id == 'a'
    assert session.version == Decimal('1')
    assert session.issued_at == Decimal('1000000')
    assert session.state == {'a': 'b'}


def test_factory_invalid_id():
    "Session ID doesn't exist."
    table = Mock()
    table.get_item = Mock(return_value={})
    factory = DynamoDBSessionFactory(table, cookie_name='cook')
    request = DummyRequest()
    request.cookies['cook'] = 'a/1'
    session = factory(request)
    assert session.new


def test_factory_expired():
    "Session exists but is expired"
    table = Mock()
    table.get_item = Mock(return_value={
        'Item': {
            'exp': Decimal(int(time() - 100)),
        },
    })
    factory = DynamoDBSessionFactory(table, cookie_name='cook')
    request = DummyRequest()
    request.cookies['cook'] = 'a'
    session = factory(request)
    assert session.new


def test_factory_save_new_session():
    table = Mock()
    session = DynamoDBSession.new_session()
    session['a'] = 'b'
    factory = DynamoDBSessionFactory(
        table,
        cookie_name='cook',
        secure=True,
        timeout=1000,
    )
    request = object()
    response = Response()
    factory._response_callback(session, request, response)
    assert response.headerlist[-1][0] == 'Set-Cookie'
    table.put_item.assert_called_once()
    args = table.put_item.call_args[1]
    assert args['Item']['sid']
    assert args['Item']['dat'] == '{"a": "b"}'
    assert args['Item']['ver'] == Decimal('1')
    assert time() - 1 < args['Item']['iss'] < time()
    assert time() + 999 < args['Item']['exp'] < time() + 1000
    assert args['Expected'] == {'sid': {'Exists': False}}


def test_factory_save_update_session():
    table = Mock()
    session = DynamoDBSession('a', dict(), Decimal('2'), 123)
    session['a'] = 'b'
    factory = DynamoDBSessionFactory(
        table,
        cookie_name='cook',
        secure=True,
        timeout=1000,
    )
    request = object()
    response = Response()
    factory._response_callback(session, request, response)
    assert response.headerlist[-1][0] == 'Set-Cookie'
    table.put_item.assert_called_once()
    args = table.put_item.call_args[1]
    assert args['Item']['sid'] == hashlib.sha256(b'a').digest()
    assert args['Item']['dat'] == '{"a": "b"}'
    assert args['Item']['ver'] == Decimal('3')
    assert time() - 1 < args['Item']['iss'] < time()
    assert time() + 999 < args['Item']['exp'] < time() + 1000
    assert args['Expected'] == {'ver': {'Value': Decimal('2')}}


def test_factory_save_reissue_session():
    table = Mock()
    issued_at = time() - 15
    session = DynamoDBSession('a', dict(), Decimal('2'), issued_at)
    factory = DynamoDBSessionFactory(
        table,
        secure=True,
        timeout=1000,
        reissue_time=10,
    )
    request = object()
    response = Response()
    factory._response_callback(session, request, response)
    assert response.headerlist[-1][0] == 'Set-Cookie'
    table.update_item.assert_called_once()
    args = table.update_item.call_args[1]
    assert args['Key'] == {'sid': hashlib.sha256(b'a').digest()}
    assert time() - 1 < args['AttributeUpdates']['iss']['Value'] < time()
    assert (
        time() + 999 < args['AttributeUpdates']['exp']['Value']
        < time() + 1000
    )


def test_factory_set_cookie_settings():
    factory = DynamoDBSessionFactory(
        None,
        cookie_name='abc',
        path='/foo',
        domain='localhost',
        secure=True,
        httponly=True,
        samesite='Lax',
    )
    request = DummyRequest()
    response = Response()
    session = DynamoDBSession('sid', dict(), Decimal('2'), 123)
    factory._set_cookie(request, response, session)
    cookieval = response.headerlist[-1][1]
    params = {x.strip() for x in cookieval.split(';')}
    assert params == {
        'abc=sid/2',
        'Domain=localhost',
        'Path=/foo',
        'secure',
        'HttpOnly',
        'SameSite=Lax',
    }


def test_factory_set_cookie_secure():
    factory = DynamoDBSessionFactory(
        None,
        secure=None,
    )
    request = DummyRequest()
    request.scheme = 'https'
    response = Response()
    session = DynamoDBSession('sid', dict(), Decimal('2'), 123)
    factory._set_cookie(request, response, session)
    cookieval = response.headerlist[-1][1]
    params = {x.strip() for x in cookieval.split(';')}
    assert 'secure' in params


def test_factory_response_callback():
    "Make sure that fetching a session registers a response callback."
    factory = DynamoDBSessionFactory(None)
    factory._response_callback = Mock()
    request = DummyRequest()
    response = object()
    session = factory(request)
    assert len(request.response_callbacks) == 1
    request.response_callbacks[0](request, response)
    factory._response_callback.assert_called_once_with(
        session, request, response,
    )
