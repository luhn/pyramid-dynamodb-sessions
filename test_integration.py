import hashlib
import secrets
from decimal import Decimal
from time import time

import boto3
import pytest
from pyramid.config import Configurator
from pyramid.response import Response
from pyramid.testing import DummyRequest
from webtest import TestApp

from pyramid_dynamodb_sessions import (DynamoDBSession, DynamoDBSessionFactory,
                                       RaceConditionException)


@pytest.fixture(scope='session')
def table(request):
    # return boto3.resource('dynamodb').Table('sessiontest')
    tablename = f'DynamoDBSession-{ int(time()) }'
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.create_table(
        TableName=tablename,
        KeySchema=[
            {
                'AttributeName': 'sid',
                'KeyType': 'HASH'
            },
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'sid',
                'AttributeType': 'B'
            },
        ],
        BillingMode='PAY_PER_REQUEST',
    )
    boto3.client('dynamodb').get_waiter('table_exists')\
        .wait(TableName=tablename)

    def delete_table():
        table.delete()
    request.addfinalizer(delete_table)

    return table


def test_load_invalid_session_id(table):
    factory = DynamoDBSessionFactory(table, cookie_name='cook')
    request = DummyRequest()
    request.cookies['cook'] = secrets.token_urlsafe() + '/1'
    session = factory(request)
    assert session.new


def test_load_session(table):
    session_id = secrets.token_urlsafe()
    hashed_id = hashlib.sha256(session_id.encode('utf8')).digest()
    table.put_item(
        Item={
            'sid': hashed_id,
            'ver': 2,
            'dat': '{"a": "b"}',
            'iss': int(time()),
            'exp': int(time() + 1000),
        },
    )
    factory = DynamoDBSessionFactory(table, cookie_name='cook')
    request = DummyRequest()
    request.cookies['cook'] = session_id + '/2'
    session = factory(request)
    assert session.state == {'a': 'b'}
    assert session.version == Decimal('2')


def test_save_new_session(table):
    factory = DynamoDBSessionFactory(table, secure=True)
    session = DynamoDBSession.new_session()
    session['a'] = 'b'
    request = DummyRequest()
    response = Response()
    factory._response_callback(session, request, response)
    value = response.headerlist[-1][1].split(';')[0]
    cookie_val = value.partition('=')[2]
    session_id, version = cookie_val.split('/')
    assert version == '1'
    hashed_id = hashlib.sha256(session_id.encode('utf8')).digest()
    item = table.get_item(
        Key={'sid': hashed_id},
        ConsistentRead=True,
    )['Item']
    assert item['dat'] == '{"a": "b"}'


def test_save_existing_session(table):
    session_id = secrets.token_urlsafe()
    hashed_id = hashlib.sha256(session_id.encode('utf8')).digest()
    table.put_item(
        Item={
            'sid': hashed_id,
            'ver': 2,
        },
    )
    factory = DynamoDBSessionFactory(table, secure=True)
    session = DynamoDBSession(session_id, {'a': 'b'}, Decimal('2'), 123)
    session.dirty = True
    request = DummyRequest()
    response = Response()
    factory._response_callback(session, request, response)
    item = table.get_item(
        Key={'sid': hashed_id},
        ConsistentRead=True,
    )['Item']
    assert item['dat'] == '{"a": "b"}'
    assert item['ver'] == Decimal('3')


def test_save_race_condition(table):
    session_id = secrets.token_urlsafe()
    hashed_id = hashlib.sha256(session_id.encode('utf8')).digest()
    table.put_item(
        Item={
            'sid': hashed_id,
            'ver': 2,
        },
    )
    factory = DynamoDBSessionFactory(table, secure=True)
    session = DynamoDBSession(session_id, {'a': 'b'}, Decimal('2'), 123)
    session.dirty = True
    request = DummyRequest()
    response = Response()
    factory._response_callback(session, request, response)
    with pytest.raises(RaceConditionException):
        session.version = Decimal('2')
        factory._response_callback(session, request, response)


def test_reissue_session(table):
    session_id = secrets.token_urlsafe()
    hashed_id = hashlib.sha256(session_id.encode('utf8')).digest()
    table.put_item(
        Item={
            'sid': hashed_id,
            'ver': 2,
        },
    )
    factory = DynamoDBSessionFactory(table, secure=True)
    session = DynamoDBSession(session_id, {'a': 'b'}, Decimal('2'), 1000)
    request = DummyRequest()
    response = Response()
    factory._response_callback(session, request, response)
    item = table.get_item(
        Key={'sid': hashed_id},
        ConsistentRead=True,
    )['Item']
    assert item['iss'] > 1000
    assert item['ver'] == Decimal('2')


# Test application


@pytest.fixture
def wsgiapp(table):
    factory = DynamoDBSessionFactory(table)
    config = Configurator(
        settings={},
        session_factory=factory,
    )

    # Basic endpoints
    config.add_route('index', '/')
    config.add_view(
        lambda _, r: dict(r.session),
        route_name='index',
        request_method='GET',
        renderer='json',
    )
    config.add_view(
        lambda _, r: r.session.update(r.json_body),
        route_name='index',
        request_method='PUT',
        renderer='json',
    )

    # Flash endpoints
    config.add_route('flash', '/flash')

    config.add_view(
        lambda _, r: r.session.pop_flash(),
        route_name='flash',
        request_method='GET',
        renderer='json',
    )
    config.add_view(
        lambda _, r: r.session.flash(r.json_body),
        route_name='flash',
        request_method='POST',
        renderer='json',
    )

    return config.make_wsgi_app()


@pytest.fixture
def testapp(wsgiapp):
    return TestApp(wsgiapp)


def test_app(testapp):
    assert testapp.get('/').json == {}
    testapp.put_json('/', {'a': 'b'})
    assert testapp.get('/').json == {'a': 'b'}
    testapp.put_json('/', {'c': 'd'})
    assert testapp.get('/').json == {'a': 'b', 'c': 'd'}


def test_flash(testapp):
    assert testapp.get('/flash').json == []
    testapp.post_json('/flash', 'a')
    assert testapp.get('/flash').json == ['a']
    assert testapp.get('/flash').json == []
