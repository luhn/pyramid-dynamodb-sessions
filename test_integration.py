from time import time
import secrets
from decimal import Decimal
import hashlib
import pytest
import boto3
from pyramid.testing import DummyRequest
from pyramid.response import Response

from pyramid_dynamodb_sessions import (
    DynamoDBSessionFactory,
    DynamoDBSession,
    RaceConditionException,
)


@pytest.fixture(scope='session')
def table(request):
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
    request.cookies['cook'] = secrets.token_urlsafe()
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
    request.cookies['cook'] = session_id
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
    session_id = value.partition('=')[2]
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
