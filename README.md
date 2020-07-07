# pyramid-dynamodb-sessions

`pyramid-dynamodb-sessions` stores user sessions for Pyramid in DynamoDB.
DynamoDB sessions offer large storage (up to 400kb per session), confidentiality (the user can't see the contents of the session) and low operational overhead.

## Motiviation

Pyramid ships with cookie-based sessions by default.
This is a good option for many applications, but has several downsides:

- Data is unencrypted and can be be read by the user.
- Cookies are limited to 4kb of data.

Redis-backed sessions is another popular option, but requires operating a Redis server.

DynamoDB can store up to 400kb of data per session and requires no server management.
With On-Demand Capacitiy, you don't have to do any capacity planning and only pay for what you use.
You can also opt for Provisioned Capacity as a way to optimize costs.

## Getting Started

Before getting started, you should be familiar with AWS IAM and know how to grant permissions to your application.

To get started, first create a new DynamoDB table.
The table should have a hash key of `sid` as a binary type.
Time-to-live should be enabled on the `exp` attribute.
You can use the following AWS CLI command to create the table.

```sh
aws dynamodb create-table \
  --table-name mytable \
  --attribute-definitions AttributeName=sid,AttributeType=B \
  --key-schema AttributeName=sid,KeyType=HASH \
  --billing-mode=PAY_PER_REQUEST
aws dynamodb update-time-to-live \
  --table-name mytable \
  --time-to-live-specification "Enabled=true, AttributeName=exp"
```

To enable pyramid-dynamodb-sessions in your application, first make sure your application has the following permissions for your newly created table:

- `dynamodb:GetItem`
- `dynamodb:PutItem`
- `dynamodb:UpdateItem`
- `dynamodb:DeleteItem`

Next set your session factory to a `pyramid_dynamodb_sessions.DynamoDBSessionFactory` object.

```python
from pyramid.config import Configurator
from pyramid_dynamodb_sessions import DynamoDBSessionFactory


def app(config, **settings):
    config = Configurator(
        session_factory=DynamoDBSessionFactory('mytable'),
    )
    config.make_wsgi_app()
```

And that's it!
When your application adds data to the session, it will be persisted to DynamoDB and a unique session ID will be stored in the users cookie.

## Configuration

`DynamoDBSessionFactory` requires only one argument on initialization:  the table name.
You can also pass a [boto3 Table object](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb.html#table).
This is useful if you want control over the configuration of Boto3.

Additional arguments mostly deal with the session ID cookie and roughly match the arguments for
[Pyramid's built-in cookie sessions](https://docs.pylonsproject.org/projects/pyramid/en/latest/api/session.html#pyramid.session.SignedCookieSessionFactory).

* `table` —  The DynamoDB table to use.
  Can be a string or a boto3 Table object.
* `cookie_name` — The name of the cookie used to store the session ID.
  Defaults to `session_id`.
* `max_age` —  The expiration time for the cookie in seconds.
  Defaults to `None` (session-only cookie).
* `path` — The path for the cookie.  Defaults to `/`.
* `domain` —  The domain for the cookie.
  Defaults to no domain.
* `secure` — If true, sets the `secure` flag for the cookie.
  Defaults to `None`, which will set the flag if the request is made via HTTPS.
* `httponly` —  If true, hide the cookie from Javascript by setting the `HttpOnly` flag.
  Defaults to true.
* `samesite` — The SameSite property for the cookie, or `None` to disable the SameSite option.
  Defaults to `Strict`.
* `timeout` — The number of seconds of inactivity before the session times out.
  Defaults to `1200` (20 minutes).
* `reissue_time` — The number of seconds before the session is "reissued," meaning that the activity timeout is reset.
  Reissuing performs a write to DynamoDB, so it is recommended to set this to a reasonably high value, such as 1/10 of the timeout.
  Defaults to `120`  (2 minutes).
