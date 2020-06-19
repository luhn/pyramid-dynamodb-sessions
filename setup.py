from setuptools import setup

VERSION = '0.1.0'

REQUIRES = [
    'boto3',
    'pyramid',
    'zope.interface',
]

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='pyramid-dynamodb-sessions',
    description='Pyramid sessions stored in DynamoDB',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/luhn/limited/',
    author='Theron Luhn',
    author_email='theron@luhn.com',
    version='0.1.0',
    py_modules=['pyramid_dynamodb_sessions'],
    python_requires='>=3.6',
    install_requires=REQUIRES,
)
