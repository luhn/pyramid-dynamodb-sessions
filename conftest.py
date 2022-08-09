
def pytest_addoption(parser):
    parser.addoption(
        "--dynamodb",
        action="store",
        default=None,
        help="The endpoint URL for DynamoDB.",
    )

