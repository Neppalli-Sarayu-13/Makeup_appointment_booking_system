
import os
from itsdangerous import URLSafeTimedSerializer

secret_key = os.environ["TOKEN_SECRET_KEY"]
token_salt = os.environ["TOKEN_SALT"]


def endata(data):
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.dumps(data, salt=token_salt)


def dndata(data):
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.loads(data, salt=token_salt)
