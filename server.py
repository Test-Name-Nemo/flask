from flask import Flask, jsonify, request
from flask.views import MethodView
from flask_bcrypt import Bcrypt
from pydantic import ValidationError
from sqlalchemy.exc import DisconnectionError, IntegrityError
from models import Session, User
from shema import CreatUser, UpdateUser

app = Flask("my_server")
bcrypt = Bcrypt(app)


def hash_password(password: str) -> str:
    password_bytes = password.encode()
    password_hashed_bytes = bcrypt.generate_password_hash(password_bytes)
    password_hashed = password_hashed_bytes.decode()
    return password_hashed


def check_password(password: str, hashed_password: str) -> bool:
    password = password.encode()
    hashed_password = hashed_password.encode()
    return bcrypt.check_password_hash(hashed_password, password)


class HttpError(Exception):

    def __init__(self, status_code, message):
        self.status_code = status_code
        self.message = message


@app.errorhandler(HttpError)
def error_handler(error: HttpError):
    response = jsonify({"error": error.message})
    response.status_code = error.status_code
    return response


def validate(schema_cls: type[CreatUser] | type[UpdateUser],
             json_data):
    try:
        return schema_cls(**json_data).dict(exclude_unset=True)
    except ValidationError as err:
        errors = err.errors()
        for error in errors:
            error.pop("ctx", None)
        raise HttpError(400, errors)


@app.before_request
def before_requests():
    session = Session()
    request.session = session


@app.after_request
def after_request(http_response):
    request.session.close()
    return http_response


def add_user(user):
    request.session.add(user)
    try:
        request.session.commit()
    except IntegrityError as er:
        raise HttpError(409, "user already exist")


def get_user_by_id(user_id) -> User:
    user = request.session.get(User, user_id)
    if user is None:
        raise HttpError(404, "user not found")
    return user
