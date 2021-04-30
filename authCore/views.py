from datetime import datetime

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.serializers.json import DjangoJSONEncoder
from django.core.signing import Signer
from django.http import JsonResponse
from django.utils.crypto import get_random_string
from django.views.decorators.csrf import csrf_exempt

from .models import User
# from .permissions import IsOwnerOrReadOnly
from .serializers import UserLoginSerializer, UserSerializer, UserListSerializer
from django.core import serializers

import json
from . import response
import base64
import hashlib

TOKEN_TIME_ALIVE = 25 * 60


@csrf_exempt
def user(request):
    """register a user in system"""

    if request.method == 'POST':
        try:
            required_fields = ["username", "email", "password", "role"]
            request_data = extract_request_data_post(request)

            # Validate inputs
            errors = validate_required_body_items(required_fields, request_data)
            if len(errors) > 0:
                return response.bad_request_response(errors)

            this_username = request_data['username']
            email = request_data['email']
            password = hashlib.md5(request_data['password'].encode('utf-8')).hexdigest()
            if request_data['role'] == "RESTAURANT":
                role = "RESTAURANT"
            else:
                role = "CUSTOMER"

            # Duplicate username error: another user already has chosen this username
            if User.objects.filter(username=this_username).count() != 0:
                return response.bad_request_response("Duplicate username!")

            new_user = User(username=this_username,
                            email=email,
                            password=password,
                            date_joined=datetime.now(),
                            role=role,
                            is_login=True
                            )
            new_user.save()
            token = create_token(this_username, email, role)
            return response.success_response(token)
        except:
            return response.internal_server_error_response()

    elif request.method == 'GET':
        try:
            users = User.objects.all()

            serialized_users = []
            for user_item in users.values():
                serialized_users.append(UserListSerializer(user_item).data)
            return response.success_response(serialized_users)
        except:
            return response.internal_server_error_response()

    return response.method_not_allowed_response()


def create_token(username, email, role):
    date = datetime.now()
    token_info = username + ":" + email + ":" + role + ":" + str(round(date.timestamp()))
    token_bytes = token_info.encode("ascii")
    base64_bytes = base64.b64encode(token_bytes)
    token = base64_bytes.decode("ascii")
    return token


def decode_token(token):
    date = datetime.now()
    base64_bytes = token.encode("ascii")
    token_bytes = base64.b64decode(base64_bytes)
    info = token_bytes.decode("ascii")
    return info.split(":")


def token_validation(token_creation_time, role):
    date = round(datetime.now().timestamp())
    if role != "INTERNAL" and (int(token_creation_time) + TOKEN_TIME_ALIVE) < date:
        return False
    return True


def extract_request_data_post(request):
    try:
        if len(request.POST.keys()) > 0:
            request_data = request.POST
        else:
            request_data = json.load(request)
        return request_data
    except:
        return {}


def extract_request_headers(request):
    request_data = request.headers
    return request_data


def validate_required_body_items(required_fields, request_data):
    errors = []
    for item in required_fields:
        if item not in request_data.keys():
            errors.append(item + " is required!")

    return errors


def validate_required_header_items(required_fields, request_headers):
    errors = []
    for item in required_fields:
        if item not in request_headers.keys():
            errors.append(item + " is required!")

    return errors


@csrf_exempt
def user_detail(request, pk):
    if request.method == "GET":
        try:
            user = User.objects.get(pk=pk)
        except Exception as e:
            if str(e) == "User matching query does not exist.":
                return response.not_found_response("User Not Found!")
            else:
                return response.internal_server_error_response()

        return response.success_response(UserListSerializer(user).data)
    return response.method_not_allowed_response()


@csrf_exempt
def login(request):
    if request.method == "PUT":
        try:
            required_fields = ["username", "password"]
            request_data = extract_request_data_post(request)
            errors = validate_required_body_items(required_fields, request_data)
            if len(errors) > 0:
                return response.bad_request_response(errors)
            this_username = request_data['username']
            password = hashlib.md5(request_data['password'].encode('utf-8')).hexdigest()
            user = User.objects.get(username=this_username)
            if password == user.password:
                token = create_token(this_username, user.email, user.role)
                user.is_login = True
                user.save()
                return response.success_response(token)
            else:
                return response.bad_request_response("Invalid credential info")
        except Exception as e:
            if str(e) == "User matching query does not exist.":
                return response.not_found_response("User Not Found!")
            else:
                return response.internal_server_error_response()
    return response.method_not_allowed_response()


@csrf_exempt
def logout(request):
    if request.method == "PUT":
        try:
            request_headers = extract_request_headers(request)
            required_fields = ["token"]

            errors = validate_required_header_items(required_fields, request_headers)
            if len(errors) > 0:
                return response.bad_request_response(errors)

            token = request_headers['token']
            try:
                info = decode_token(token)
            except:
                return response.un_authorized_response()
            token_is_valid = token_validation(info[3], info[2])
            if token_is_valid:
                user = User()
                user.username = info[0]
                user.email = info[1]
                user.role = info[2]
                user_obj = User.objects.get(username=user.username)
                if user_obj.is_login:
                    user_obj.is_login = False
                    user_obj.save()
                    return response.success_response("OK")
                else:
                    return response.un_authorized_response()
            else:
                return response.un_authorized_response()
        except Exception as e:
            if str(e) == "User matching query does not exist.":
                return response.un_authorized_response()
            else:
                return response.internal_server_error_response()

    return response.method_not_allowed_response()


@csrf_exempt
def verify_token(request):
    if request.method == 'POST':
        try:
            request_headers = extract_request_headers(request)
            required_fields = ["token"]

            errors = validate_required_header_items(required_fields, request_headers)
            if len(errors) > 0:
                return response.bad_request_response(errors)

            token = request_headers['token']
            try:
                info = decode_token(token)
            except:
                return response.un_authorized_response()
            token_is_valid = token_validation(info[3], info[2])
            if token_is_valid:
                user = User()
                user.username = info[0]
                user.email = info[1]
                user.role = info[2]
                if user.role != "INTERNAL":
                    user_obj = User.objects.get(username=user.username)
                    if user_obj.is_login:
                        return response.success_response(UserListSerializer(user).data)
                else:
                    return response.success_response(UserListSerializer(user).data)
            else:
                return response.un_authorized_response()
        except Exception as e:
            if str(e) == "User matching query does not exist.":
                return response.un_authorized_response()
            else:
                return response.internal_server_error_response()
    return response.method_not_allowed_response()
