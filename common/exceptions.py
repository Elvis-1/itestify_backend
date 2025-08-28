from http import HTTPStatus
from rest_framework.views import exception_handler
from rest_framework.exceptions import (
    AuthenticationFailed,
    ValidationError as DRFValidationError,
    APIException,
    PermissionDenied, 
    NotAuthenticated,
)

from django.core.exceptions import ValidationError as DjangoValidationError

from .responses import CustomResponse
from .error import ErrorCode
from functools import wraps

import logging

logger = logging.getLogger(__name__)


class RequestError(APIException):
    default_detail = "An error occured"

    def __init__(
        self, err_msg: str, err_code: str, status_code: int = 400, data: dict = None
    ) -> None:
        self.status_code = HTTPStatus(status_code)
        self.err_code = err_code
        self.err_msg = err_msg
        self.data = data

        super().__init__()



def custom_exception_handler(exc, context):
    try:
        response = exception_handler(exc, context)
        
        if isinstance(exc, AuthenticationFailed):
            exc_list = str(exc).split("DETAIL: ")
            return CustomResponse.error(
                message=exc_list[-1],
                status_code=401,
                err_code=ErrorCode.UNAUTHORIZED_USER,
            )
        elif isinstance(exc, RequestError):
            return CustomResponse.error(
                message=exc.err_msg,
                data=exc.data,
                status_code=exc.status_code,
                err_code=exc.err_code,
            )
        elif isinstance(exc, (DRFValidationError, DjangoValidationError)):
            errors = exc.message_dict if hasattr(exc, "message_dict") else exc.detail

            # Normalize errors to your response format
            if isinstance(errors, dict):
                first_error_msg = list(errors.values())[0]
                if isinstance(first_error_msg, list):
                    first_error_msg = first_error_msg[0]
            else:
                # sometimes Django ValidationError only has .messages (a list)
                first_error_msg = errors[0] if isinstance(errors, list) else str(errors)

            return CustomResponse.error(
                message=str(first_error_msg).capitalize(),
                status_code=422,
                err_code=ErrorCode.INVALID_ENTRY,
            )
        elif isinstance(exc, PermissionDenied):
            return CustomResponse.error(
                message="You don't have the permission to perform this operation.",
                status_code=403,
                err_code=ErrorCode.FORBIDDEN
            )
        elif isinstance(exc, NotAuthenticated):
            return CustomResponse.error(
                message="You are not logged in.",
                status_code=401,
                err_code=ErrorCode.UNAUTHORIZED_USER
            )
        else:
            # print("error:", exc)
            logger.exception("Unexpected error occured.")
            return CustomResponse.error(
                message="Something went wrong!",
                status_code=(
                    response.status_code if hasattr(response, "status_code") else 500
                ),
                err_code=ErrorCode.SERVER_ERROR,
            )
    except APIException as e:
        print("Server Error: ", e)
        return CustomResponse.error(
            message="Server Error", status_code=500, err_code=ErrorCode.SERVER_ERROR
        )
        

def handle_custom_exceptions(view_func):
    """
    Decorator to apply the custom exception handler to a specific method.
    """
    @wraps(view_func)
    def wrapper(self, request, *args, **kwargs):
        try:
            return view_func(self, request, *args, **kwargs)
        except Exception as exc:
            return custom_exception_handler(exc, {'view': self})
    return wrapper
