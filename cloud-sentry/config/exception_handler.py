import uuid

from rest_framework.response import Response
from rest_framework.views import exception_handler


def api_exception_handler(exc, context):
    response = exception_handler(exc, context)
    request_id = getattr(context.get("request"), "request_id", None) or str(uuid.uuid4())
    if response is None:
        return Response(
            {
                "error": {
                    "code": "internal_error",
                    "message": "The request could not be completed.",
                    "request_id": request_id,
                }
            },
            status=500,
        )
    detail = response.data
    message = "The request was rejected."
    if isinstance(detail, dict) and "detail" in detail:
        message = str(detail["detail"])
    elif isinstance(detail, list) and detail:
        message = str(detail[0])
    response.data = {
        "error": {
            "code": f"http_{response.status_code}",
            "message": message,
            "details": detail,
            "request_id": request_id,
        }
    }
    return response
