import uuid

from django.db import DatabaseError

from .services import organizations_for_user


class OrganizationContextMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.request_id = request.META.get("HTTP_X_REQUEST_ID") or str(uuid.uuid4())
        request.current_organization = None
        try:
            user = getattr(request, "user", None)
            if user and user.is_authenticated:
                organizations = organizations_for_user(user)
                active_id = request.session.get("active_organization_id")
                if active_id:
                    request.current_organization = next(
                        (item for item in organizations if str(item.id) == str(active_id)),
                        None,
                    )
                if request.current_organization is None:
                    request.current_organization = organizations.first()
                if request.current_organization:
                    request.session["active_organization_id"] = str(request.current_organization.id)
        except DatabaseError:
            request.current_organization = None
        response = self.get_response(request)
        response["X-Request-ID"] = getattr(request, "request_id", "")
        return response
