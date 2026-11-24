from django.conf import settings

from accounts.permissions import organization_role
from organizations.services import organizations_for_user


def cloudsentry_context(request):
    if not getattr(request, "user", None) or not request.user.is_authenticated:
        return {
            "cloudsentry_name": "CLOUDSENTRY",
            "demo_mode": settings.CLOUDSENTRY["DEMO_MODE"],
            "current_organization": None,
            "current_organization_role": None,
            "user_organizations": [],
        }
    organization = getattr(request, "current_organization", None)
    return {
        "cloudsentry_name": "CLOUDSENTRY",
        "demo_mode": settings.CLOUDSENTRY["DEMO_MODE"],
        "current_organization": organization,
        "current_organization_role": organization_role(request.user, organization),
        "user_organizations": list(organizations_for_user(request.user)),
    }
