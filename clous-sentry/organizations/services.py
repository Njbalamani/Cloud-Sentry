from django.db import transaction
from django.utils.text import slugify

from accounts.models import User

from .models import Organization, OrganizationMembership


def create_organization_with_owner(name, owner, slug_source=None, description=""):
    source = slug_source or name
    with transaction.atomic():
        organization = Organization.objects.create(
            name=name.strip(),
            description=description.strip(),
            created_by=owner,
        )
        if source and source.strip() != name.strip():
            organization.slug = f"{slugify(source) or 'organization'}-{organization.id}"
            organization.save(update_fields=["slug"])
        OrganizationMembership.objects.create(
            user=owner,
            organization=organization,
            role=OrganizationMembership.Role.OWNER,
            is_active=True,
        )
    return organization


def add_member(organization, email, role, added_by=None):
    user = User.objects.get(email__iexact=email.strip())
    membership, created = OrganizationMembership.objects.get_or_create(
        user=user,
        organization=organization,
        defaults={"role": role, "is_active": True},
    )
    if not created:
        membership.role = role
        membership.is_active = True
        membership.save(update_fields=["role", "is_active"])
    return membership


def set_active_organization(request, organization):
    from accounts.permissions import organization_role

    if organization_role(request.user, organization):
        request.session["active_organization_id"] = str(organization.id)
        request.current_organization = organization
        return True
    return False


def organizations_for_user(user):
    if not user.is_authenticated:
        return Organization.objects.none()
    if user.is_platform_admin:
        return Organization.objects.filter(is_active=True)
    return Organization.objects.filter(
        is_active=True,
        memberships__user=user,
        memberships__is_active=True,
    ).distinct()
