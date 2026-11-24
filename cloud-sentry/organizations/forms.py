from django import forms
from django.utils.translation import gettext_lazy as _

from accounts.models import User
from organizations.models import Organization, OrganizationMembership


class OrganizationCreateForm(forms.ModelForm):
    class Meta:
        model = Organization
        fields = ("name", "description")
        widgets = {
            "description": forms.Textarea(attrs={"rows": 4}),
        }


class OrganizationMemberForm(forms.Form):
    email = forms.EmailField(label=_("User email"))
    role = forms.ChoiceField(choices=OrganizationMembership.Role.choices, label=_("Organization role"))

    def __init__(self, *args, organization=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.organization = organization
        self.fields["role"].choices = [
            (OrganizationMembership.Role.ADMIN, "Security Administrator"),
            (OrganizationMembership.Role.ANALYST, "Security Analyst"),
            (OrganizationMembership.Role.VIEWER, "Viewer"),
        ]

    def clean_email(self):
        email = self.cleaned_data["email"].lower()
        user = User.objects.filter(email__iexact=email, is_active=True).first()
        if not user:
            raise forms.ValidationError(_("No active CloudSentry user has this email address."))
        if self.organization and OrganizationMembership.objects.filter(
            user=user, organization=self.organization, is_active=True
        ).exists():
            raise forms.ValidationError(_("This user is already an active member."))
        self.user = user
        return email
