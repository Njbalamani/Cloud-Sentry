from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.utils.translation import gettext_lazy as _

from .models import User


class LoginForm(AuthenticationForm):
    username = forms.EmailField(label=_("Email address"), widget=forms.EmailInput(attrs={"autocomplete": "username"}))
    remember_me = forms.BooleanField(required=False, label=_("Keep me signed in"))


class RegistrationForm(UserCreationForm):
    organization_name = forms.CharField(max_length=150, label=_("Organization name"))
    full_name = forms.CharField(max_length=150, required=False, label=_("Full name"))

    class Meta:
        model = User
        fields = ("email", "full_name", "organization_name", "password1", "password2")

    def clean_email(self):
        email = self.cleaned_data["email"].lower()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError(_("An account with this email already exists."))
        return email


class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ("full_name", "email")
        widgets = {
            "full_name": forms.TextInput(attrs={"autocomplete": "name"}),
            "email": forms.EmailInput(attrs={"autocomplete": "email"}),
        }
