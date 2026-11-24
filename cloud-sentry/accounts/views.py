from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.views import LoginView
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.http import require_POST

from organizations.services import create_organization_with_owner

from .forms import LoginForm, ProfileForm, RegistrationForm
from .models import LoginAttempt

LOCKOUT_WINDOW_MINUTES = 15
LOCKOUT_THRESHOLD = 5


def client_ip(request):
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def record_attempt(request, email, success):
    LoginAttempt.objects.create(email=email.lower(), ip_address=client_ip(request), success=success)


def is_locked_out(email):
    since = timezone.now() - timezone.timedelta(minutes=LOCKOUT_WINDOW_MINUTES)
    failures = LoginAttempt.objects.filter(email__iexact=email, success=False, created_at__gte=since).count()
    return failures >= LOCKOUT_THRESHOLD


class CloudSentryLoginView(LoginView):
    template_name = "auth/login.html"
    authentication_form = LoginForm
    redirect_authenticated_user = True

    def form_valid(self, form):
        response = super().form_valid(form)
        record_attempt(self.request, form.cleaned_data["username"], True)
        if form.cleaned_data.get("remember_me"):
            self.request.session.set_expiry(60 * 60 * 24 * 14)
        else:
            self.request.session.set_expiry(0)
        messages.success(self.request, "Signed in to CloudSentry.")
        return response

    def form_invalid(self, form):
        email = form.data.get("username", "")
        if email:
            record_attempt(self.request, email, False)
        return super().form_invalid(form)

    def post(self, request, *args, **kwargs):
        email = request.POST.get("username", "")
        if email and is_locked_out(email):
            messages.error(request, "Too many failed sign-in attempts. Try again in 15 minutes.")
            return self.render_to_response(self.get_context_data(form=self.get_form()))
        return super().post(request, *args, **kwargs)


class RegistrationView(View):
    template_name = "auth/register.html"

    def get(self, request):
        if not getattr(settings, "ALLOW_PUBLIC_REGISTRATION", True):
            messages.error(request, "Public registration is disabled for this deployment.")
            return redirect("accounts:login")
        if request.user.is_authenticated:
            return redirect("dashboard:index")
        return render(request, self.template_name, {"form": RegistrationForm()})

    def post(self, request):
        if not getattr(settings, "ALLOW_PUBLIC_REGISTRATION", True):
            return HttpResponseForbidden()
        if request.user.is_authenticated:
            return redirect("dashboard:index")
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            create_organization_with_owner(
                name=form.cleaned_data["organization_name"],
                owner=user,
                slug_source=form.cleaned_data["organization_name"],
            )
            login(request, user)
            messages.success(request, "Your CloudSentry organization is ready.")
            return redirect("dashboard:index")
        return render(request, self.template_name, {"form": form})


@method_decorator(require_POST, name="dispatch")
class CloudSentryLogoutView(View):
    def post(self, request):
        logout(request)
        messages.success(request, "You have been signed out.")
        return redirect("accounts:login")


class ProfileView(View):
    template_name = "auth/profile.html"

    def get(self, request):
        form = ProfileForm(instance=request.user)
        return render(request, self.template_name, {"form": form})

    def post(self, request):
        form = ProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, "Profile updated.")
            return redirect("accounts:profile")
        return render(request, self.template_name, {"form": form})


login_view = CloudSentryLoginView.as_view()
register_view = RegistrationView.as_view()
logout_view = CloudSentryLogoutView.as_view()
profile_view = ProfileView.as_view()
