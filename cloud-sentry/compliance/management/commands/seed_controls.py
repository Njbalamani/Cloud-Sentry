from django.core.management.base import BaseCommand

from compliance.controls import ensure_controls


class Command(BaseCommand):
    help = "Create or update CIS compliance controls."

    def handle(self, *args, **options):
        controls = ensure_controls()
        self.stdout.write(self.style.SUCCESS(f"Ensured {len(controls)} compliance controls."))
