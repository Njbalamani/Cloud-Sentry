from django.core.management.base import BaseCommand

from cloud_scanner.rules import ensure_rules


class Command(BaseCommand):
    help = "Create or update CloudSentry scan rules."

    def handle(self, *args, **options):
        rules = ensure_rules()
        self.stdout.write(self.style.SUCCESS(f"Ensured {len(rules)} scan rules."))
