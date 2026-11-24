from botocore.exceptions import BotoCoreError, ClientError
from django.utils import timezone

from .models import CloudAccount, CloudResource


def sanitize_aws_error(exc):
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        code = error.get("Code", "ClientError")
        message = error.get("Message", "The AWS request was rejected.")
    elif isinstance(exc, BotoCoreError):
        code = "ConnectionError"
        message = "The AWS endpoint could not be reached."
    else:
        code = "AssessmentError"
        message = "The cloud assessment could not be completed."
    return {"code": code, "message": str(message)[:300]}


def assert_read_only(cloud_account):
    if not cloud_account.is_read_only:
        raise PermissionError("CloudSentry only supports read-only assessment credentials.")


def test_connection(cloud_account):
    try:
        session = cloud_account.get_boto3_session()
        identity = session.client("sts").get_caller_identity()
        cloud_account.status = CloudAccount.Status.ACTIVE
        cloud_account.last_checked_at = timezone.now()
        cloud_account.save(update_fields=["status", "last_checked_at", "updated_at"])
        return {
            "success": True,
            "account_id": identity.get("Account"),
            "arn": identity.get("Arn"),
        }
    except Exception as exc:
        cloud_account.status = CloudAccount.Status.ERROR
        cloud_account.save(update_fields=["status", "updated_at"])
        return {"success": False, "error": sanitize_aws_error(exc)}


def upsert_resource(cloud_account, resource_id, resource_type, name="", region="", metadata=None, tags=None, is_demo=False):
    defaults = {
        "resource_type": resource_type,
        "name": name or resource_id,
        "region": region or cloud_account.region,
        "metadata": metadata or {},
        "tags": tags or {},
        "is_demo": is_demo,
    }
    resource, created = CloudResource.objects.update_or_create(
        cloud_account=cloud_account,
        resource_id=resource_id,
        defaults=defaults,
    )
    return resource, created
