import os
import json
import base64
import boto3
import hashlib
import hmac
import uuid
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# ---------- Environment Variables ----------
PII_MASKED_TABLE = os.environ.get("PII_MASKED_TABLE", "pii_records_masked")
PII_TOKEN_TABLE = os.environ.get("PII_TOKEN_TABLE", "pii_token_map")
HMAC_SECRET = os.environ.get("HMAC_SECRET")  # Retrieved securely from env
KMS_KEY_ID = os.environ.get("KMS_KEY_ID")   # KMS Key for encryption

# ---------- AWS Clients ----------
dynamodb = boto3.resource("dynamodb")
kms = boto3.client("kms")

masked_table = dynamodb.Table(PII_MASKED_TABLE)
token_table = dynamodb.Table(PII_TOKEN_TABLE)

# ---------- Helper Functions ----------

def verify_hmac(headers, body):
    """Verify timestamp freshness and HMAC signature."""
    timestamp = headers.get("X-Timestamp")
    signature = headers.get("X-Signature")

    if not timestamp or not signature:
        raise ValueError("Missing HMAC headers")

    # Reject requests older than 5 minutes
    now = datetime.now(timezone.utc)
    ts = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    if abs((now - ts).total_seconds()) > 300:
        raise ValueError("Timestamp skew too large")

    # Compute expected HMAC
    computed_hmac = hmac.new(
        key=HMAC_SECRET.encode("utf-8"),
        msg=(timestamp + body).encode("utf-8"),
        digestmod=hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, computed_hmac):
        raise ValueError("Invalid HMAC signature")


def validate_schema(data):
    """Ensure JSON has required fields."""
    for field in ["name", "email", "phone"]:
        if field not in data or not isinstance(data[field], str):
            raise ValueError(f"Missing or invalid field: {field}")


def mask_pii(name, email, phone):
    """Return masked versions of PII fields."""
    name_masked = name[0] + "*" * (len(name) - 1) if name else None

    if "@" in email:
        local, domain = email.split("@")
        email_masked = f"{local[0]}***@{domain[0]}****.{domain.split('.')[-1]}"
    else:
        email_masked = "***@***.***"

    phone_masked = f"***-***-{phone[-4:]}" if len(phone) >= 4 else "***-***-****"
    return name_masked, email_masked, phone_masked


def encrypt_pii(data):
    """Encrypt each field using AWS KMS."""
    encrypted = {}
    for key, value in data.items():
        if not value:
            encrypted[key] = None
            continue
        response = kms.encrypt(KeyId=KMS_KEY_ID, Plaintext=value.encode("utf-8"))
        encrypted[key] = base64.b64encode(response["CiphertextBlob"]).decode("utf-8")
    return encrypted

# ---------- Lambda Handler ----------

def lambda_handler(event, context):
    try:
        headers = {k: v for k, v in event.get("headers", {}).items()}
        body = event.get("body", "")

        # --- HMAC verification ---
        verify_hmac(headers, body)

        # --- Parse and validate ---
        data = json.loads(body)
        validate_schema(data)

        # --- Mask and encrypt ---
        name_masked, email_masked, phone_masked = mask_pii(data["name"], data["email"], data["phone"])
        encrypted_fields = encrypt_pii(data)

        # --- Generate record ID and timestamp ---
        record_id = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()

        # --- Store masked PII ---
        masked_table.put_item(Item={
            "id": record_id,
            "name_masked": name_masked,
            "email_masked": email_masked,
            "phone_masked": phone_masked,
            "created_at": now_iso
        })

        # --- Store encrypted PII (write-only) ---
        token_table.put_item(Item={
            "id": record_id,
            "name_enc": encrypted_fields["name"],
            "email_enc": encrypted_fields["email"],
            "phone_enc": encrypted_fields["phone"],
            "kek_id": KMS_KEY_ID,
            "created_at": now_iso
        })

        print(f"Stored masked+encrypted PII record {record_id} at {now_iso}")

        return {"statusCode": 201, "body": json.dumps({"id": record_id, "status": "stored"})}

    except ValueError as e:
        print(f"Validation/HMAC error: {e}")
        return {"statusCode": 401, "body": json.dumps({"error": str(e)})}

    except ClientError as e:
        print(f"AWS ClientError: {e}")
        return {"statusCode": 500, "body": json.dumps({"error": "Internal server error"})}

    except Exception as e:
        print(f"Unexpected error: {e}")
        return {"statusCode": 400, "body": json.dumps({"error": str(e)})}

