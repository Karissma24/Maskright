# Maskright
A secure cloud app that collects personal data, encrypts and masks it in AWS, and displays only safe, anonymized information through a Streamlit dashboard.


# Streamlit Dashboard (Shreya)

This dashboard:
- Calls the `/query` API endpoint through CloudFront.
- Sends `X-Timestamp` and `X-Signature` (HMAC-SHA256) headers.
- Shows only **masked** PII records (name, email, phone) plus `created_at`.
- Displays simple metrics (total masked records, rows shown).

## Tech Stack

- Streamlit
- Python `requests`
- Secure API via CloudFront + API Gateway + Lambda
- Data from DynamoDB (masked table only)

## Configuration

The app expects these secrets:

```toml
API_BASE_URL = "https://dm1sj67sl000.cloudfront.net"
HMAC_SECRET  = "<team HMAC secret>"
