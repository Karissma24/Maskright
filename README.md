# Maskright
A secure cloud app that collects personal data, encrypts and masks it in AWS, and displays only safe, anonymized information through a Streamlit dashboard.


# Streamlit Dashboard (Shreya)
- Reads masked records via `GET /query` with HMAC headers.
- Shows table + simple metrics. No raw PII is fetched or stored.

## Local run
pip install -r requirements.txt
export API_BASE_URL=https://<api-gw-domain>
export HMAC_SECRET=<dev-secret>
streamlit run app.py
