const API_URL = "https://dm1sj67sl000.cloudfront.net/ingest";
const HMAC_SECRET = "test-secret"; // For demo; use env var in production

document.getElementById("piiForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const name = document.getElementById("name").value;
  const email = document.getElementById("email").value;
  const phone = document.getElementById("phone").value;

  const body = JSON.stringify({ name, email, phone });
  const timestamp = new Date().toISOString();

  // Compute HMAC
  const message = timestamp + body;
  const hmac = CryptoJS.HmacSHA256(message, HMAC_SECRET).toString(CryptoJS.enc.Hex);

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Timestamp": timestamp,
        "X-Signature": hmac,
      },
      body: body,
    });

    const result = await response.json();
    document.getElementById("result").textContent = JSON.stringify(result, null, 2);
  } catch (err) {
    document.getElementById("result").textContent = "Error: " + err.message;
  }
});
