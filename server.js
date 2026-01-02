const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.listen(4000, () => {
  console.log("Auth Server running on http://localhost:4000");
});

// Fake database (clients, codes, tokens)
  // we skipped the Identity Check: The server checks if the user has a session cookie.
  //     If No: The server redirects the user to a Login Page (username/password/2FA).
  //     If Yes: The server shows a Consent Screen ("App X wants to access your email. Allow?").
const clients = {
  "client123": {
    redirectUris: ["http://localhost:3000/callback"]  // creating an allow list for redirects
  }
};

const authorizationCodes = new Map();
const accessTokens = new Map();


app.get("/authorize", (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    code_challenge,  //the hashed code challenge 
    code_challenge_method // specification of the hash used 
  } = req.query;

  // 1. Validate response type
  if (response_type !== "code") {
    return res.status(400).send("Unsupported response_type");
  }

  // 2. Validate client
  const client = clients[client_id];
  if (!client) {
    return res.status(400).send("Invalid client_id");
  }

  // 3. Validate redirect URI
  if (!client.redirectUris.includes(redirect_uri)) {
    return res.status(400).send("Invalid redirect_uri");  // checking the redirect uri against the allow list
  }

  // 4. Enforce PKCE
  if (!code_challenge || code_challenge_method !== "S256") {
    return res.status(400).send("PKCE required");
  }


  // ---- Fake login success ----
  const authorizationCode = crypto.randomBytes(32).toString("hex"); // Think of this as a "Claim Ticket" a user gives you. It proves that the user just logged in and gave you permission.
  console.log("authorization code :" + authorizationCode + " for client : " + client_id);

  authorizationCodes.set(authorizationCode, {
    client_id,
    redirect_uri,
    code_challenge
  });

  // Redirect back to client
  const redirectUrl = `${redirect_uri}?code=${authorizationCode}`; // possible attack vector if 
  res.redirect(redirectUrl);
});


app.post("/token", (req, res) => {
  const {
    grant_type,
    code,
    redirect_uri,
    client_id,
    code_verifier
  } = req.body;

  if (grant_type !== "authorization_code") {
    return res.status(400).json({ error: "unsupported_grant_type" });
  }

  const storedCode = authorizationCodes.get(code);
  if (!storedCode) {
    return res.status(400).json({ error: "invalid_code" });
  }

  // Validate client + redirect_uri binding
  if (
    storedCode.client_id !== client_id ||
    storedCode.redirect_uri !== redirect_uri
  ) {
    return res.status(400).json({ error: "invalid_request" });
  }

  // 🔐 PKCE verification
  const hashedVerifier = crypto.createHash("sha256").update(code_verifier).digest("base64url");

  if (hashedVerifier !== storedCode.code_challenge) {
    return res.status(400).json({ error: "invalid_code_verifier" });
  }

  // One-time use code
  authorizationCodes.delete(code);

  const accessToken = crypto.randomBytes(32).toString("hex");
  accessTokens.set(accessToken, { client_id });

  res.json({
    access_token: accessToken,
    token_type: "Bearer"
  });
});
