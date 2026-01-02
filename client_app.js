const express = require("express");
const axios = require("axios");
const crypto = require("crypto");


const app = express();
const port = 3000;
const CLIENT_ID = "client123";
const REDIRECT_URI = "http://localhost:3000/callback";
const AUTH_SERVER_URL = "http://localhost:4000";

// Step 1: The Setup (Client App Internal)

// Helper: Generate a random string for PKCE
const generateRandomString = () => crypto.randomBytes(32).toString('hex');

// Helper: Hash the string for PKCE (S256)
const generateCodeChallenge = (verifier) => {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
};

// Simple cache for our PKCE verifier (In a real app, use sessions/cookies)
let currentVerifier = "";


// landing page for the login
app.get("/", (req, res) => {
  res.send(`
    <h1>My Awesome App</h1>
    <p>Click below to log in with our custom Auth Server</p>
    <a href="/login" style="padding: 10px 20px; background: #4285f4; color: white; text-decoration: none; border-radius: 5px;">
      Log in with OAuth 2.0
    </a>
  `);
});


// Step 2: The Authorization Request (Frontchannel)
app.get("/login", (req, res) => {
  // 1. Create PKCE Verifier and Challenge
  currentVerifier = generateRandomString();
  console.log("verifier :" + currentVerifier)
  const challenge = generateCodeChallenge(currentVerifier);
  console.log("code challenge :" + challenge)

  // 2. Build the Auth Server URL
  const authUrl = `${AUTH_SERVER_URL}/authorize?` +
    `response_type=code&` +  // specifying the grant type 
    `client_id=${CLIENT_ID}&` +
    `redirect_uri=${encodeURIComponent(REDIRECT_URI)}&` +
    `code_challenge=${challenge}&` +
    `code_challenge_method=S256`;

  // 3. Send user to the Auth Server
  res.redirect(authUrl);
});

app.get("/callback", async (req, res) => {
  const { code } = req.query;

  if (!code) return res.send("No code received from Auth Server.");

  try {
    // 4. Exchange the Code for a Token
    // We send the 'currentVerifier' that we saved earlier
    const response = await axios.post(`${AUTH_SERVER_URL}/token`, {
      grant_type: "authorization_code",
      code: code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: currentVerifier
    }
// uncomment if you want to see the request using a proxy
    // ,{
    // proxy: {
    //     protocol: 'http',
    //     host: '127.0.0.1',
    //     port: 8080
    //     }}
  );

    const { access_token } = response.data;

    res.send(`
      <h1>Login Successful!</h1>
      <p><strong>Your Access Token:</strong> ${access_token}</p>
      <a href="/">Go Home</a>
    `);
  } catch (error) {
    console.error(error.response?.data || error.message);
    res.status(500).send("Failed to exchange code for token.");
  }
});

app.listen(port, () => {
  console.log(`Client App running at http://localhost:${port}`);
});



