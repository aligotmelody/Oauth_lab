1. Lack of state Parameter (CSRF)

Notice that in this current code, we are missing the state parameter.

    The Attack: As a pentester, I would try a Cross-Site Request Forgery (CSRF). I can create a malicious site that forces a victim's browser to hit http://localhost:3000/callback?code=MY_ATTACKER_CODE.

    The Fix: You should always generate a random state on the Client, send it to the /authorize endpoint, and ensure the Server sends it back. If they don't match on the way back, the request is a forgery.

2. Code Replay (If Map.delete() is missing)

As a pentester, one of the first things I check is if the auth_code is truly single-use.

    The Test: I capture the /token request (by proxying Node.js through Burp as discussed). I try to send the exact same POST request twice.

    The Vulnerability: If the server returns a second access_token instead of an error, the code wasn't deleted. This is a critical "Replay Attack" vulnerability.


---

High: Missing state parameter (CSRF risk).

Medium: In-memory storage (Map)—risk of service denial if the Map grows too large or is cleared.