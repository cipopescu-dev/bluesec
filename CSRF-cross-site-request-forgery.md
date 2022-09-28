# [⬅️](./README.md) CSRF - Cross-Site Request Forgery

## Severity:
Medium/High
## Description:
A CSRF attack involves one webapp performing actions on the user’s behalf in another webapp.
>“Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they are currently authenticated.”</br>
>“CSRF vulnerabilities in web applications abuse the trust the server has in the browser agent (end user).”
### `SOP` x `CORS`:
| Policy       | methods      |
| ------------ | ------------ |
| `SOP`/`CORS` | `GET`        |
| `CSRF`       | `PUT`/`POST` |
## Vulnerable code:
```python
@app.route("/update", methods=['POST', 'GET'])
def update():
    if not session.get('loggedin'):
        return render_template('index.html')
    sqli  = Classes()
    if request.method == "POST":
        sqli.updateColor(request.form['color'], session.get('userId'))

    pref = sqli.getColor(session.get('userId'))
    color = pref[0][0]
    return render_template("loggedin.html", color = color)
```
## Steps to reproduce the vulnerability:
Evil webserver that will trigger the malicious `XHR` `POST`/`PUT` form-request using the stored session cookie.
```html
<html><head></head>
<body>
<iframe style="display:none" name="csrf-frame"></iframe>
<form method='POST' action='http://127.0.0.1:5000/update' target="csrf-frame" id="csrf-form">
<input type='hidden' name='color' value='Hackzord!'>
<input type='submit' value='submit'>
</form>
<script>document.getElementById("csrf-form").submit()</script>
</body></html>
```
## Remediation description:
* Via the header `Set-Cookie: CookieName=CookieValue; SameSite=Lax;` (Not supported on all browsers yet!)
* Do not use `GET` for requests changes, only `PUT`/`POST`
* Via `CSRF` mechanism:
  * Create a CSRF-token as hidden input field in the form
  * Verify that token is present and correct in the request.
  * Reject the request if it is wrong.
  * CSRF-tokens should not be passed in the URL or as a part of the Query string
  * A CSRF token should contain at least 128 bits of entropy
  * Create a new token for each form
### `CSRF` Mitigations:
* synchronizer
* encryption based
* `HMAC` based Token Pattern
## Remediation code:
To implement proper CSRF tokenization inside this guide would be an overkill. We could for example make a proof-of-concept using a hard-coded token:
```html
<form action="/update" method="post">
    <input type="hidden" name="CSRFToken" value="OWY4NmQwODE4ODRjN2Q2NTlhMmZlYWEwYzU1YWQwMTVhM2JmNGYxYjJiMGI4MjJjZDE1ZDZMGYwMGEwOA==">
...
```
```python
if request.method == "POST":
    if request.form['CSRFToken'] == "OWY4NmQwODE4ODRjN2Q2NTlhMmZlYWEwYzU1YWQwMTVhM2JmNGYxYjJiMGI4MjJjZDE1ZDZMGYwMGEwOA==":
        sqli.updateColor(request.form['color'], session.get('userId'))
```