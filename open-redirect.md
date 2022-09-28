# [⬅️](./README.md) Open Redirect

## Severity:
Low/Medium
## Description:
Let’s say that our website, under normal circumstances, uses this mechanism to redirect the user after login.<br>
`https://www.originalwebsite.com/login?redirect=/user/`

Can we predict what would happen if someone were to send a user the following links instead?<br>
`https://www.originalwebsite.com/login?redirect=//attacker.com`<br>
`https://www.originalwebsite.com/login?redirect=https://attacker.com`<br>
`https://www.originalwebsite.com/login?redirect=javascript:alert(document.cookie)`<br>

### Types:
* Pure header set: `response.setHeader("Location", newUrl);`
* Specific redirect/forward `response.sendRedirect(newUrl);`

## Vulnerable code:
Given the following `form`:
```html
<form method="post" action="/redirect?newurl=newsite">
    <button class="btn btn-primary" type="submit">Go to new website</button>
</form>
```
And the following webserver:
```python
def blacklist(url):
	blacklist = ["."]
	for b in blacklist:
		if url.find(b) != -1:
			return True
	return False

@app.route("/redirect", methods=['POST', 'GET'])
def redirector():
    landing_page = request.args.get('newurl')
    if blacklist(landing_page):
    	return render_template("index.html", content = "Sorry, you cannot use \".\" in the redirect")
    return redirect(landing_page, 302)
```
## Steps to reproduce the vulnerability:
If we URL encode the dot, the application is smart enough to decode it and recognise it in the URL, blocking us again. We can verify it just using `http://127.0.0.1:5000/redirect?newurl=https:google%E3%80%82com`
## Remediation description:
* Simply avoid using redirects and forwards.
* If used, do not allow the url as user input for the destination. This can usually be done. In this case, you should have a method to validate URL.
* If user input can’t be avoided, ensure that the supplied value is valid, appropriate for the application, and is authorized for the user.
* It is recommended that any such destination input be mapped to a value, rather than the actual URL or portion of the URL, and that server side code translate this value to the target URL.
* Sanitize input by creating a list of trusted URL's (lists of hosts or a regex).
* Force all redirects to first go through a page notifying users that they are going off of your site, and have them click a link to confirm.
## Remediation code:
It can be simply resolved with a whitelist in the webserver:
```python
def whitelist(url):
	whitelist = ["http://127.0.0.1:5000/newsite"]
	for b in whitelist:
		if url==b:
			return True
	return False

@app.route("/redirect", methods=['POST', 'GET'])
def redirector():
    landing_page = request.args.get('newurl')
    if whitelist(landing_page):
        return redirect(landing_page, 302)
    return render_template("index.html", content = "Nice try!")
```