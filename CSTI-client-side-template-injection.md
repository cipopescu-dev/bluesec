# [⬅️](./README.md) CSTI - Client Side Template Injection

## Severity:
Medium/High
## Description:
Client-side template injection vulnerabilities arise when applications using a client-side template framework dynamically embed user input in web pages. See [XSS](./XSS-cross-site-scripting.md) example.
```html
<!-- https://www.originalwebsite.com/?username=j0hntheh4cker -->
<!-- https://www.originalwebsite.com/?username={{7*7}} -->
<!-- https://www.originalwebsite.com/?username={{constructor.constructor(‘alert(1)’)()}} -->
<body ng-app="templateHelloUser">
    <div ng-controller="helloController">
     Hello {{username}} how are you today?
    </div>
</body>
```
## Vulnerable code:
```python
@app.route("/home", methods=['POST'])
def home():
    CSTI = request.form['string']
    return render_template("index.html",CSTI = CSTI)
```
```html
<!-- Old angular lib -->
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.5.0/angular.js"></script>
<!-- ... -->
<div ng-controller="someController">{{CSTI}}</div>
```
## Steps to reproduce the vulnerability:
We need to go though the following steps to have a successful exploit:
* break the sanitizer
* escape the sandbox
* forge a working payload

## Remediation description:
* Avoid reflecting user input in the template
* Encode server-side user inputs
* Keep the framework up to date
## Remediation code:
* Sanitize the input before passing it into the templates by removing unwanted and risky characters before parsing the data. This minimizes the vulnerabilities for any malicious probing of your templates.
* Keep the framework up to date