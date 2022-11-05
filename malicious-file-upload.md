# [⬅️](./README.md) Malicious File Upload

## Severity:
High/Critical
## Description:
Application capability allowing users to upload extraneous files to its premises.
> When application fails to proper validate the resources during the upload process opens an important channel for application/server compromising: **upload of shells, exploits, backdoors, defacements, client and server side attacks, DoS**, etc.
```html
<!-- Upload exploit.svg into a webapp known to use IM’s “convert” and you’re good to go! -->
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd";>

<svg width="640px" height="480px" version="1.1" xmlns="http://www.w3.org/2000/svg"; xmlns:xlink="http://www.w3.org/1999/xlink";>

    <image xlink:href="https://example.com/image.jpg&quot;|ls &quot;-la" x="0" y="0" height="640px" width="480px"/>

</svg>
```
## Vulnerable code:
```python
ALLOWED_EXTENSIONS = app.config['ALLOWED_EXTENSIONS'] = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'html'])
app.config['DEBUG'] = True

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route("/", methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['file']
        print(file)
        if file and allowed_file(file.filename):
            filename = file.filename
            file.save(os.path.join('uploads/', filename))
            uploaded = "File was uploaded"
            return render_template("index.html",uploaded = uploaded)
        uploaded = "something went wrong!"
        return render_template("index.html",uploaded = uploaded)
    return render_template("index.html")
```
## Steps to reproduce the vulnerability:
Simply sending a post, with a malformed `filename`:
```
172.17.0.1 - - [29/Sep/2022 05:19:19] "GET /static HTTP/1.1" 200 -
<FileStorage: '../static/img/cip.jpg' ('image/jpeg')>
```
## Remediation description:
* Validate the file
    * Check file content and name length (min and max)
    * Move the file to a temporary location
    * Remove execution permission
    * Limit the number of allowed extensions – block the upload of the others
        * Watch out double extensions!
        * Do not rely on file name extensions
    * Do MIME-Type and metadata checks
    * Validate the WHOLE content of the file – malicious data could be anywhere
        * MSOffice files can hide Macros and multiple documents
        * PDF files can hide malicious JS
        * If there is a format specific, perform schema validation
* Rename the file to a unique identifier
* Store the file outside document root
* Run a malware scan
## Remediation code:
Weak protections to fix uploads are:
* Blacklisting File Extensions
* Whitelisting File Extensions
* "Content-Type" Header Validation
* Using a File Type Detector
[File Upload CheatSheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)