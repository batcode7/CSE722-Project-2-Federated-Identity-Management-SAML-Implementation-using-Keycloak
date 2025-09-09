# CSE722-Project-2-Federated-Identity-Management-SAML-Implementation-using-Keycloak

This is a setup on **Windows** using **Keycloak** as the Identity Provider (IdP) and two **Flask** based Service Providers: **sp1** and **sp2**.  
---


> Note: All commands below were run in **cmd.exe**

---

## Step 1) Directory setup

### 1A) Create project folders
```bat
mkdir C:\project\saml-local
mkdir C:\project\saml-local\keycloak
mkdir C:\project\saml-local\sp1
mkdir C:\project\saml-local\sp2
```

### 1B) Add hostnames
Open the hosts file in Notepad as **Administrator**:
```bat
C:\Windows\System32\drivers\etc\hosts
```

Append these lines at the bottom, then **Save**:
```
127.0.0.1  idp.local
127.0.0.1  sp1.local
127.0.0.1  sp2.local
```

### 1C) Make sure the Java version is >= 17
```bat
java -version
```

---

## Step 2) Keycloak: Set up

### 2.1 Download Keycloak via CMD into the keyloak folder that has been created in Step 1
```bat
curl -L -o C:\project\saml-local\keycloak\keycloak-26.3.3.zip ^
  https://github.com/keycloak/keycloak/releases/download/26.3.3/keycloak-26.3.3.zip
```

**Extract** the ZIP inside `C:\project\saml-local\keycloak\`. After extraction, we should see the kc.bat file along with other files:
```
C:\project\saml-local\keycloak\bin\kc.bat
```

### 2.2 Start Keycloak (we will use port 8180)
```bat
cd C:\project\saml-local\keycloak\bin
kc.bat start-dev --http-port 8180 --hostname idp.local --hostname-strict=false
```
Leave this **cmd window running**. And open 
```bat 
http://idp.local:8180/
```
in a browser and set the **admin** credentials when prompted. we must remember the admin credentials for future logins. 

### 2.3 Create realms

In Keycloak Admin UI:

- Top-left realm selector → **Manage realm**
  - **Create realm**  
  - **Realm name:** `idp-a`  
  - Click **Create**.
- Repeat to create **`idp-b`**.

### 2.4 Create a test user in each realm

Do this in realm **idp-a**, then repeat in **idp-b**:

- Left menu → **Users** → **Add user**
  - **Username:**  (use something easier to remember)
  - **Email:** (optional)
  - **First name / Last name:** (optional)
  - **Save**
- On the user page → **Credentials** tab → **Set password**
  - **New password:**  (use something easier to remember)
  - **Temporary:** **OFF**
  - **Save**

Once done in realm **idp-a**, now repeat for realm **idp-b**. 

*(Optionally we may create a second user in both realms. To create another user repeat the same process)*

### 2.5 Create **SAML clients** for `sp1` and `sp2` in each realm

we will create **two clients per realm**: one for `sp1` and one for `sp2`.

First in **`idp-a`**

#### A) Create `sp1` client
- Left menu → **Clients** → **Create client**
  - **Client type:** `SAML`
  - **Client ID:** `http://sp1.local:5001/metadata`
  - **Next**
- **Settings** tab (important fields):
  - **Valid redirect URIs:** `http://sp1.local:5001/*`
  - **Master SAML Processing URL:** `http://sp1.local:5001/assert/a`
  - **Name ID format (under SAML capabilities):** `username`
  - **Include AuthnStatement:** On  
  - **Save**.
- **Keys** tab:
  - **Client signature required:** Off
  - Click **Save**.
- **Client scopes** tab:
  - remove **role_list** and **saml_organization**
  - keep only **http://sp1.local:5001/metadata-dedicated**
  - Now press on to **http://sp1.local:5001/metadata-dedicated**
  - Add Mappers → From predefined mappers → select **X500 email** only
  - Press **Add**
  - Press **Save**

> This ensures we always send an AttributeStatement with just the attributes that wer SP expects and no duplicates.

Keep **Sign assertions = On**, **Force POST binding = On**, **Front channel logout = On**.

#### B) Create `sp2` client
- Left menu → **Clients** → **Create client**
  - **Client type:** `SAML`
  - **Client ID:** `http://sp2.local:5002/metadata`
  - **Next**
- **Settings** tab (important fields):
  - **Valid redirect URIs:** `http://sp2.local:5002/*`
  - **Master SAML Processing URL:** `http://sp2.local:5002/assert/a`
  - **Name ID format (under SAML capabilities):** `username`
  - **Include AuthnStatement:** On  
  - **Save**.
- **Keys** tab:
  - **Client signature required:** Off
  - Click **Save**.
- **Client scopes** tab:
  - remove **role_list** and **saml_organization**
  - keep only **http://sp1.local:5001/metadata-dedicated**
  - Now press on to **http://sp1.local:5001/metadata-dedicated**
  - Add Mappers → From predefined mappers → select **X500 email** only
  - Press **Add**
  - Press **Save**

> This ensures we always send an AttributeStatement with just the attributes that wer SP expects and no duplicates.

Keep **Sign assertions = On**, **Force POST binding = On**, **Front channel logout = On**.

Now in **`idp-b`**.

#### C) Create `sp1` client
- Left menu → **Clients** → **Create client**
  - **Client type:** `SAML`
  - **Client ID:** `http://sp1.local:5001/metadata`
  - **Next**
- **Settings** tab (important fields):
  - **Valid redirect URIs:** `http://sp1.local:5001/*`
  - **Master SAML Processing URL:** `http://sp1.local:5001/assert/b`
  - **Name ID format (under SAML capabilities):** `username`
  - **Include AuthnStatement:** On  
  - **Save**.
- **Keys** tab:
  - **Client signature required:** Off
  - Click **Save**.
- **Client scopes** tab:
  - remove **role_list** and **saml_organization**
  - keep only **http://sp1.local:5001/metadata-dedicated**
  - Now press on to **http://sp1.local:5001/metadata-dedicated**
  - Add Mappers → From predefined mappers → select **X500 email** only
  - Press **Add**
  - Press **Save**

> This ensures we always send an AttributeStatement with just the attributes that wer SP expects and no duplicates.

Keep **Sign assertions = On**, **Force POST binding = On**, **Front channel logout = On**.

#### D) Create `sp2` client
- Left menu → **Clients** → **Create client**
  - **Client type:** `SAML`
  - **Client ID:** `http://sp2.local:5002/metadata`
  - **Next**
- **Settings** tab (important fields):
  - **Valid redirect URIs:** `http://sp2.local:5002/*`
  - **Master SAML Processing URL:** `http://sp2.local:5002/assert/b`
  - **Name ID format (under SAML capabilities):** `username`
  - **Include AuthnStatement:** On  
  - **Save**.
- **Keys** tab:
  - **Client signature required:** Off
  - Click **Save**.
- **Client scopes** tab:
  - remove **role_list** and **saml_organization**
  - keep only **http://sp1.local:5001/metadata-dedicated**
  - Now press on to **http://sp1.local:5001/metadata-dedicated**
  - Add Mappers → From predefined mappers → select **X500 email** only
  - Press **Add**
  - Press **Save**

> This ensures we always send an AttributeStatement with just the attributes that wer SP expects and no duplicates.

Keep **Sign assertions = On**, **Force POST binding = On**, **Front channel logout = On**.

### 2.6 Get the IdP SAML descriptors (certificates)

Open these URLs to view each realm's SAML descriptor (and copy the signing certificate/X509):
- **http://idp.local:8180/realms/idp-a/protocol/saml/descriptor**
- **http://idp.local:8180/realms/idp-b/protocol/saml/descriptor**

We will paste each realm’s **x509 certificate** into the SP settings files later.

---

## Step 3) Build **sp1** (Flask SAML SP)

### 3.1 We will create a virtual environment & install dependencies
```bat
cd C:\project\saml-local\sp1
python -m venv .venv
.\.venv\Scripts\activate.bat
pip install flask python3-saml
```

### 3.2 Create folder structure
```bat
md templates
md static
```

### 3.3 Create `app.py`
Create an empty file, then paste the following code:
```bat
type nul > app.py
```

```python
import os
import json
import functools
from flask import (
    Flask, render_template, redirect, request, session, url_for,
    send_from_directory, abort, Response
)
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings


# ----- Flask app (explicit folders so it works no matter where we launch from)
BASE = os.path.abspath(os.path.dirname(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(BASE, "templates"),
    static_folder=os.path.join(BASE, "static"),
)
app.secret_key = "dev-only-change-me"   # change for anything public


# ----- Helpers
def _prepare_flask_request():
    \"\"\"Convert Flask request to the dict that python3-saml expects.\"\"\"
    host = request.host
    # derive port part for the SAML dict
    if \":\" in host:
        port = host.split(\":\", 1)[1]
    else:
        port = \"443\" if request.is_secure else \"80\"

    return {
        \"https\": \"on\" if request.is_secure else \"off\",
        \"http_host\": host,
        \"server_port\": port,
        \"script_name\": request.path,
        \"get_data\": request.args.copy(),
        \"post_data\": request.form.copy(),
        \"query_string\": request.query_string,
    }


def load_settings(choice: str) -> dict:
    \"\"\"Merge base per-IdP settings with the advanced security options.
    choice: 'a' or 'b'\"\"\"
    assert choice in (\"a\", \"b\")
    with open(os.path.join(BASE, \"advanced_settings.json\"), \"r\", encoding=\"utf-8\") as f:
        adv = json.load(f)
    with open(os.path.join(BASE, f\"settings_kc{'A' if choice == 'a' else 'B'}.json\"), \"r\", encoding=\"utf-8\") as f:
        base = json.load(f)

    # Merge in 'security' section from advanced settings
    if \"security\" in adv:
        base[\"security\"] = adv[\"security\"]
    return base


def build_auth(choice: str) -> OneLogin_Saml2_Auth:
    \"\"\"Create a SAML Auth object for the chosen IdP.
    NOTE: pass the dict as `old_settings=` (or as 2nd positional) — NOT `settings=`.
    \"\"\"
    saml_settings = load_settings(choice)
    return OneLogin_Saml2_Auth(_prepare_flask_request(), old_settings=saml_settings)


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if \"user\" not in session:
            return redirect(url_for(\"choose_idp\", next=request.path))
        return view(*args, **kwargs)
    return wrapper


# ----- Routes
@app.route(\"/\")
def home():
    return render_template(\"home.html\")


@app.route(\"/choose-idp\")
def choose_idp():
    nxt = request.args.get(\"next\", \"/\")
    return render_template(\"choose_idp.html\", next=nxt)


@app.route(\"/login\")
def login():
    choice = request.args.get(\"idp\")  # 'a' or 'b'
    nxt = request.args.get(\"next\", \"/\")
    if choice not in (\"a\", \"b\"):
        return redirect(url_for(\"choose_idp\", next=nxt))

    session[\"pending_idp\"] = choice
    session[\"post_login_next\"] = nxt

    # Set force_authn=True if we want to always show the IdP login page
    auth = build_auth(choice)
    return redirect(auth.login(force_authn=False))


@app.route(\"/assert/<choice>\", methods=[\"POST\"])
def acs(choice):
    \"\"\"Assertion Consumer Service endpoint — receives SAMLResponse.\"\"\"
    if choice not in (\"a\", \"b\"):
        abort(404)

    auth = build_auth(choice)
    auth.process_response()
    errors = auth.get_errors()
    if errors:
        return f\"ACS errors: {errors} :: {auth.get_last_error_reason()}\", 400
    if not auth.is_authenticated():
        return \"Not authenticated\", 401

    session[\"user\"] = {
        \"nameid\": auth.get_nameid(),
        \"attrs\": auth.get_attributes(),
    }
    return redirect(session.pop(\"post_login_next\", url_for(\"profile\")))


@app.route(\"/profile\")
@login_required
def profile():
    return render_template(\"profile.html\", user=session[\"user\"])


@app.route(\"/photo\")
@login_required
def photo():
    return send_from_directory(os.path.join(BASE, \"static\"), \"photo.jpg\")


@app.route(\"/logout\")
def logout():
    \"\"\"Local logout + redirect to IdP logout. If we know which IdP we used,
    pass ?idp=a or ?idp=b; otherwise we'll reuse the last pending choice.\"\"\"
    choice = request.args.get(\"idp\", session.get(\"pending_idp\", \"a\"))
    session.clear()
    try:
        return redirect(build_auth(choice).logout())
    except Exception:
        # If IdP logout URL not configured, just return to home
        return redirect(url_for(\"home\"))


@app.route(\"/metadata\")
def metadata():
    \"\"\"Expose SP metadata (use IdP-A settings for SP descriptor).
    NOTE: pass dict as old_settings=, NOT settings=.\"\"\"
    settings = OneLogin_Saml2_Settings(
        old_settings=load_settings(\"a\"),
        sp_validation_only=True
    )
    md = settings.get_sp_metadata()
    errors = settings.validate_metadata(md)
    if errors:
        return f\"Metadata errors: {errors}\", 500
    return Response(md, mimetype=\"text/xml\")


if __name__ == \"__main__\":
    # run SP1 on port 5001
    app.run(host=\"0.0.0.0\", port=5001, debug=True)
```

### 3.4 Create and update the html files inside templates folder

**`templates\home.html`**
```bat
type nul > templates\home.html
```

```html
<!doctype html>
<h2>Site-A (SP1) Home</h2>
<p>This is a public landing page.</p>
<p><a href="/photo">Access service (protected photo)</a></p>
```

**`templates\choose_idp.html`**
```bat
type nul > templates\choose_idp.html
```

```html
<!doctype html>
<h3>Choose wer Identity Provider</h3>
<ul>
  <li><a href="/login?idp=a&next={{ next }}">Login with IdP-A</a></li>
  <li><a href="/login?idp=b&next={{ next }}">Login with IdP-B</a></li>
</ul>
```

**`templates\profile.html`**
```bat
type nul > templates\profile.html
```

```html
<!doctype html>
<h2>Profile</h2>
{% if user %}
  <p><strong>NameID:</strong> {{ user.nameid }}</p>
  <h3>Attributes</h3>
  <pre>{{ user.attrs | tojson(indent=2) }}</pre>
{% else %}
  <p>No user in session.</p>
{% endif %}
<p><a href="/logout">Logout</a></p>
```

### 3.5 Static asset (photo)
Copy a sample image into `static\photo.jpg`:
```bat
copy %WINDIR%\Web\Wallpaper\Windows\img0.jpg static\photo.jpg
```

### 3.6 SAML settings files

**`advanced_settings.json`** creation. Afterwards, paste the following code:
```bat
type nul > advanced_settings.json
```

```json
{
  "security": {
    "authnRequestsSigned": false,
    "wantAssertionsSigned": true,
    "wantMessagesSigned": false,
    "requestedAuthnContext": false
  }
}
```

**`settings_kcA.json`** (IdP **idp-a**) 
```bat
type nul > settings_kcA.json
```

```json
{
  "strict": true,
  "sp": {
    "entityId": "http://sp1.local:5001/metadata",
    "assertionConsumerService": {
      "url": "http://sp1.local:5001/assert/a",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    }
  },
  "idp": {
    "entityId": "http://idp.local:8180/realms/idp-a",
    "singleSignOnService": {
      "url": "http://idp.local:8180/realms/idp-a/protocol/saml",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    },
    "singleLogoutService": {
      "url": "http://idp.local:8180/realms/idp-a/protocol/saml",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    },
    "x509cert": "PASTE_IDP_A_CERT_HERE; we will find the certificate from 2.6 first url"
  }
}
```

**`settings_kcB.json`** (IdP **idp-b**)
```bat
type nul > settings_kcB.json
```

```json
{
  "strict": true,
  "sp": {
    "entityId": "http://sp1.local:5001/metadata",
    "assertionConsumerService": {
      "url": "http://sp1.local:5001/assert/b",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    }
  },
  "idp": {
    "entityId": "http://idp.local:8180/realms/idp-b",
    "singleSignOnService": {
      "url": "http://idp.local:8180/realms/idp-b/protocol/saml",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    },
    "singleLogoutService": {
      "url": "http://idp.local:8180/realms/idp-b/protocol/saml",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    },
    "x509cert": "PASTE_IDP_B_CERT_HERE; we will find the certificate from 2.6 second url"
  }
}
```

> Paste each realm’s **x509cert** (from the realm SAML descriptor) in place of the placeholders above.

### 3.7 Run **sp1**
```bat
cd C:\project\saml-local\sp1
.\.venv\Scripts\activate.bat
python app.py
```

Open **http://sp1.local:5001/** → click **Access service** → choose IdP → login.

---

## Step 4) Now we will build **sp2** by cloning **sp1**

### 4.1 Copy files
```bat
mkdir C:\project\saml-local\sp2
xcopy /E /I C:\project\saml-local\sp1 C:\project\saml-local\sp2
```

### 4.2 Copy the virtual environment 
```bat
xcopy /E /I C:\project\saml-local\sp1\.venv C:\project\saml-local\sp2\.venv
```

### 4.3 Update ports for **sp2**
Open `C:\project\saml-local\sp2\app.py` and change the Flask port to **5002**:
```python
app.run(host="0.0.0.0", port=5002, debug=True)
```

Update the SAML settings in **sp2**:

- `settings_kcA.json`: change "entityId" to **http://sp2.local:5002/metadata** and change "url" to **http://sp2.local:5002/assert/a**
- `settings_kcB.json`: change "entityId" to **http://sp2.local:5002/metadata** and change "url" to **http://sp2.local:5002/assert/b**

### 4.4 Update the home.html in **sp2** with the following lines
```
<h2>Site-B (SP2) Home</h2>
<p>This is another public landing page.</p>
```
> You may change the photo in **sp2**. Make sure the extension of the new photo is .jpg and don't forget to rename it as photo.

> `advanced_settings.json` remains the same.

### 4.4 Run **sp2**
```bat
cd C:\project\saml-local\sp2
.\.venv\Scripts\activate
python app.py
```

Open `http://sp2.local:5002/` and repeat the login test.

---

## URLs

- `http://idp.local:8180/` opens Keycloak admin UI.
- `http://sp1.local:5001/` → SP1 Homepage
- `http://sp2.local:5002/` → SP2 Homepage

---

## Helpful commands:

- **Run Keycloak**:
```bat
cd C:\project\saml-local\keycloak\bin
kc.bat start-dev --http-port 8180 --hostname idp.local --hostname-strict=false
```

- **Run SP1**:
```bat
cd C:\project\saml-local\sp1
.\.venv\Scripts\activate.bat
python app.py
```

- **Run SP2**:
```bat
cd C:\project\saml-local\sp2
.\.venv\Scripts\activate.bat
python app.py
```

