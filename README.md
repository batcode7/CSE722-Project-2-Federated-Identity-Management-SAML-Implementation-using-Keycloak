# How to Run:

1) Once you download the files from git repo: 
2) Make sure you create a folder called “project”
3) Inside that, you create another folder called “saml-local”
4) Inside “saml-local” keep the “keycloak”, “sp1” and ‘“sp2” folders. Afterwards, in three different cmd run the following commands and keep all the cmds alive. 

## Keycloak:
```bat
cd C:\project\saml-local\keycloak\bin
kc.bat start-dev --http-port 8180 --hostname idp.local --hostname-strict=false
```

## SP1:

```bat
cd C:\project\saml-local\sp1
.\.venv\Scripts\activate.bat
python app.py
```

> Open http://sp1.local:5001/

## SP2:

```bat
cd C:\project\saml-local\sp2
.\.venv\Scripts\activate.bat
python app.py
```

> Open http://sp2.local:5002/

Now, test accordingly.
