![Logo](https://github.com/datatrails/datatrails-scitt-samples/blob/main/DataTrails_Horizontal_Logo_Black.png)


# datatrails-scitt-samples

The files in this repository can be used to demonstrate how the DataTrails SCITT API works. To do this please download one or more of these files, then follow

the getting started docs.


## Creating a signed statement

To create a signed statement we can use a venv.

If virtual environment is not installed, install it with the following:

```
pip install virtualenv
```

Now create a new venv:

```
virtualenv venv
```

Now activate the new venv:

```
source venv/bin/activate
```

Now ensure all the requirements are installed:

```
pip install -r requirements.txt
```

Finally we have an environment we can run the creat signed statement script in:

```
python scitt/create_signed_statement.py --signing-key-file scitt-signing-key.pem \
    --statement-file scitt-statement.json \
    --feed testfeed \
    --issuer testissuer
```
