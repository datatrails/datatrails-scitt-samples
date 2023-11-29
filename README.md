![Logo](https://github.com/datatrails/datatrails-scitt-samples/blob/main/DataTrails_Horizontal_Logo_Black.png#gh-light-mode-only)
![Logo](https://github.com/datatrails/datatrails-scitt-samples/blob/main/DataTrails_Horizontal_Logo_White.png#gh-dark-mode-only)

# datatrails-scitt-samples

The files in this repository can be used to demonstrate how the DataTrails SCITT API works. To do this please download one or more of these files, then follow

the getting started docs.

## Generating a signing key

In the samples we assume the signed key is an ecdsa p256 key:

```
openssl ecparam -name prime256v1 -genkey -out scitt-signing-key.pem
```

## Generating a statement

In the samples we assume the statement is a json document, e.g:

```
{
    "author": "fred",
    "title": "my biography",
    "reviews": "mixed"
}
```

## Creating a signed statement

To create a signed statement we can use a venv.

Create a new venv:

```
python -m  venv
```

Now activate the new venv:

```
source venv/bin/activate
```

Now ensure all the requirements are installed:

```
pip install -r requirements.txt
```

Finally we have an environment we can run the create signed statement script in:

```
python scitt/create_signed_statement.py --signing-key-file scitt-signing-key.pem \
    --statement-file scitt-statement.json \
    --feed testfeed \
    --issuer testissuer \
    --output-file signed-statement.txt
```

Now we have the signed statement we can deactivate the venv:

```
deactivate
```

## Verifying a SCITT counter signed receipt

To verify a countersigned receipt issued from datatrails we can use a venv.


Create a new venv:

```
python -m  venv
```

Now activate the new venv:

```
source venv/bin/activate
```

Now ensure all the requirements are installed:

```
pip install -r requirements.txt
```

Finally we have an environment we can run the verify counter signed receipt signature script in:

```
python scitt/verify_receipt_signature.py \
    --scitt-receipt.txt 
```

Now we have verified the receipt signature we can deactivate the venv:

```
deactivate
```
