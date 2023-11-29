![Logo](https://raw.githubusercontent.com/datatrails/datatrails-scitt-samples/main/DataTrails_Horizontal_Logo_Black.png)
![Logo](https://raw.githubusercontent.com/datatrails/datatrails-scitt-samples/main/DataTrails_Horizontal_Logo_White.png)

# DataTrails SCITT Examples

The files in this repository can be used to demonstrate how the DataTrails SCITT API works.

## Copy the Samples

```shell
git clone https://github.com/datatrails/datatrails-scitt-samples.git

cd datatrails-scitt-samples
```

## Generating a Signing Key

In the samples we assume the signed key is an ecdsa p256 key:

```shell
openssl ecparam -name prime256v1 -genkey -out scitt-signing-key.pem
```

## Generating a Statement

In the samples we assume the statement is a json document, e.g:

```shell
cat > statement.json <<EOF
{
    "author": "fred",
    "title": "my biography",
    "reviews": "mixed"
}
EOF
```

## Creating a Signed Statement

To create a signed statement we can use a venv.

Create a new venv:

```shell
python -m  venv venv
```

Now activate the new venv:

```shell
source venv/bin/activate
```

Now ensure all the requirements are installed:

```shell
pip install --upgrade pip && \
pip install -r requirements.txt
```

Finally we have an environment we can run the create signed statement script in:

```bash
python scitt/create_signed_statement.py \
    --signing-key-file scitt-signing-key.pem \
    --statement-file statement.json \
    --feed testfeed \
    --issuer sysnation.dev \
    --output-file signed-statement.cbor
```

Now we have the signed statement we can deactivate the venv:

```shell
deactivate
```

## Verifying a SCITT counter signed receipt

To verify a countersigned receipt issued from DataTrails we can use a venv.

Create a new venv:

```shell
python -m  venv
```

Now activate the new venv:

```shell
source venv/bin/activate
```

Now ensure all the requirements are installed:

```shell
pip install -r requirements.txt
```

Finally we have an environment we can run the verify counter signed receipt signature script in:

```shell
python scitt/verify_receipt_signature.py \
    --scitt-receipt.txt 
```

Now we have verified the receipt signature we can deactivate the venv:

```shell
deactivate
```
