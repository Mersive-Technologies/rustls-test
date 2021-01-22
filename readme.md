# rustls test

A non-mio simple example of client & server.

## Generating keys

```
openssl req -x509 -newkey rsa:4096 -keyout key1.pem -out cert1.pem -days 365
openssl rsa -in key1.pem -out unencrypted_key1.pem
```