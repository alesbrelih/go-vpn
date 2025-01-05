# How to generate CA

```bash
openssl genrsa -out ca-key.pem 4096
```

```bash
openssl req -x509 -new -nodes -key ca-key.pem -sha256 -days 3650 -out ca-cert.pem
```

When prompted for details just enter something.
