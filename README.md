# custom VPN

This project is just a playground on how VPN works and trying to implement it myself. Don't use it for actual VPN (atleast ATM).

## Testing

1. Start docker compose

```bash
docker compose up
```

2. Call web server through inside client app through VPN

```bash
docker exec -it vpn-client-1 bash
root@1f9030abce42:/app# curl 10.6.0.10:8080
Hello world!
root@1f9030abce42:/app#
```

To see actual packets inside logs just lower
log lvl to Info inside docker-compose.yml commands.

Example:

```yaml
server:
  build: ./
  working_dir: /app
  volumes:
    - ./:/app
  command: go run cmd/server/main.go --log-level INFO
  privileged: true
  ...
```
