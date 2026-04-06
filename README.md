# MiniDNS

A tiny DNS server that serves a custom local domain using a hosts‑style file.


## What it does

- Reads a hosts file (default `/etc/hosts` or a file supplied with `-f`).
- Serves **A** (IPv4) records for any name that belongs to the configured **local domain**.
- For all other queries it can forward the request to an upstream DNS server (primary and/or secondary) using UDP.
- If no upstream server is configured, non‑local queries receive a **REFUSED** response.
- Supports both UDP and TCP DNS transports.


## Build

```bash
 make
```


## Usage

```
minidns <local_domain> [-f hostsfile] [-l listen_address] [-P listen_port]
        [-p primary_dns] [-s secondary_dns] [-v]
```
| Option | Description |
|--------|-------------|
| `<local_domain>` | Domain that the server is authoritative for (e.g. `myhome.local`). |
| `-f hostsfile` | Path to a hosts‑style file. Default: `/etc/hosts`. |
| `-l listen_address` | IP address to bind to. Default: `0.0.0.0` (all interfaces). |
| `-P listen_port` | UDP/TCP port to listen on. Default: `53`. |
| `-p primary_dns` | IPv4 address of the primary upstream DNS server. |
| `-s secondary_dns` | IPv4 address of the secondary upstream DNS server. |
| `-v` | Enable verbose debug output (printed to `stderr`). |


## Example

```bash
# Serve the domain "demo.local" using a custom hosts file and forward other queries
# to Google's public DNS server.
./minidns demo.local -f ./myhosts.txt -p 8.8.8.8 -v
```
The above command will:
- Listen on all interfaces, port 53.
- Answer forward queries like `host1.demo.local` using entries from `myhosts.txt`.
- Answer reverse DNS (PTR) lookups for IPs defined in `myhosts.txt`.
- Forward any query not ending with `demo.local` to `8.8.8.8`.
- Print debug information about the received query.


## Hosts file format

The file follows the classic `/etc/hosts` syntax:
```
192.168.1.10   host1.demo.local   host1
10.0.0.5       host2.demo.local   host2   # comment
```
- IP address first, followed by one or more hostnames.
- Hostnames are case‑insensitive.
- Lines starting with `#` or empty lines are ignored.


## Notes

- Supports **A** (IPv4) and **PTR** (reverse DNS) records; other types return **NOTIMP**.
- TCP handling follows the same logic as UDP but with a 2‑byte length prefix as required by the DNS‑over‑TCP spec.
- The server does **not** implement recursion; it merely forwards queries.
- Be sure to run the program with sufficient privileges to bind to port 53 (e.g., as root or with `setcap`).

## Packaging

### DEB package

```bash
make deb
```
Creates `minidns-$(VERSION).deb` in the repository root.

### RPM package

```bash
make rpm
```
Builds `minidns-$(VERSION).rpm` in the repository root (may require root privileges).

## Docker

Build the OCI image:
```bash
make oci
```

Run with Docker Compose (example `docker-compose.yml`):
```yaml
version: "3.8"
services:
  minidns:
    image: minidns:1.0.0
    container_name: minidns
    environment:
      DOMAIN: local
      PRIMARY_DNS: 9.9.9.9
      SECONDARY_DNS: 1.1.1.1
    volumes:
      - /etc/hosts:/data/hosts:ro
    ports:
      - "53:53/udp"
      - "53:53/tcp"
```
The container reads the hosts file from the mounted volume `/data/hosts`. Adjust `DOMAIN`, `PRIMARY_DNS`, and `SECONDARY_DNS` as needed.
