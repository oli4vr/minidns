#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/select.h>

/*
 * Minimal DNS server implementation in C.
 *
 * This program acts as a tiny authoritative DNS server for a specific
 * local domain (provided as the first command‑line argument).  It parses a
 * hosts‑style file (default /etc/hosts) to build a map of hostnames to IPv4
 * addresses.  When it receives a DNS query for a name that belongs to the
 * configured local domain, it answers directly from that map.  Queries for
 * other domains are optionally forwarded to an external DNS server (primary
 * and/or secondary) using UDP.  If no upstream servers are configured the
 * server replies with REFUSED for non‑local queries.
 *
 * Supported features:
 *   • IPv4 A records only (type 1, class IN)
 *   • Both UDP and TCP DNS transports
 *   • Simple hosts‑file parsing with case‑insensitive lookup
 *   • Verbose debug output (enabled with -v)
 *   • Configurable listen address/port and upstream DNS servers
 *
 * Command‑line usage:
 *   minidns <local_domain> [-f hostsfile] [-l listen_address]
 *           [-P listen_port] [-p primary_dns] [-s secondary_dns] [-v]
 */

#define DNS_PORT 53
#define MAX_DNS_MSG 512
#define TTL 300

/* DNS header – network byte order */
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

/* Simple map from hostname (lowercase) to IPv4 address string */
typedef struct host_entry {
    char *name;               // lower‑case, without trailing dot
    char *ip;                 // dotted decimal string
    struct host_entry *next;
} host_entry_t;

static host_entry_t *hosts = NULL;
static char *local_domain = NULL;
static char *primary_dns = NULL;
static char *secondary_dns = NULL;
static int verbose = 0;

static char *listen_addr = "0.0.0.0"; // default listen address
static int listen_port = DNS_PORT; // default listen port
static int domain_is_local(const char *qname);


/* ---------- Utility Functions ---------- */
/* Helper to remove leading/trailing whitespace from a string */
/* Trim whitespace from both ends of a string */
static char *trim_whitespace(char *s) {

    while (isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

/* Add a hostname/IP pair to the linked‑list map */
static void add_host(const char *ip, const char *name) {
    host_entry_t *e = malloc(sizeof(*e));
    e->ip = strdup(ip);
    e->name = strdup(name);
    for (char *p = e->name; *p; ++p) *p = tolower((unsigned char)*p);
    e->next = hosts;
    hosts = e;
}

/* Convert reverse DNS name to IP string. Returns 0 on success, -1 on failure */
static int reverse_name_to_ip(const char *rev, char *out_ip, size_t out_len) {
    const char *suffix = ".in-addr.arpa";
    size_t revlen = strlen(rev);
    size_t suffixlen = strlen(suffix);
    if (revlen <= suffixlen) return -1;
    if (strcasecmp(rev + revlen - suffixlen, suffix) != 0) return -1;
    char tmp[256];
    size_t partlen = revlen - suffixlen;
    if (partlen >= sizeof(tmp)) return -1;
    memcpy(tmp, rev, partlen);
    tmp[partlen] = '\0';
    // split tokens
    char *tokens[10];
    int count = 0;
    char *p = strtok(tmp, ".");
    while (p && count < 10) {
        tokens[count++] = p;
        p = strtok(NULL, ".");
    }
    if (count < 4) return -1;
    // build IP in reverse order
    snprintf(out_ip, out_len, "%s.%s.%s.%s", tokens[3], tokens[2], tokens[1], tokens[0]);
    return 0;
}

/* Forward declarations */
static int read_name(const uint8_t *msg, size_t msg_len, size_t *offset, char *out, size_t out_len);
static size_t write_name(uint8_t *buf, const char *name);

/* Build PTR response for given hostname */
static void build_ptr_response(const uint8_t *query, size_t qlen, uint8_t *out, size_t *outlen, const char *hostname) {
    char qname[256];
    size_t name_offset = sizeof(dns_header_t);
    if (read_name(query, qlen, &name_offset, qname, sizeof(qname)) != 0) {
        qname[0] = '\0';
    }
    dns_header_t *qh = (dns_header_t *)query;
    dns_header_t *rh = (dns_header_t *)out;
    memcpy(rh, qh, sizeof(dns_header_t));
    rh->flags = htons(0x8180);
    rh->ancount = htons(1);
    rh->nscount = 0;
    rh->arcount = 0;
    size_t pos = sizeof(dns_header_t);
    // Copy only the question section (without any additional records)
    size_t q_offset = sizeof(dns_header_t);
    char tmp[256];
    if (read_name(query, qlen, &q_offset, tmp, sizeof(tmp)) == 0) {
        // advance past QTYPE and QCLASS (4 bytes)
        q_offset += 4;
    }
    size_t question_len = q_offset - sizeof(dns_header_t);
    memcpy(out + pos, query + sizeof(dns_header_t), question_len);
    pos += question_len;
    // answer name: compression pointer to query name at offset 12
    out[pos++] = 0xC0; out[pos++] = 0x0C;
    // TYPE PTR (12), CLASS IN
    out[pos++] = 0x00; out[pos++] = 0x0c;
    out[pos++] = 0x00; out[pos++] = 0x01;
    uint32_t ttl = htonl(TTL);
    memcpy(out + pos, &ttl, 4); pos += 4;
    // placeholder for RDLENGTH
    size_t rdlen_pos = pos;
    pos += 2;
    // write hostname as domain name
    size_t host_len = write_name(out + pos, hostname);
    pos += host_len;
    // fill RDLENGTH (network byte order, no htons needed for length)
    uint16_t rdlen = host_len;
    out[rdlen_pos] = (rdlen >> 8) & 0xFF;
    out[rdlen_pos + 1] = rdlen & 0xFF;
    *outlen = pos;
    if (verbose) {
        fprintf(stderr, "[DEBUG] build_ptr_response length %zu qname='%s'\n", pos, qname);
    }
}

/* ---------- Main Server Loop ---------- */
/* Load and parse a hosts‑style file, populating the map */
static void load_hosts_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("fopen hosts file");
        exit(EXIT_FAILURE);
    }
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        p = trim_whitespace(p);
        if (*p == '\0' || *p == '#') continue;
        char *ip = strtok(p, " \t");
        if (!ip) continue;
        // Skip loopback (127.*) and IPv6 addresses
        if (strncmp(ip, "127.", 4) == 0 || strchr(ip, ':')) continue;
        char *host;
        while ((host = strtok(NULL, " \t\n")) != NULL) {
            if (*host == '#') break; // comment after hosts
            // Skip localhost entries explicitly
            if (strcasecmp(host, "localhost") == 0) continue;
            add_host(ip, host);
        }
    }
    fclose(fp);
}

/* Look up the IP address for a given hostname, handling local domain logic */
static const char *find_ip(const char *name) {

    // Debug: show query name
    if (verbose) fprintf(stderr, "[DEBUG] find_ip called with '%s'\n", name);

    char lower[256];
    strncpy(lower, name, sizeof(lower)-1);
    lower[sizeof(lower)-1] = '\0';
    for (char *p = lower; *p; ++p) *p = tolower((unsigned char)*p);
    // strip trailing dot if present
    size_t len = strlen(lower);
    if (len && lower[len-1] == '.') lower[len-1] = '\0';
    // direct match
    for (host_entry_t *e = hosts; e; e = e->next) {
        if (strcmp(e->name, lower) == 0) return e->ip;
    }
    // If query is a local domain name, try stripping the domain suffix
    if (domain_is_local(lower)) {
        // remove the provided domain suffix (e.g., myhost.mydomain.xyz -> myhost)
        size_t dlen = strlen(local_domain);
        size_t base_len = strlen(lower) - dlen - 1; // exclude the dot before the domain
        if ((int)base_len > 0) {
            char base[256];
            memcpy(base, lower, base_len);
            base[base_len] = '\0';
            for (host_entry_t *e = hosts; e; e = e->next) {
                if (strcmp(e->name, base) == 0) return e->ip;
            }
        }
    }
    // If the hosts entry is a short name (no dot), also match name.domain
    if (!strchr(lower, '.')) {
        char qualified[300];
        snprintf(qualified, sizeof(qualified), "%s.%s", lower, local_domain);
        for (host_entry_t *e = hosts; e; e = e->next) {
            if (strcmp(e->name, qualified) == 0) return e->ip;
        }
    }
    return NULL;
}

/* Find hostname for given IP address */
static const char *find_name_by_ip(const char *ip) {
    for (host_entry_t *e = hosts; e; e = e->next) {
        if (strcmp(e->ip, ip) == 0) return e->name;
    }
    return NULL;
}

/* Determine if a queried name belongs to the configured local domain */
static int domain_is_local(const char *qname) {
    size_t qlen = strlen(qname);
    size_t dlen = strlen(local_domain);
    if (qlen < dlen) return 0;
    const char *suffix = qname + qlen - dlen;
    if (strcasecmp(suffix, local_domain) != 0) return 0;
    // ensure the name either equals the domain or has a dot before the domain
    if (qlen == dlen) return 1;
    return qname[qlen - dlen - 1] == '.';
}

/* ---------- DNS Message Helpers ---------- */
/* Parse a DNS‑encoded domain name from a message, handling compression */
static int read_name(const uint8_t *msg, size_t msg_len, size_t *offset, char *out, size_t out_len) {
    size_t pos = *offset;
    size_t outpos = 0;
    int jumped = 0;
    size_t jump_pos = 0;
    while (pos < msg_len) {
        uint8_t len = msg[pos];
        if (len == 0) { // end
            pos++;
            break;
        }
        if ((len & 0xC0) == 0xC0) { // pointer
            if (!jumped) {
                jump_pos = pos + 2;
                jumped = 1;
            }
            uint8_t b2 = msg[pos+1];
            uint16_t ptr = ((len & 0x3F) << 8) | b2;
            pos = ptr;
            continue;
        }
        pos++;
        if (outpos + len + 1 >= out_len) return -1; // overflow
        memcpy(out + outpos, msg + pos, len);
        outpos += len;
        out[outpos++] = '.';
        pos += len;
    }
    if (outpos == 0) {
        out[0] = '\0';
    } else {
        out[outpos-1] = '\0'; // replace last dot
    }
    if (!jumped) *offset = pos; else *offset = jump_pos;
    return 0;
}

/* Write a domain name into a DNS message using the uncompressed label format */
static size_t write_name(uint8_t *buf, const char *name) {
    // simple uncompressed representation
    size_t pos = 0;
    const char *label = name;
    while (*label) {
        const char *dot = strchr(label, '.');
        size_t len = dot ? (size_t)(dot - label) : strlen(label);
        buf[pos++] = (uint8_t)len;
        memcpy(buf + pos, label, len);
        pos += len;
        if (!dot) break;
        label = dot + 1;
    }
    buf[pos++] = 0; // null terminator
    return pos;
}

/* Forward a DNS query to an upstream server (UDP) and receive the response */
static int forward_query(const uint8_t *query, size_t qlen, uint8_t *response, size_t *rlen) {
    struct sockaddr_in dest;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    const char *dns = primary_dns ? primary_dns : secondary_dns;
    if (!dns) { close(sock); return -1; }
    if (inet_pton(AF_INET, dns, &dest.sin_addr) <= 0) { close(sock); return -1; }
    if (sendto(sock, query, qlen, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        close(sock);
        return -1;
    }
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ssize_t n = recvfrom(sock, response, *rlen, 0, NULL, NULL);
    close(sock);
    if (n < 0) return -1;
    *rlen = (size_t)n;
    return 0;
}

/* Construct a DNS response containing the given IP address for the original query */
static void build_response(const uint8_t *query, size_t qlen, uint8_t *out, size_t *outlen, const char *ip) {
    char qname[256];
    size_t name_offset = sizeof(dns_header_t);
    if (read_name(query, qlen, &name_offset, qname, sizeof(qname)) != 0) {
        // fallback to empty name
        qname[0] = '\0';
    }
    // copy header
    dns_header_t *qh = (dns_header_t *)query;
    dns_header_t *rh = (dns_header_t *)out;
    memcpy(rh, qh, sizeof(dns_header_t));
    rh->flags = htons(0x8180); // QR=1, AA=1, RCODE=0
    rh->ancount = htons(1);
    rh->nscount = 0;
    rh->arcount = 0;
    size_t pos = sizeof(dns_header_t);
    // copy only the question section (exclude any additional records)
    size_t q_offset = sizeof(dns_header_t);
    char tmp[256];
    if (read_name(query, qlen, &q_offset, tmp, sizeof(tmp)) == 0) {
        q_offset += 4; // skip QTYPE and QCLASS
    }
    size_t question_len = q_offset - sizeof(dns_header_t);
    memcpy(out + pos, query + sizeof(dns_header_t), question_len);
    pos += question_len;
    // answer: name (full name, no compression)
    pos += write_name(out + pos, qname);
    // TYPE A, CLASS IN
    out[pos++] = 0x00; out[pos++] = 0x01; // A
    out[pos++] = 0x00; out[pos++] = 0x01; // IN
    // TTL
    uint32_t ttl = htonl(TTL);
    memcpy(out + pos, &ttl, 4); pos += 4;
    // RDLENGTH
    out[pos++] = 0x00; out[pos++] = 0x04;
    // RDATA (IPv4)
    struct in_addr addr;
    inet_pton(AF_INET, ip, &addr);
    memcpy(out + pos, &addr, 4); pos += 4;
    *outlen = pos;
    if (verbose) fprintf(stderr, "[DEBUG] build_response length %zu\n", pos);
}

/* ---------- Main Server Loop ---------- */
/* Initialize sockets, parse command‑line options, load hosts, and enter the select‑based event loop */
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <local_domain> [-f hostsfile] [-l listen_address] [-P listen_port] [-p primary_dns] [-s secondary_dns] [-v]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    local_domain = argv[1];
    const char *hosts_path = "/etc/hosts";
    int opt;
    while ((opt = getopt(argc - 1, argv + 1, "f:p:s:l:P:v")) != -1) {
        switch (opt) {
            case 'f': hosts_path = optarg; break;
            case 'p': primary_dns = optarg; break;
            case 's': secondary_dns = optarg; break;
            case 'l': listen_addr = optarg; break;
            case 'P': listen_port = atoi(optarg); break;
            case 'v': verbose = 1; break;
            default:
                fprintf(stderr, "Invalid option\n");
                exit(EXIT_FAILURE);
        }
    }
    load_hosts_file(hosts_path);
    // Debug: list loaded hosts
    for (host_entry_t *e = hosts; e; e = e->next) {
        if (verbose) fprintf(stderr, "[DEBUG] host entry: %s -> %s\n", e->name, e->ip);
    }

    /* Create UDP socket for DNS queries */
int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) { perror("socket udp"); exit(EXIT_FAILURE); }
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    if (inet_pton(AF_INET, listen_addr, &serv.sin_addr) <= 0) { perror("inet_pton listen_addr"); exit(EXIT_FAILURE); }
    serv.sin_port = htons(listen_port);
    if (bind(udp_sock, (struct sockaddr *)&serv, sizeof(serv)) < 0) { perror("bind udp"); exit(EXIT_FAILURE); }

    /* Create TCP socket for DNS over TCP */
int tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock < 0) { perror("socket tcp"); exit(EXIT_FAILURE); }
    int on = 1;
    setsockopt(tcp_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (bind(tcp_sock, (struct sockaddr *)&serv, sizeof(serv)) < 0) { perror("bind tcp"); exit(EXIT_FAILURE); }
    if (listen(tcp_sock, 5) < 0) { perror("listen"); exit(EXIT_FAILURE); }

    fd_set readset;
    /* Main event loop: wait for UDP or TCP DNS queries */
while (1) {
        FD_ZERO(&readset);
        FD_SET(udp_sock, &readset);
        FD_SET(tcp_sock, &readset);
        int maxfd = (udp_sock > tcp_sock) ? udp_sock : tcp_sock;
        int rc = select(maxfd + 1, &readset, NULL, NULL, NULL);
        if (rc < 0) { perror("select"); continue; }
        /* Handle incoming UDP DNS request */
if (FD_ISSET(udp_sock, &readset)) {
            uint8_t buf[MAX_DNS_MSG];
            struct sockaddr_in cli;
            socklen_t clilen = sizeof(cli);
            ssize_t n = recvfrom(udp_sock, buf, sizeof(buf), 0, (struct sockaddr *)&cli, &clilen);
            if (n <= 0) continue;
            // parse question name
            size_t offset = sizeof(dns_header_t);
            char qname[256];
            if (read_name(buf, n, &offset, qname, sizeof(qname)) != 0) continue;
            uint16_t qtype, qclass;
            memcpy(&qtype, buf + offset, 2); offset += 2;
            memcpy(&qclass, buf + offset, 2); offset += 2;
            qtype = ntohs(qtype); qclass = ntohs(qclass);
            if (qtype == 12 && qclass == 1) {
                // PTR query – perform reverse lookup
                char ip[64];
                if (reverse_name_to_ip(qname, ip, sizeof(ip)) == 0) {
                    const char *host = find_name_by_ip(ip);
                    if (host) {
                        uint8_t resp[MAX_DNS_MSG];
                        size_t resp_len = 0;
                        build_ptr_response(buf, n, resp, &resp_len, host);
                        sendto(udp_sock, resp, resp_len, 0, (struct sockaddr *)&cli, clilen);
                    } else {
                        dns_header_t *hdr = (dns_header_t *)buf;
                        hdr->flags = htons(0x8183); // NXDOMAIN
                        sendto(udp_sock, buf, n, 0, (struct sockaddr *)&cli, clilen);
                    }
                } else {
                    dns_header_t *hdr = (dns_header_t *)buf;
                    hdr->flags = htons(0x8184); // NOTIMP for malformed
                    sendto(udp_sock, buf, n, 0, (struct sockaddr *)&cli, clilen);
                }
                continue;
            }
            if (qtype != 1 || qclass != 1) {
                // not A/IN – respond with NOTIMP
                dns_header_t *hdr = (dns_header_t *)buf;
                //hdr->flags = htons(0x8184); // RCODE=4 NOTIMP
		hdr->flags = htons(0x8180); // NOERROR, QR=1, AA=1
		hdr->ancount = 0;
                sendto(udp_sock, buf, n, 0, (struct sockaddr *)&cli, clilen);
                continue;
            }
            if (domain_is_local(qname)) {
                const char *ip = find_ip(qname);
                if (ip) {
                    uint8_t resp[MAX_DNS_MSG];
                    size_t resp_len = 0;
                    build_response(buf, n, resp, &resp_len, ip);
                    sendto(udp_sock, resp, resp_len, 0, (struct sockaddr *)&cli, clilen);
                } else {
                    // NXDOMAIN
                    dns_header_t *hdr = (dns_header_t *)buf;
                    hdr->flags = htons(0x8183); // RCODE=3 NXDOMAIN
                    sendto(udp_sock, buf, n, 0, (struct sockaddr *)&cli, clilen);
                }
            } else if (primary_dns || secondary_dns) {
                uint8_t fwd_resp[MAX_DNS_MSG];
                size_t fwd_len = sizeof(fwd_resp);
                if (forward_query(buf, n, fwd_resp, &fwd_len) == 0) {
                    sendto(udp_sock, fwd_resp, fwd_len, 0, (struct sockaddr *)&cli, clilen);
                } else {
                    // REFUSED
                    dns_header_t *hdr = (dns_header_t *)buf;
                    hdr->flags = htons(0x8185); // RCODE=5 REFUSED
                    sendto(udp_sock, buf, n, 0, (struct sockaddr *)&cli, clilen);
                }
            } else {
                dns_header_t *hdr = (dns_header_t *)buf;
                hdr->flags = htons(0x8185); // REFUSED
                sendto(udp_sock, buf, n, 0, (struct sockaddr *)&cli, clilen);
            }
        }
        /* Handle incoming TCP DNS request */
if (FD_ISSET(tcp_sock, &readset)) {
            /* Accept TCP connection from client */
int client = accept(tcp_sock, NULL, NULL);
            if (client < 0) continue;
            /* Read two‑byte length prefix for DNS message */
            uint8_t lenbuf[2];
            if (recv(client, lenbuf, 2, MSG_WAITALL) != 2) { close(client); continue; }
            uint16_t msglen = (lenbuf[0] << 8) | lenbuf[1];
            if (msglen > MAX_DNS_MSG) { close(client); continue; }
            uint8_t buf[MAX_DNS_MSG];
            /* Receive the DNS query payload */
if (recv(client, buf, msglen, MSG_WAITALL) != msglen) { close(client); continue; }
            /* Process query using same logic as UDP handling */
            size_t offset = sizeof(dns_header_t);
            char qname[256];
            if (read_name(buf, msglen, &offset, qname, sizeof(qname)) != 0) { close(client); continue; }
            uint16_t qtype, qclass;
            memcpy(&qtype, buf + offset, 2); offset += 2;
            memcpy(&qclass, buf + offset, 2); offset += 2;
            qtype = ntohs(qtype); qclass = ntohs(qclass);
            uint8_t resp[MAX_DNS_MSG];
            size_t resp_len = 0;
            if (qtype == 12 && qclass == 1) {
                // PTR query – reverse lookup
                char ip[64];
                if (reverse_name_to_ip(qname, ip, sizeof(ip)) == 0) {
                    const char *host = find_name_by_ip(ip);
                    if (host) {
                        build_ptr_response(buf, msglen, resp, &resp_len, host);
                    } else {
                        dns_header_t *hdr = (dns_header_t *)buf;
                        hdr->flags = htons(0x8183); // NXDOMAIN
                        memcpy(resp, buf, msglen);
                        resp_len = msglen;
                    }
                } else {
                    dns_header_t *hdr = (dns_header_t *)buf;
                    hdr->flags = htons(0x8184); // NOTIMP malformed
                    memcpy(resp, buf, msglen);
                    resp_len = msglen;
                }
                // response ready
            } else if (qtype != 1 || qclass != 1) {
                dns_header_t *hdr = (dns_header_t *)buf;
                hdr->flags = htons(0x8184);
                memcpy(resp, buf, msglen);
                resp_len = msglen;
            } else if (domain_is_local(qname)) {
                const char *ip = find_ip(qname);
                if (ip) {
                    build_response(buf, msglen, resp, &resp_len, ip);
                } else {
                    dns_header_t *hdr = (dns_header_t *)buf;
                    hdr->flags = htons(0x8183);
                    memcpy(resp, buf, msglen);
                    resp_len = msglen;
                }
            } else if (primary_dns || secondary_dns) {
                uint8_t fwd_resp[MAX_DNS_MSG];
                size_t fwd_len = sizeof(fwd_resp);
                if (forward_query(buf, msglen, fwd_resp, &fwd_len) == 0) {
                    memcpy(resp, fwd_resp, fwd_len);
                    resp_len = fwd_len;
                } else {
                    dns_header_t *hdr = (dns_header_t *)buf;
                    hdr->flags = htons(0x8185);
                    memcpy(resp, buf, msglen);
                    resp_len = msglen;
                }
            } else {
                dns_header_t *hdr = (dns_header_t *)buf;
                hdr->flags = htons(0x8185);
                memcpy(resp, buf, msglen);
                resp_len = msglen;
            }
            // send length prefix then data
            uint8_t outlen[2] = { (resp_len >> 8) & 0xFF, resp_len & 0xFF };
            send(client, outlen, 2, 0);
            send(client, resp, resp_len, 0);
            close(client);
        }
    }
    return 0;
}
