/* Test-only Linux socket boundary for user namespaces without CAP_NET_ADMIN.
 * Route just 93.184.216.34 to the local fixture and deny any other public IP.
 * Log address-family/type only; never retain payloads, domains, or credentials. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

static void record(const char *event) {
    const char *path = getenv("MAGICBOX_FIXTURE_LOG");
    if (!path) return;
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (fd >= 0) {
        dprintf(fd, "%s\n", event);
        close(fd);
    }
}
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
                struct addrinfo **res) {
    (void)node; (void)service; (void)hints; (void)res;
    record("system-dns");
    return EAI_FAIL;
}
int socket(int domain, int type, int protocol) {
    int (*real_socket)(int,int,int) = dlsym(RTLD_NEXT, "socket");
    record((type & 0xf) == SOCK_DGRAM ? "datagram" :
           (type & 0xf) == SOCK_STREAM ? "stream" : "other");
    return real_socket(domain, type, protocol);
}
int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    int (*real_connect)(int,const struct sockaddr*,socklen_t) = dlsym(RTLD_NEXT, "connect");
    if (addr && addr->sa_family == AF_INET && len >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in peer = *(const struct sockaddr_in *)addr;
        uint32_t ip = ntohl(peer.sin_addr.s_addr);
        if (ip == 0x5db8d822u) {
            record("fixture");
            peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            return real_connect(fd, (const struct sockaddr *)&peer, sizeof peer);
        }
        if (ip >> 24 == 127) {
            record("loopback");
            return real_connect(fd, addr, len);
        }
    }
    record("forbidden");
    errno = ENETUNREACH;
    return -1;
}
