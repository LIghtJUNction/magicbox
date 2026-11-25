// Compile as a test helper. It runs only on loopback in a fresh network namespace.
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int probe(int family, int kind, int port, int use_msg, int deny) {
    struct sockaddr_storage dst = {0};
    socklen_t len;
    if (family == AF_INET) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&dst;
        v4->sin_family = AF_INET;
        v4->sin_port = htons(port);
        v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        len = sizeof(*v4);
    } else {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&dst;
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(port);
        v6->sin6_addr = in6addr_loopback;
        len = sizeof(*v6);
    }
    int fd = socket(family, kind, 0);
    if (fd < 0) { perror("socket"); return 1; }
    struct iovec buf = { .iov_base = "x", .iov_len = 1 };
    struct msghdr msg = { .msg_name = &dst, .msg_namelen = len, .msg_iov = &buf, .msg_iovlen = 1 };
    int ret = use_msg ? sendmsg(fd, &msg, 0) : connect(fd, (struct sockaddr *)&dst, len);
    int err = ret < 0 ? errno : 0;
    close(fd);
    if (deny ? err == EPERM : (err == 0 || (kind == SOCK_STREAM && err == ECONNREFUSED))) return 0;
    fprintf(stderr, "family %d socket %d port %d sendmsg %d expected deny %d errno %d\n",
            family, kind, port, use_msg, deny, err);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    if (strcmp(argv[1], "-")) {
        int fd = open(argv[1], O_WRONLY);
        if (fd < 0 || write(fd, "0", 1) != 1) { perror("enter test cgroup"); return 1; }
        close(fd);
    }
    int guard = !strcmp(argv[2], "protected");
    const int ports[] = { 53, 853, 443, 5353 };
    const int families[] = { AF_INET, AF_INET6 };
    for (size_t f = 0; f < 2; ++f) for (size_t p = 0; p < 4; ++p) {
        int deny = guard && (p < 2);
        if (probe(families[f], SOCK_STREAM, ports[p], 0, deny)
            || probe(families[f], SOCK_DGRAM, ports[p], 0, deny)
            || probe(families[f], SOCK_DGRAM, ports[p], 1, deny)) return 1;
    }
    puts(guard ? "24 protected-group checks passed" : "24 unrestricted checks passed");
    return 0;
}
