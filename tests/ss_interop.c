/* Black-box client and disposable origin for the independent ss-server matrix. */
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define COUNT 180123
static unsigned char bytes[COUNT], echo[COUNT];

static void require(int valid, const char *name) {
    if (!valid) { perror(name); exit(1); }
}
static void all(int sock, unsigned char *buf, size_t len, int writing) {
    while (len) {
        ssize_t n = writing ? send(sock, buf, len, 0) : recv(sock, buf, len, 0);
        require(n > 0, writing ? "send" : "recv");
        len -= (size_t)n; buf += n;
    }
}
static struct sockaddr_in addr(const char *ip, unsigned short port) {
    struct sockaddr_in value = {.sin_family = AF_INET, .sin_port = htons(port)};
    require(inet_pton(AF_INET, ip, &value.sin_addr) == 1, "invalid fixture address");
    return value;
}
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    alarm(15);
    int negative = !strcmp(argv[3], "wrong");
    int http = !strcmp(argv[3], "http");
    int server = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in dest = addr(argv[1], 0), proxy = addr("127.0.0.1", atoi(argv[2]));
    require(bind(server, (struct sockaddr *)&dest, sizeof(dest)) == 0 && listen(server, 2) == 0, "origin");
    socklen_t size = sizeof(dest);
    require(getsockname(server, (struct sockaddr *)&dest, &size) == 0, "origin address");
    int sent[2];
    require(pipe(sent) == 0, "probe synchronization");
    pid_t child = fork();
    require(child >= 0, "fork");
    if (child == 0) {
        close(sent[1]);
        if (negative) {
            unsigned char published = 0;
            require(read(sent[0], &published, 1) == 1, "missing wrong-key attempt");
        }
        close(sent[0]);
        struct pollfd p = {server, POLLIN, 0};
        int ready = poll(&p, 1, negative ? 700 : 6500);
        if (negative) _exit(ready == 0 ? 0 : 1);
        require(ready == 1, "missing origin connection");
        int accepted = accept(server, NULL, NULL);
        require(accepted >= 0, "accept");
        all(accepted, bytes, COUNT, 0);
        all(accepted, bytes, COUNT, 1);
        close(accepted); _exit(0);
    }
    close(server); close(sent[0]);
    int local = socket(AF_INET, SOCK_STREAM, 0);
    require(connect(local, (struct sockaddr *)&proxy, sizeof(proxy)) == 0, "proxy connect");
    for (size_t i = 0; i < COUNT; i++) bytes[i] = (unsigned char)(i * 53 + i / 257);
    size_t early = 0;
    if (http) {
        unsigned char req[1024]; char head[256];
        int n = snprintf(head, sizeof(head), "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\n\r\n",
                         argv[1], ntohs(dest.sin_port), argv[1], ntohs(dest.sin_port));
        early = 287;
        memcpy(req, head, (size_t)n); memcpy(req + n, bytes, early);
        all(local, req, (size_t)n + early, 1);
        size_t read = 0;
        do {
            require(read < sizeof(req) - 1, "CONNECT headers");
            all(local, &req[read++], 1, 0); req[read] = 0;
        } while (!strstr((const char *)req, "\r\n\r\n"));
        require(strstr((const char *)req, " 200 ") != NULL, "CONNECT response");
    } else {
        unsigned char greeting[] = {5,1,0}, answer[10], request[] = {5,1,0,1,0,0,0,0,0,0};
        memcpy(request+4, &dest.sin_addr, 4); memcpy(request+8, &dest.sin_port, 2);
        all(local, greeting, 3, 1); all(local, answer, 2, 0);
        require(answer[0] == 5 && answer[1] == 0, "SOCKS greeting");
        all(local, request, 10, 1); all(local, answer, 10, 0);
        require(answer[0] == 5 && answer[1] == 0, "SOCKS CONNECT");
    }
    if (negative) {
        (void)send(local, bytes, 128, MSG_NOSIGNAL);
        require(write(sent[1], bytes, 1) == 1, "probe synchronization");
    } else {
        all(local, bytes + early, COUNT - early, 1);
        all(local, echo, COUNT, 0);
        require(memcmp(bytes, echo, COUNT) == 0, "echo mismatch");
    }
    close(sent[1]);
    int status = 0;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "origin audit");
    close(local);
    return 0;
}
