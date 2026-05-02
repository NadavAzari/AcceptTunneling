#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main(void)
{
    int srv = socket(AF_INET, SOCK_STREAM, 0);

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(9999),
        .sin_addr.s_addr = INADDR_ANY,
    };
    bind(srv, (struct sockaddr *)&addr, sizeof(addr));
    listen(srv, 8);

    printf("[server] listening on :9999  (pid %d)\n", getpid());
    fflush(stdout);

    while (1) {
        struct sockaddr_in client;
        socklen_t len = sizeof(client);

        int fd = accept(srv, (struct sockaddr *)&client, &len);
        if (fd < 0) {
            perror("accept");
            continue;
        }

        char buf[64];
        inet_ntop(AF_INET, &client.sin_addr, buf, sizeof(buf));
        printf("[server] connection from %s:%d  fd=%d\n",
               buf, ntohs(client.sin_port), fd);
        fflush(stdout);

        close(fd);
    }
}
