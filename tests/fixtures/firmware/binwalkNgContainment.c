/* Test-only producer: exercise the exact selected confinement policy in both
 * leader and descendant. This is containment evidence, not native-format evidence. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>

static int check_policy(char **argv) {
    int fd = open(argv[1], O_RDONLY);
    int host_denied = fd < 0;
    if (fd >= 0) close(fd);
    fd = open(argv[2], O_RDONLY);
    int input_readable = fd >= 0;
    if (fd >= 0) close(fd);
    fd = open(argv[2], O_WRONLY);
    int input_write_denied = fd < 0;
    if (fd >= 0) close(fd);
    fd = open("/work/probe.txt", O_CREAT | O_WRONLY, 0600);
    int work_writable = fd >= 0;
    if (fd >= 0) close(fd);
    int inherited_denied = fcntl(atoi(argv[4]), F_GETFD) < 0 && errno == EBADF;
    int ambient_denied = getenv("REA_TEST_AMBIENT_CANARY") == NULL;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(atoi(argv[3]));
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    int network_denied = sock < 0 || connect(sock, (struct sockaddr *)&address, sizeof(address)) < 0;
    if (sock >= 0) close(sock);
    printf("host_denied=%d input_readable=%d input_write_denied=%d work_writable=%d inherited_denied=%d ambient_denied=%d network_denied=%d\n", host_denied, input_readable, input_write_denied, work_writable, inherited_denied, ambient_denied, network_denied);
    fflush(stdout);
    return !(host_denied && input_readable && input_write_denied && work_writable && inherited_denied && ambient_denied && network_denied);
}

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    int result = check_policy(argv);
    pid_t child = fork();
    if (child < 0) return 3;
    if (child == 0) _exit(check_policy(argv));
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 4;
    return result || WEXITSTATUS(status);
}
