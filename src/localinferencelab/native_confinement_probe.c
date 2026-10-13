/* Harmless, fixed-operation libc probes. Only the explicit Python harness builds this. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static int result(const char *operation, int ok, int error, unsigned int detail) {
    printf("{\"detail\":%u,\"errno\":%d,\"ok\":%s,\"operation\":\"%s\"}\n",
           detail, error, ok ? "true" : "false", operation);
    return fflush(stdout) == 0 ? 0 : 3;
}

static int limits(void) {
    const struct rlimit cpu = {1, 1}, core = {0, 0}, files = {1024, 1024}, fds = {256, 256};
    return setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_CORE, &core) ||
           setrlimit(RLIMIT_FSIZE, &files) || setrlimit(RLIMIT_NOFILE, &fds);
}

int main(int argc, char **argv) {
    if (argc < 3 || limits() != 0) return 2;
    const char *op = argv[1], *target = argv[2];
    if (strcmp(op, "exec_marker") == 0) {
        if (strcmp(target, "exec_self") != 0 && strcmp(target, "exec_other") != 0) return 2;
        return result(target, 1, 0, 0);
    }
    if (strncmp(op, "read_", 5) == 0) {
        int fd = open(target, O_RDONLY);
        if (fd < 0) return result(op, 0, errno, 0);
        unsigned char byte = 0;
        ssize_t n = read(fd, &byte, 1);
        int error = n == 1 ? 0 : (n < 0 ? errno : EIO);
        close(fd);
        return result(op, n == 1, error, byte);
    }
    if (strncmp(op, "write_", 6) == 0) {
        int fd = open(target, O_WRONLY | O_TRUNC);
        if (fd < 0) return result(op, 0, errno, 0);
        ssize_t n = write(fd, "W", 1);
        int error = n == 1 ? 0 : (n < 0 ? errno : EIO);
        close(fd);
        return result(op, n == 1, error, 0);
    }
    if (strcmp(op, "socket_loopback") == 0 || strcmp(op, "connect_loopback") == 0) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return result(op, 0, errno, 0);
        int rc = 0, error = 0;
        if (strcmp(op, "connect_loopback") == 0) {
            char *end = NULL;
            long port = strtol(target, &end, 10);
            if (*end != '\0' || port < 1 || port > 65535) { close(fd); return 2; }
            struct sockaddr_in address = {0};
            address.sin_family = AF_INET;
            address.sin_port = htons((unsigned short)port);
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            rc = connect(fd, (struct sockaddr *)&address, sizeof(address));
            if (rc < 0) error = errno;
        }
        close(fd);
        return result(op, rc == 0, error, 0);
    }
    if (strcmp(op, "fork") == 0) {
        pid_t child = fork();
        if (child < 0) return result(op, 0, errno, 0);
        if (child == 0) _exit(0);
        int status = 0;
        if (waitpid(child, &status, 0) != child) return result(op, 0, errno, 0);
        return result(op, WIFEXITED(status) && WEXITSTATUS(status) == 0,
                      status == 0 ? 0 : EIO, 0);
    }
    if (strcmp(op, "exec_self") == 0 || strcmp(op, "exec_other") == 0) {
        char *const args[] = {(char *)target, "exec_marker", (char *)op, NULL};
        char *const env[] = {NULL};
        execve(target, args, env);
        return result(op, 0, errno, 0);
    }
    if (strcmp(op, "descriptors") == 0) {
        unsigned int count = 0;
        for (int fd = 3; fd < 256; ++fd) {
            errno = 0;
            if (fcntl(fd, F_GETFD) >= 0 || errno != EBADF) ++count;
        }
        return result(op, count == 0, count == 0 ? 0 : EIO, count);
    }
    if (strcmp(op, "environment") == 0) {
        unsigned int count = 0;
        while (count < 65535 && environ[count] != NULL) ++count;
        return result(op, count == 0, count == 0 ? 0 : EIO, count);
    }
    return 2;
}
