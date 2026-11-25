/* HOST_ONLY fixture: no Qt, browser, network, device or vendor interaction. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping = 0;
static void stop(int signum) { (void) signum; stopping = 1; }
static double now_seconds(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
    return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}

int main(int argc, char **argv) {
    double deadline = now_seconds() + 9.0;
    struct timespec delay = { 0, 20000000 };
    signal(SIGTERM, stop);
    signal(SIGINT, stop);
    if (argc == 3 && strcmp(argv[1], "--helper") == 0) {
        pid_t child = fork();
        if (child < 0) return 81;
        if (child == 0) {
            if (setsid() < 0) _exit(82);
            execl(argv[2], "QtWebEngineProcess", "--escaped", (char *)0);
            _exit(83);
        }
        printf("HOST_ONLY_MAIN_READY pid=%ld escaped_child=%ld\n", (long)getpid(), (long)child);
    } else if (argc == 2 && strcmp(argv[1], "--escaped") == 0) {
        printf("HOST_ONLY_ESCAPED_READY pid=%ld group=%ld session=%ld\n",
               (long)getpid(), (long)getpgrp(), (long)getsid(0));
    } else if (argc == 2 && strcmp(argv[1], "--sentinel") == 0) {
        printf("HOST_ONLY_UNRELATED_SENTINEL_READY pid=%ld\n", (long)getpid());
    } else {
        return 84;
    }
    fflush(stdout);
    while (!stopping && now_seconds() < deadline) {
        struct timespec left = delay;
        while (nanosleep(&left, &left) < 0 && errno == EINTR && !stopping) {}
    }
    printf("HOST_ONLY_EXIT pid=%ld requested=%d\n", (long)getpid(), (int)stopping);
    fflush(stdout);
    return stopping ? 0 : 124;
}
