#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>

#define MONITOR_PID ".monitor_pid"

//Flag-uri volatile pentru handler-e
static volatile sig_atomic_t g_got_sigusr1 = 0;
static volatile sig_atomic_t g_got_sigint  = 0;

//Handler SIGUSR1 
static void handler_sigusr1(int sig)
{
    (void)sig;
    g_got_sigusr1 = 1;
}

//Handler SIGINT
static void handler_sigint(int sig)
{
    (void)sig;
    g_got_sigint = 1;
}

//Timestamp helper (async-signal-safe nu e necesar in main)
static void print_ts(void)
{
    time_t now = time(NULL);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    printf("[%s] ", buf);
}

int main(void)
{
    pid_t my_pid = getpid();

    //Scrie PID in .monitor_pid
    int fd = open(MONITOR_PID, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
    {
        perror("open .monitor_pid");
        return 1;
    }
    char pidbuf[32];
    int n = snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)my_pid);
    write(fd, pidbuf, n);
    close(fd);

    print_ts();
    printf("monitor_reports started (PID %d). Watching for new reports...\n",
           (int)my_pid);
    fflush(stdout);

    //Instaleaza handlere cu sigaction()
    struct sigaction sa_usr1, sa_int;

    memset(&sa_usr1, 0, sizeof(sa_usr1));
    sa_usr1.sa_handler = handler_sigusr1;
    sigemptyset(&sa_usr1.sa_mask);
    sa_usr1.sa_flags = SA_RESTART;   //Restart syscalls intrerupte 
    if (sigaction(SIGUSR1, &sa_usr1, NULL) < 0)
    {
        perror("sigaction SIGUSR1"); unlink(MONITOR_PID); return 1;
    }

    memset(&sa_int, 0, sizeof(sa_int));
    sa_int.sa_handler = handler_sigint;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;   //Fara SA_RESTART – pause() sa se intoarca
    if (sigaction(SIGINT, &sa_int, NULL) < 0)
    {
        perror("sigaction SIGINT"); unlink(MONITOR_PID); return 1;
    }

    //Main Loop
    while (1)
    {
      pause();   //Asteapta un semnal

        if (g_got_sigusr1)
        {
            g_got_sigusr1 = 0;
            print_ts();
            printf("SIGUSR1 received: a new report has been added.\n");
            fflush(stdout);
        }

        if (g_got_sigint)
        {
            print_ts();
            printf("SIGINT received: monitor_reports shutting down.\n");
            fflush(stdout);
            break;
        }
    }

    //Curatenie la iesire 
    if (unlink(MONITOR_PID) < 0)
        perror("unlink .monitor_pid");

    return 0;
}
