#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <stdint.h>

//Constante

#define NAME_LEN 32
#define CAT_LEN 32
#define DESC_LEN 128
#define REPORTS_FILE "reports.dat"
#define CONFIG_FILE "district.cfg"
#define LOG_FILE "logged_district"

//Report (packed = no padding, portable binary layout)

typedef struct {
    uint32_t id;
    char     inspector[NAME_LEN];
    float    latitude;
    float    longitude;
    char     category[CAT_LEN];
    uint32_t severity;      //1=minor 2=moderat 3=critical
    time_t   timestamp;
    char     description[DESC_LEN];
} __attribute__((packed)) Report;

//CLI state 
static char  g_role[20];
static char  g_user[20];
static char  g_op[24];
static char  g_district[64];
static char  g_extra[20];       /* report_id sau threshold */
static int   g_value;
static char  g_conds[10][64];
static int   g_nconds;

/* permisiuninile binare */
static void mode_to_str(mode_t m, char out[10]) 
{
    out[0] = (m & S_IRUSR) ? 'r' : '-';  
    out[1] = (m & S_IWUSR) ? 'w' : '-';
    out[2] = (m & S_IXUSR) ? 'x' : '-';  
    out[3] = (m & S_IRGRP) ? 'r' : '-';
    out[4] = (m & S_IWGRP) ? 'w' : '-';  
    out[5] = (m & S_IXGRP) ? 'x' : '-';
    out[6] = (m & S_IROTH) ? 'r' : '-';  
    out[7] = (m & S_IWOTH) ? 'w' : '-';
    out[8] = (m & S_IXOTH) ? 'x' : '-';  
    out[9] = '\0';
}

/*
 Acces Role-based  (manager = owner bits, inspector = group bits).
 Returneaza 0 daca are voie, -1 daca nu.
 */
 
static int check_access(const char *path, int need_read, int need_write) {
    struct stat st;
    if (stat(path, &st) < 0) 
        return 0;  //inca nu e creat fisierul
    mode_t m = st.st_mode;
    int ok = 1;
    if (strcmp(g_role, "manager") == 0) 
    {
        if (need_read  && !(m & S_IRUSR)) ok = 0;
        if (need_write && !(m & S_IWUSR)) ok = 0;
    }
    else 
    {
        if (need_read  && !(m & S_IRGRP)) ok = 0;
        if (need_write && !(m & S_IWGRP)) ok = 0;
    }
    if (!ok)
    {
        fprintf(stderr, "Permission denied: role '%s' cannot %s '%s'\n",
                g_role, need_write ? "write" : "read", path);
        return -1;
    }
    return 0;
}

static void log_action(const char *action) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", g_district, LOG_FILE);

    struct stat st;
    if (stat(path, &st) == 0 &&
        strcmp(g_role, "inspector") == 0 && !(st.st_mode & S_IWGRP))
        return;  

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    chmod(path, 0644);

    char ts[32], line[256];
    time_t now = time(NULL);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    int n = snprintf(line, sizeof(line),
                     "[%s] role=%s user=%s action=%s\n", ts, g_role, g_user, action);
    write(fd, line, n);
    close(fd);
}

static int ensure_district(void) 
{
    struct stat st;
    if (stat(g_district, &st) < 0) {
        if (mkdir(g_district, 0750) < 0) { perror("mkdir"); return -1; }
        chmod(g_district, 0750);
    }
    char p[256];
    snprintf(p, sizeof(p), "%s/%s", g_district, CONFIG_FILE);
    if (stat(p, &st) < 0) {
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0640);
        if (fd < 0) { perror("open cfg"); return -1; }
        write(fd, "threshold=2\n", 12);
        close(fd);
        chmod(p, 0640);
    }
    snprintf(p, sizeof(p), "%s/%s", g_district, LOG_FILE);
    if (stat(p, &st) < 0) {
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) close(fd);
        chmod(p, 0644);
    }
    return 0;
}

static void update_symlink(void) {
    char link[256], target[256];
    snprintf(link,   sizeof(link),   "active_reports-%s", g_district);
    snprintf(target, sizeof(target), "%s/%s", g_district, REPORTS_FILE);
    struct stat lst;
    if (lstat(link, &lst) == 0) unlink(link);
    if (symlink(target, link) < 0) perror("symlink");
}

static uint32_t next_id(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 1;
    uint32_t max = 0;
    Report r;
    while (read(fd, &r, sizeof(r)) == (ssize_t)sizeof(r))
        if (r.id > max) max = r.id;
    close(fd);
    return max + 1;
}

//Comenzi

static void cmd_add(void)
{
    if (ensure_district() < 0) return;
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", g_district, REPORTS_FILE);
    if (check_access(path, 0, 1) < 0) return;

    Report r;
    memset(&r, 0, sizeof(r));
    r.id        = next_id(path);
    r.timestamp = time(NULL);
    strncpy(r.inspector, g_user, NAME_LEN - 1);

    printf("Latitude  : "); fflush(stdout); scanf("%f",  &r.latitude);
    printf("Longitude : "); fflush(stdout); scanf("%f",  &r.longitude);
    getchar();
    printf("Category (road/lighting/flooding/other): "); fflush(stdout);
    fgets(r.category, CAT_LEN, stdin);
    r.category[strcspn(r.category, "\n")] = '\0';
    printf("Severity (1-3): "); fflush(stdout); scanf("%u", &r.severity);
    getchar();
    if (r.severity < 1 || r.severity > 3) r.severity = 1;
    printf("Description: "); fflush(stdout);
    fgets(r.description, DESC_LEN, stdin);
    r.description[strcspn(r.description, "\n")] = '\0';

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0664);
    if (fd < 0) { perror("open"); return; }
    chmod(path, 0664);
    write(fd, &r, sizeof(r));
    close(fd);

    update_symlink();
    log_action("add");
    printf("Report #%u added to district '%s'.\n", r.id, g_district);
}

static void cmd_list(void) 
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", g_district, REPORTS_FILE);
    if (check_access(path, 1, 0) < 0) return;

    struct stat st;
    if (stat(path, &st) < 0) { printf("No reports found for '%s'.\n", g_district); return; }

    char perm[10], ts[32];
    mode_to_str(st.st_mode, perm);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&st.st_mtime));
    printf("File: %s | Perms: %s | Size: %lld bytes | Modified: %s\n",
           path, perm, (long long)st.st_size, ts);
    printf("----------------------------------------------------------\n");

    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return; }
    Report r; int n = 0;
    while (read(fd, &r, sizeof(r)) == (ssize_t)sizeof(r)) {
        { time_t _t = r.timestamp; strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&_t)); }
        printf("ID:%-4u | %-20s | %-12s | Sev:%u | %s\n",
               r.id, r.inspector, r.category, r.severity, ts);
        n++;
    }
    close(fd);
    if (!n) printf("(no reports)\n");
    else    printf("----------------------------------------------------------\n");
    log_action("list");
}

static void cmd_view(void) 
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", g_district, REPORTS_FILE);
    if (check_access(path, 1, 0) < 0) return;

    uint32_t tid = (uint32_t)strtoul(g_extra, NULL, 10);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return; }

    Report r;
    while (read(fd, &r, sizeof(r)) == (ssize_t)sizeof(r)) 
    {
        if (r.id == tid) {
            char ts[32];
            { time_t _t = r.timestamp; strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&_t)); }
            printf("===================================\n");
            printf("Report ID   : %u\n",            r.id);
            printf("Inspector   : %s\n",             r.inspector);
            printf("GPS         : %.4f, %.4f\n",     r.latitude, r.longitude);
            printf("Category    : %s\n",             r.category);
            printf("Severity    : %u\n",             r.severity);
            printf("Timestamp   : %s\n",             ts);
            printf("Description : %s\n",             r.description);
            printf("===================================\n");
            close(fd); log_action("view"); return;
        }
    }
    close(fd);
    printf("Report #%u not found in '%s'.\n", tid, g_district);
}

static void cmd_remove_report(void) 
{
    if (strcmp(g_role, "manager") != 0) {
        fprintf(stderr, "Permission denied: manager only.\n"); return;
    }
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", g_district, REPORTS_FILE);
    if (check_access(path, 1, 1) < 0) return;

    struct stat st;
    if (stat(path, &st) < 0) { perror("stat"); return; }
    long n = st.st_size / sizeof(Report);

    int fd = open(path, O_RDWR);
    if (fd < 0) { perror("open"); return; }

    uint32_t tid = (uint32_t)strtoul(g_extra, NULL, 10);
    long del = -1; Report r;
    for (long i = 0; i < n; i++) {
        lseek(fd, i * sizeof(r), SEEK_SET);
        read(fd, &r, sizeof(r));
        if (r.id == tid) { del = i; break; }
    }
    if (del < 0) { printf("Report #%u not found.\n", tid); close(fd); return; }

    for (long i = del + 1; i < n; i++) {
        lseek(fd, i * sizeof(r), SEEK_SET);
        read(fd, &r, sizeof(r));
        lseek(fd, (i - 1) * sizeof(r), SEEK_SET);
        write(fd, &r, sizeof(r));
    }
    ftruncate(fd, (n - 1) * sizeof(r));
    close(fd);

    update_symlink();
    log_action("remove_report");
    printf("Report #%u removed from '%s'.\n", tid, g_district);
}

static void cmd_update_threshold(void) 
{
    if (strcmp(g_role, "manager") != 0) {
        fprintf(stderr, "Permission denied: manager only.\n"); return;
    }
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", g_district, CONFIG_FILE);

    int fc = open(path, O_WRONLY | O_CREAT | O_EXCL, 0640);
    if (fc >= 0) close(fc);

    struct stat st;
    if (stat(path, &st) < 0) { perror("stat cfg"); return; }
    if ((st.st_mode & 0777) != 0640) {
        fprintf(stderr, "Security alert: %s perms are %o, expected 640. Refusing.\n",
                path, st.st_mode & 0777);
        return;
    }
    if (check_access(path, 0, 1) < 0) return;

    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) { perror("open cfg"); return; }
    char buf[64];
    int len = snprintf(buf, sizeof(buf), "threshold=%d\n", g_value);
    write(fd, buf, len);
    close(fd);

    log_action("update_threshold");
    printf("Threshold updated to %d in '%s'.\n", g_value, g_district);
}

/*de bagat filter*/


//Argument parsing + main
static void usage(void) 
{
    fprintf(stderr,
        "Usage: city_manager --role <manager|inspector> --user <name> --<cmd> [args]\n"
        "Commands: --add <d>  --list <d>  --view <d> <id>  --remove_report <d> <id>\n"
        "          --update_threshold <d> <val>  --filter <d> [cond ...]\n");
}

int main(int argc, char *argv[]) 
{
    int role_set = 0, user_set = 0, op_set = 0;

    for (int i = 1; i < argc; i++) 
    {
        if      (!strcmp(argv[i],"--role") && i+1<argc) { strcpy(g_role, argv[++i]); role_set=1; }
        else if (!strcmp(argv[i],"--user") && i+1<argc) { strcpy(g_user, argv[++i]); user_set=1; }
        else if ((!strcmp(argv[i],"--add") || !strcmp(argv[i],"--list")) && i+1<argc) {
            strcpy(g_op, argv[i]); strcpy(g_district, argv[++i]); op_set=1;
        }
        else if ((!strcmp(argv[i],"--view") || !strcmp(argv[i],"--remove_report")) && i+2<argc) {
            strcpy(g_op, argv[i]); strcpy(g_district, argv[++i]);
            strcpy(g_extra, argv[++i]); op_set=1;
        }
        else if (!strcmp(argv[i],"--update_threshold") && i+2<argc) {
            strcpy(g_op, argv[i]); strcpy(g_district, argv[++i]);
            g_value = atoi(argv[++i]); op_set=1;
        }
        else if (!strcmp(argv[i],"--filter") && i+1<argc) {
            strcpy(g_op, argv[i]); strcpy(g_district, argv[++i]);
            while (i+1 < argc && argv[i+1][0] != '-')
                strcpy(g_conds[g_nconds++], argv[++i]);
            op_set=1;
        }
    }

    if (!role_set || !user_set || !op_set) { usage(); return 1; }
    if (strcmp(g_role,"manager")!=0 && strcmp(g_role,"inspector")!=0) {
        fprintf(stderr, "Invalid role: %s\n", g_role); return 1;
    }

    const char *cmd = g_op + 2;   
    if      (!strcmp(cmd,"add"))   
        cmd_add();
    else if (!strcmp(cmd,"list"))             
        cmd_list();
    else if (!strcmp(cmd,"view"))         
        cmd_view();
    else if (!strcmp(cmd,"remove_report"))    
        cmd_remove_report();
    else if (!strcmp(cmd,"update_threshold")) 
        cmd_update_threshold();
    else if (!strcmp(cmd,"filter"))           
        cmd_filter();
    else 
    { 
        fprintf(stderr, "Unknown command: %s\n", g_op); 
        return 1; 
    }

    return 0;
}
