#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdint.h>
#include <time.h>

#define NAME_LEN     32
#define CAT_LEN      32
#define DESC_LEN     128
#define REPORTS_FILE "reports.dat"
#define MAX_INSPECTORS 256

typedef struct {
    uint32_t id;
    char     inspector[NAME_LEN];
    float    latitude;
    float    longitude;
    char     category[CAT_LEN];
    uint32_t severity;
    time_t   timestamp;
    char     description[DESC_LEN];
} __attribute__((packed)) Report;

typedef struct {
    char     name[NAME_LEN];
    uint32_t total_severity;
    uint32_t report_count;
} InspectorScore;

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: scorer <district_id>\n");
        return 1;
    }

    const char *district = argv[1];

    struct stat st; //verifica existenta directorului
    if (stat(district, &st) < 0 || !S_ISDIR(st.st_mode)) {
        printf("ERROR:District '%s' does not exist or is not a directory.\n", district);
        fflush(stdout);
        return 1;
    }

    char reppath[256];
    snprintf(reppath, sizeof(reppath), "%s/%s", district, REPORTS_FILE);

    int fd = open(reppath, O_RDONLY);
    if (fd < 0) {
        printf("DISTRICT:%s\n", district);
        printf("INFO:No reports found (reports.dat missing).\n");
        printf("END:%s\n", district);
        fflush(stdout);
        return 0;
    }

    //citeste toate rapoartele si acumuleaza scorurile 
    InspectorScore scores[MAX_INSPECTORS];
    int n_inspectors = 0;

    Report r;
    while (read(fd, &r, sizeof(r)) == (ssize_t)sizeof(r))
    {
        //cauta inspector existent
        int found = 0;
        for (int i = 0; i < n_inspectors; i++) {
            if (strcmp(scores[i].name, r.inspector) == 0) {
                scores[i].total_severity += r.severity;
                scores[i].report_count++;
                found = 1;
                break;
            }
        }
        //daca nu exista il adauga
        if (!found && n_inspectors < MAX_INSPECTORS) {
            strncpy(scores[n_inspectors].name, r.inspector, NAME_LEN - 1);
            scores[n_inspectors].name[NAME_LEN - 1] = '\0';
            scores[n_inspectors].total_severity = r.severity;
            scores[n_inspectors].report_count   = 1;
            n_inspectors++;
        }
    }
    close(fd);

    //sorteaza descrescator dupa score
    for (int i = 0; i < n_inspectors - 1; i++) {
        for (int j = 0; j < n_inspectors - 1 - i; j++) {
            if (scores[j].total_severity < scores[j+1].total_severity) {
                InspectorScore tmp = scores[j];
                scores[j]   = scores[j+1];
                scores[j+1] = tmp;
            }
        }
    }

    //output pt city_hub
    printf("DISTRICT:%s\n", district);
    if (n_inspectors == 0) {
        printf("INFO:No reports in district '%s'.\n", district);
    } else {
        for (int i = 0; i < n_inspectors; i++) {
            printf("INSPECTOR:%s SCORE:%u REPORTS:%u\n",
                   scores[i].name,
                   scores[i].total_severity,
                   scores[i].report_count);
        }
    }
    printf("END:%s\n", district);
    fflush(stdout);

    return 0;
}
