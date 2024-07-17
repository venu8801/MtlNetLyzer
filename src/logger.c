// logger.c

#include "logger.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>   /* For exit() and EXIT_FAILURE*/
#include <time.h>     /* For time_t, localtime(), strftime()*/

 FILE *logfile = NULL;

void open_log_file() {
     time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char logfile_name[100];
    strftime(logfile_name, sizeof(logfile_name) - 1, "./log/log_file_%Y_%m_%d_%H_%M_%S.txt", t);
    logfile = fopen(logfile_name, "w");
    if (logfile == NULL) {
        perror("Failed to open log file");
        exit(EXIT_FAILURE);
    }
     else {
        printf("Log file opened: %s\n", logfile_name);  /* Print success message*/
    }
}


void log_printf(FILE *log_file, const char *format, ...) {
    va_list args;
    
    /* Print to the log_file if it's open*/
    if (log_file != NULL) {
        va_start(args, format);
        vfprintf(log_file, format, args);
        va_end(args);
        fflush(log_file); /* Ensure the log is written immediately*/
    }
#if PRINT_ON_TERMINAL
    /* Print to the terminal*/
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
#endif
}



void close_log_file() {
    if (logfile != NULL) {
        fclose(logfile);
        logfile = NULL;
    }
}

