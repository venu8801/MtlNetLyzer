// logger.h

#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h> // For timestamp formatting


#define PRINT_ON_TERMINAL 1



extern FILE *logfile;
void open_log_file();
void close_log_file();

void log_printf(FILE *log_file, const char *format, ...);

void generate_logfile_name(char *logfile_name, size_t size);

#endif // LOGGER_H

