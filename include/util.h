#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//extern int res;





#define MAX_LINE_LENGTH 256
typedef struct {
    char key[MAX_LINE_LENGTH];
    char value[MAX_LINE_LENGTH];
} ConfigEntry;


extern int ReadValues(char* str);
extern int LOG_LEVEL;
extern void UsageHandler(char *str);


