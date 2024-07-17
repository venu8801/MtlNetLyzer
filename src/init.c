#include <stdio.h>
#include <init.h>
#include <util.h>
#include "scan.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>



#define MAX_LINE_LENGTH 256
#define MAX_NAME_LENGTH 50
#define MAX_VALUE_LENGTH 200
#define MAX_CHANNELS 20

char key[MAX_NAME_LENGTH];
char value[MAX_VALUE_LENGTH];

int TIMEOUT_PAC_CAP = 0;
int TIMEOUT_PAC_CAP_set = 0;

int channels_2ghz_5ghz[MAX_CHANNELS];
int channels_2ghz_5ghz_set = 0;
int num_channels_2ghz_5ghz = 0;

// Function to trim leading and trailing whitespaces
char *trim_whitespace(char *str) {
    char *end;

    // Trim leading space
    while (isspace((unsigned char)*str)) str++;

    if (*str == 0)  // All spaces?
        return str;

    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    // Write new null terminator
    *(end + 1) = 0;

    return str;
}

// Function to read and assign configuration values
void read_config(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return;
    }

    char line[MAX_LINE_LENGTH];

    while (fgets(line, sizeof(line), file) != NULL) {
        char *trimmed_line = trim_whitespace(line);
        if (sscanf(trimmed_line, "%[^=]=%s", key, value) == 2) {
            if (strcmp(key, "TIMEOUT_PAC_CAP") == 0) {
                if (TIMEOUT_PAC_CAP_set) {
                    fprintf(stderr, "Error: Duplicate key 'TIMEOUT_PAC_CAP' found.\n");
                    fclose(file);
                    exit(EXIT_FAILURE);
                }
                TIMEOUT_PAC_CAP = atoi(value);
                if (TIMEOUT_PAC_CAP > 1) {
                    fprintf(stderr, "Error: 'TIMEOUT_PAC_CAP' should not be greater than 1.\n");
                    fclose(file);
                    exit(EXIT_FAILURE);
                }
                TIMEOUT_PAC_CAP_set = 1;
                printf("TIMEOUT_PAC_CAP: %d\n", TIMEOUT_PAC_CAP);
            } else if (strcmp(key, "channels_2ghz_5ghz") == 0) {
                if (channels_2ghz_5ghz_set) {
                    fprintf(stderr, "Error: Duplicate key 'channels_2ghz_5ghz' found.\n");
                    fclose(file);
                    exit(EXIT_FAILURE);
                }

                char *token = strtok(value, ",");
                while (token != NULL && num_channels_2ghz_5ghz < MAX_CHANNELS) {
                    channels_2ghz_5ghz[num_channels_2ghz_5ghz++] = atoi(token);
                    token = strtok(NULL, ",");
                }

                channels_2ghz_5ghz_set = 1;
                printf("channels_2ghz_5ghz: ");
                for (int i = 0; i < num_channels_2ghz_5ghz; ++i) {
                    printf("%d ", channels_2ghz_5ghz[i]);
                }
                printf("\n");
            }
            // Add more configuration keys as needed
        }
    }

    fclose(file);
}
