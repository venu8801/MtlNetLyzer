struct packet_node {
    char timer[16];
    unsigned long int microsec;
    uint8_t addr[6];
    char ssid[50];
    uint8_t addr_da[6];
    uint8_t addr_sa[6];
    int16_t ant_signal;
    float support_rate[8];
    struct packet_node *next;
};
int beacon_thread_implement(const char *filter_exp, char *interface, pcap_t *handle, void* (*thread_ptr)(void *) );
void *beacon_parser_thread(void *args);
void beacon_handler_routine(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes);
int insert_beacon_queue(char *tmr, unsigned int usec, uint8_t *mac, const u_char *tagged_params, size_t length, const uint8_t *da, const uint8_t *sa, int16_t ant_signal);
void display_packet_queue();
void delete_duplicate_packet();
// Function to extract SSID
void copy_ssid(const u_char *tagged_params, size_t length, uint8_t *buf);

/* sorts based on antenna signal 
 * uses bubble sort 
 */
void sort_antSignal();

#define BEACON_LIMIT 100	/* beacon frames limit */
#define PARSE_DELAY 3