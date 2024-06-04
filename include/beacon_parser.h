struct packet_node
{
	char timer[16];
	unsigned long int microsec;
	uint8_t addr[6];
	char ssid[50];
	uint8_t addr_da[6];
	uint8_t addr_sa[6];
	int16_t ant_signal;
	float support_rate[8];
	uint8_t bandwidth;
	uint8_t suratetag_len;
	uint8_t channel_number;
	uint8_t rsn_taglen;
	uint8_t cipher_type;
	struct packet_node *next;
};

/* structure to pass to insert queue function*/
struct queue_node_arg
{

	char *tmr;
	unsigned int usec;
	uint8_t *mac;
	const u_char *tagged_params;
	size_t length;
	const uint8_t *da;
	const uint8_t *sa;
	int16_t ant_signal;
	uint8_t *data;
	uint8_t tag_len;
	const u_char *lsb;
	 u_char channel_num;
	
};
#define TIMEOUT_MS 100
#define CHANNEL_SWITCH_INTERVAL 1
#define PACKETS_PER_CHANNEL 10
//#define CHANNEL_HOP_INTERVAL 2

struct beacon_fptr{
void* (*bfill_fptr)(void *);
void* (*bparse_fptr)(void *);
};

int beacon_thread_implement(const char *filter_exp, char *interface, pcap_t *handle, struct beacon_fptr *);
void *beacon_parser_thread(void *args);
void *beacon_capture_thread(void *args);
void beacon_handler_routine(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes);
// Function to create a node for storing beacon packet information
//int insert_beacon_queue(struct queue_node_arg *);

void delete_duplicate_packet();
// Function to extract SSID
void copy_ssid(const u_char *tagged_params, size_t length, uint8_t *buf);
void delete_all_nodes() ;
/* sorts based on antenna signal
 * uses bubble sort
 */
int insert_beacon_queue(struct queue_node_arg *NodeQueue);
void insert_non_duplicate_node(struct packet_node *node);

void sort_antSignal(struct packet_node *non_duplicate_nodes);
uint8_t extract_channel(const u_char *packet);

void switch_channel(const char *interface, int channel);

void display_packet_queue(struct packet_node *non_duplicate_nodes);

//bool is_duplicate_in_structure(struct packet_node *node);
#define BEACON_LIMIT 50 /* beacon frames limit */
#define PARSE_DELAY 2
#define DELETE_DUPS 1
#define BEACON_EXTRA_INFO  0 /* adds extra info into
								beacon node*/
#define PACKET_COUNT_PER_CYCLE 15

