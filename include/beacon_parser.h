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



void delete_duplicate_packet();
// Function to extract SSID
void copy_ssid(const u_char *tagged_params, size_t length, uint8_t *buf);
void delete_all_nodes() ;
/* sorts based on antenna signal
 * uses bubble sort
 */
int insert_beacon_queue(struct queue_node_arg *NodeQueue);
//void insert_non_duplicate_node(struct packet_node *node);

void sort_antSignal();
uint8_t extract_channel(const u_char *packet);

void switch_channel(const char *interface, int channel);

void display_sorted_beacon_nodes();


//bool is_duplicate_in_structure(struct packet_node *node);
#define BEACON_LIMIT 50 /* beacon frames limit */
#define PARSE_DELAY 2
#define DELETE_DUPS 1
#define BEACON_EXTRA_INFO  0 /* adds extra info into
								beacon node*/
#define PACKET_COUNT_PER_CYCLE 15

#define FREQ_2GHZ_LOWER_BOUND 2412 /* starting freq of 2.4ghz */
#define FREQ_2GHZ_UPPER_BOUND 2472 /* ending freq of 2.4ghz */
#define FREQ_2GHZ_CHANNEL_14 2484
#define FREQ_5GHZ_LOWER_BOUND 5180 /* starting freq of 5ghz */
#define FREQ_5GHZ_UPPER_BOUND 5825 /* ending freq of 2.4ghz */
#define FREQ_2GHZ_BASE 2407 /*base value 2.4ghz freq for cal the channel no */
#define FREQ_5GHZ_BASE 5000 /*base value 5ghz freq for cal the channel no */
#define CHANNEL_SPACING 5 
#define ELE_ID 0x32
#define SUPPORT_RATE_SIZE 16 /*for supported rate cal */
#define DATA_OFFSET 2 /*offset for supported rates */
#define SEARCH_BYTE 0x2D /*searching the byte for the supported rate*/
#define SEARCH_RANGE 100 /*range cal for rsn*/
#define SIGNAL_OFFSET 256
#define CIPHER_OFFSET_WPA2 0x04 /*cipher offset value of wpa2*/
#define CIPHER_OFFSET_WPA 0x02/*cipher offset value of wpa*/
#define MAC_ADDR_LEN 5
#define RSN_INFO_ADD 0x30 /*rsn address offset value*/
#define SSID_TAG_PARM 24  /* tagged parameters for the ssid */
#define SSID_PARM_LEN 12 /*lenght of the tagged parameters */
#define FRAME_DUR_BYTES 4 /*skipping the frame & duration byte */
#define DESTINATION_BYTES 6 /*destination bytes for ssid extraction*/
#define BASIC_RATE_MASK 0x7F
#define RATE_DIVISOR 2.0
#define ITERATING_DISPLAY_LOOP_VAL 5 /*no of iteration for loop in the display func */
#define TAG_PARM_BYTES 1
#define TAG_PARM_MOV_BYTE 2 /*shifting the tagged parameters*/
#define SSID_TAG_VAL 2
#define RSN_TAG_VAL 1 /*rsn tag value */
#define CIPHER_TAG_VAL 7
#define ITERATING_INSERT_LOOP_VAL 6 /*no of iteration for loop in the insert func */
#define INTIALIZATION_VAL 0 /*initalising the all the value in loop */
#define SHIFTING_VAL_FREQ 1 /*value for the shifting the frequency*/
#define RSN_VAL 30 /*vaule for cal the rsn */
extern int TIMEOUT_PAC_CAP; /*timeout for the packet capturing*/
#define START_ADDR_FREQ1 26 /*starting address of the frequecy */
#define START_ADDR_FREQ2 27
#define CHANNEL_14_VAL 14




























