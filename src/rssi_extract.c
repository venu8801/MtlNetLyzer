//parses radiotap info

//#include <beacon_parser.h>
#include <sys/types.h>
#include "MtlPktLyzer.h"
#include "func_dec.h"
#include "dbgprint.h" 
#include <beacon_parser.h>


/* beacon queue nodes*/
struct packet_node *rear = NULL;
struct packet_node *front = NULL;
int beacon_count=1;


// int ssi_parser(const u_char *packet){
	
// 	struct radiotap_header * radioInfo = (struct radiotap_header *)packet;
// 	printf("size of radiottap struct: %ld\n",sizeof(struct radiotap_header));
// 	uint16_t rlen = radioInfo->it_len;
	
// //	printf("radio tap length: %d\n",*(packet + 2));
	
// 	printf("radio tap length: %d\n",rlen);

// 	//antenna signal strength at 30th byte
	
// 	uint8_t *rssi_ptr = packet + 30;

// 	uint8_t rssi =  (*rssi_ptr);
	
// 	//IEEE 802.11 beacon frame
// //	printf("r:%p  p:%p\n",radioInfo,packet);
// 	struct beacon_frame *beaconFrame = (struct beacon_frame *)((uint8_t *)radioInfo + rlen);
// 	printf("size: %ld\n",(char *)(beaconFrame) - (char *)radioInfo);
	
// 	printf("subtype: %x\n",beaconFrame->type_subtype);

// 	printf("Mac Addr: ");
// 	mac_parser( (uint8_t *)(beaconFrame->transmitter_address) );

// 	printf("Antenna Signal Hex : %02x\n",(uint8_t)rssi);
	
// 	printf("Antenna Signal : %d dBm\n",(int16_t)rssi - 256);
// 	insert_queue((uint8_t *)beaconFrame->transmitter_address, rssi);

// }



//int handle_beacon(const u_char* mgm_frame, )


/* call back function which creates thread for beacon parser */
int beacon_thread_implement(const char *filter_exp, char *interface, pcap_t *handle, void* (*thread_ptr)(void *) ){
	//printf("\nInside beacon thread implement\n");
	struct bpf_program fp;
	pthread_t beacon_parser_id;
	dbg_log(MSG_DEBUG,"beacon parser thread creation in process");
	 if (pthread_create(&beacon_parser_id, NULL, thread_ptr, (void *)handle) !=0 ) {
        fprintf(stderr, "Error creating beacon parser thread\n");
		dbg_log(MSG_DEBUG,"Error creating beacon parser thread\n");
        pcap_freecode(&fp); // Free the compiled filter
        pcap_close(handle); // Close pcap handle
        return EXIT_FAILURE;
    }
	
	 // Wait for the packet capture thread to finish
    pthread_join(beacon_parser_id, NULL);
}


/* thread which captures packets from handle */
void *beacon_parser_thread(void *args){
	pcap_t *handle = (pcap_t *)args;
	printf("Inside %s\n",__func__);
	dbg_log(MSG_DEBUG,"-----------beacon capture---------\n");	
	pcap_loop(handle,BEACON_LIMIT,beacon_handler_routine,NULL);
	sleep(PARSE_DELAY);
	delete_duplicate_packet();
	sort_antSignal();
	display_packet_queue();

}

void beacon_handler_routine(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes){

		//printf("Inside %s\n",__func__);

	struct radiotap_header *rth = (struct radiotap_header *)(bytes);
    int header_len = rth->it_len;
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;
    unsigned int usec_value;
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
    usec_value = header->ts.tv_usec;

    struct beacon_frame *bf = (struct beacon_frame *)(bytes + header_len);

    // Pointer to the start of the IEEE 802.11 header, right after the Radiotap header
    const uint8_t *ieee80211_header = bytes + header_len;

    // Destination Address is the first address field in the 802.11 header for management frames
    const uint8_t *da = ieee80211_header + 4; // Skipping Frame Control (2 bytes) and Duration (2 bytes)

    // Source Address
    const uint8_t *sa = ieee80211_header + 4 + 6; // Skipping Frame Control (2 bytes), Duration (2 bytes), and DA (6 bytes)

    // Extract SSID from tagged parameters
    const u_char *tagged_params = bytes + header_len + 24 + 12;
    size_t params_length = header->caplen - (header_len + 24 + 12);

    // Antenna signal strength at 30th byte
    uint8_t *rssi_ptr = (uint8_t *)(bytes + 30);
    int16_t rssi = (int16_t)(*rssi_ptr);

    insert_beacon_queue(timestr, usec_value, bf->transmitter_address, tagged_params, params_length, da, sa, rssi);
    


}

// Function to create a node for storing beacon packet information
int insert_beacon_queue(char *tmr, unsigned int usec, uint8_t *mac, const u_char *tagged_params, size_t length, const uint8_t *da, const uint8_t *sa, int16_t ant_signal) {
    struct packet_node *temp;
    temp = (struct packet_node *)malloc(sizeof(struct packet_node));
    if (temp == NULL) {
        printf("Memory not allocated\n");
        return -1;
    }
    // Copy the time string to the timer field
    strcpy(temp->timer, tmr);
    temp->microsec = usec;
    for (int i = 0; i < 6; i++) {
        temp->addr[i] = mac[i];
    }
    // Copying SSID
    copy_ssid(tagged_params, length, temp->ssid);

    // Destination Address
    for (int i = 0; i < 6; i++) {
        temp->addr_da[i] = da[i];
    }
    // Source Address
    for (int i = 0; i < 6; i++) {
        temp->addr_sa[i] = sa[i];
    }
    temp->ant_signal = ant_signal;
    temp->next = NULL;

    if (rear == NULL)
        front = rear = temp;
    else
        rear->next = temp;
    rear = temp;

	return 0;
}


// Function to extract SSID
void copy_ssid(const u_char *tagged_params, size_t length, uint8_t *buf) {
    size_t i = 0, j;
    while (i < length) {
        uint8_t tag_type = tagged_params[i];
        uint8_t tag_len = tagged_params[i + 1];
        if (tag_type == 0) { // SSID tag type
            for (j = 0; j < tag_len; ++j) {
                char ssid_char = tagged_params[i + 2 + j];
                buf[j] = ssid_char;
            }
            buf[j] = '\0'; // null terminator
            break;
        }
        i += 2 + tag_len; // Move to the next tag
    }
}

// Function to display packet information
void display_packet_queue() {
    struct packet_node *temp = front;
    if (temp == NULL) {
        printf("Queue is empty\n");
        return;
    }
    while (temp != NULL) {
        printf("%d >",beacon_count++);
        printf("Timestamp:%s.%06ld\t ", temp->timer, temp->microsec);
        printf("  BSSID:");
        for (int i = 0; i < 5; i++)
            printf("%02x:", temp->addr[i]);
        printf("%02x", temp->addr[5]);
 
       /* // Destination Address
        printf("\tDA:");
        for (int i = 0; i < 5; i++)
            printf("%02x:", temp->addr_da[i]);
        printf("%02x", temp->addr_da[5]);
 
        // Source Address
        printf("\tSA:");
        for (int i = 0; i < 5; i++)
            printf("%02x:", temp->addr_sa[i]);
        printf("%02x", temp->addr_sa[5]);*/
 
        printf("\tSignal: %ddBm", temp->ant_signal - 256);
        printf("\t  SSID: %s", temp->ssid);
        printf("\n");
 
        temp = temp->next;
    }
    printf("\n");
}

// Function to delete duplicate nodes
void delete_duplicate_packet() {
    struct packet_node *p, *q, *s;
    if (rear == NULL) {
        printf("Queue is empty\n");
        return;
    }
    for (p = front; p != NULL; p = p->next) {
        for (s = p, q = p->next; q != NULL;) {
            int count = 1;
            for (int i = 0; i < 6; i++) {
                if (p->addr[i] != q->addr[i]) {
                    count = 0;
                    break;
                }
            }
            if (count) {
                s->next = q->next;
                if (q == rear) {
                    rear = s;
                }
                struct packet_node *temp = q;
                q = q->next;
                free(temp);
            } else {
                s = q;
                q = q->next;
            }
        }
    }
}


void sort_antSignal(){

	if(front == NULL){
		printf("list is empty\n");
		return;
	}
	if(front == rear)
		return;
	struct packet_node *p,*q, *e = NULL, *s, *r, *temp;

	for(e = NULL; front->next != e; e = q)
	{
		for(r = p = front; p->next != e; r = p, p = p->next)
		{
			q = p->next;
			if(p->ant_signal < q->ant_signal)
			{
				p->next = q->next;
				q->next = p;
				if(p!=front)
					r->next = q;
				else
					front = q;
				if(q == rear)
					rear = p;
				temp = p;
				p = q;
				q = temp;
			}
		}
	}			
}