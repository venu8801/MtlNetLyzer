// parses radiotap info

// #include <beacon_parser.h>
#include <sys/types.h>
#include "MtlPktLyzer.h"
#include "func_dec.h"
#include "dbgprint.h"
#include <beacon_parser.h>
#include <stdbool.h>
#include <scan.h>
pthread_cond_t captureDone = PTHREAD_COND_INITIALIZER;
pthread_mutex_t beaconMutex = PTHREAD_MUTEX_INITIALIZER;


// New structure is added here
static struct packet_node *non_duplicate_nodes = NULL;
// Define a structure to store non-duplicate nodes
struct non_duplicate_nodes {
	struct packet_node *node;
	struct non_duplicate_nodes *next;
};

// Declare a pointer to the head of the non-duplicate nodes structure
struct non_duplicate_nodes *non_duplicate_head = NULL;


/* beacon queue nodes*/
struct packet_node *rear = NULL;
struct packet_node *front = NULL;
int beacon_count = 1;
int beaconCaptureCount = 0;

int channels_2ghz_5ghz[] = {1,2,3,4,5,6,7,8,9,10,11,36,40,44,48,149,153,157,161,165};
//int channels_5ghz[] = {36,40,44,48,149,153,157,161,165};

/*Funtion to switch channels*/

void switch_channel(const char *interface, int channel) {
	char command[100];
	snprintf(command, sizeof(command), "sudo iw dev %s set channel %d", interface, channel);
	system(command);
	dbg_log(MSG_DEBUG, "Switched to channel %d on interface %s\n", channel, interface);
}


void *beacon_capture_thread(void *args)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    pcap_t *handle = (pcap_t *)args;
    printf("\n---------------------------------%s-----------------------------------------\n", __func__);
    dbg_log(MSG_DEBUG, "-----------beacon capture---------\n");
    printf("capturing packets\n");

    // Set the timeout for pcap handle outside the loop as it is applied for each packet capture attempt
    pcap_set_timeout(handle, TIMEOUT_MS);

    while (1)
    {
        for (int i = 0; i < sizeof(channels_2ghz_5ghz) / sizeof(int); i++)
        {
            int packetsCapturedOnCurrentChannel = 0;
            time_t startTime = time(NULL);

            // Switch to the next channel
            switch_channel(INTERFACE, channels_2ghz_5ghz[i]);
            sleep(CHANNEL_SWITCH_INTERVAL);

            while (packetsCapturedOnCurrentChannel < PACKETS_PER_CHANNEL)
            {
                // Lock the mutex before attempting to capture packets
                pthread_mutex_lock(&beaconMutex);

                int res = pcap_next_ex(handle, &header, &packet);
                if (res == 1)  // Successfully captured a packet
                {
                    beaconCaptureCount++;
                    packetsCapturedOnCurrentChannel++;

                    if (beaconCaptureCount > PACKET_COUNT_PER_CYCLE)
                    {
                        printf("signalling parse thread cap count: %d\n", beaconCaptureCount);
                        pthread_cond_signal(&captureDone);
                        printf("waiting till parse completes\n");
                        pthread_cond_wait(&captureDone, &beaconMutex);
                        printf("out of wait [cap]\n");
                        beaconCaptureCount = 0;
                    }

              //      printf("packet capture %d\n", beaconCaptureCount);
                    beacon_handler_routine((u_char *)handle, header, packet); // Extract the data from beacon
                }
                else if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)  // Handle errors
                {
                    printf("Error or break in pcap capture\n");
                    pthread_mutex_unlock(&beaconMutex);
                    break;
                }

                // Unlock the mutex after handling the packet
                pthread_mutex_unlock(&beaconMutex);

                // Break if no packet is captured within 1 second
                if (time(NULL) - startTime >= 1)
                {
              //      printf("No packet captured on channel %d within 1 second, switching channel\n", channels_2ghz_5ghz[i]);
                    break;
                }

                // Small sleep to prevent tight looping
                usleep(100);
            }
        }
    }
}



/* call back function which creates thread for beacon parser */
int beacon_thread_implement(const char *filter_exp, char *interface, pcap_t *handle, struct beacon_fptr *bfptr)
{
	// printf("\nInside beacon thread implement\n");
	struct bpf_program fp;
	pthread_t beacon_parser_id, beacon_capture_id;
	dbg_log(MSG_DEBUG, "beacon parser thread creation in process");
	if ((pthread_create(&beacon_capture_id, NULL, bfptr->bfill_fptr, (void *)handle) != 0) ||
			(pthread_create(&beacon_parser_id, NULL, bfptr->bparse_fptr, (void *)handle) != 0))
	{
		fprintf(stderr, "Error creating beacon parser thread\n");
		dbg_log(MSG_DEBUG, "Error creating beacon parser thread\n");
		pcap_freecode(&fp); // Free the compiled filter
		pcap_close(handle); // Close pcap handle
		return EXIT_FAILURE;
	}

	// Wait for the packet capture thread to finish
	pthread_join(beacon_capture_id, NULL);
	pthread_join(beacon_parser_id, NULL);
}

void *beacon_parser_thread(void *args) {
    pcap_t *handle = (pcap_t *)args;
    while (1) {
        printf("\n---------------------------------%s-----------------------------------------\n", __func__);
        dbg_log(MSG_DEBUG, "-----------beacon capture---------\n");
        printf("Trying to acquire mutex in parser thread\n");
        pthread_mutex_lock(&beaconMutex);
        if (rear == NULL) {
            printf("Waiting for capture thread (rear is NULL)\n");
            pthread_cond_wait(&captureDone, &beaconMutex);
            printf("Out of wait (rear is NULL) [parse]\n");
        } else if (beaconCaptureCount < PACKET_COUNT_PER_CYCLE) {
            printf("Waiting for capture thread (not enough packets)\n");
            pthread_cond_wait(&captureDone, &beaconMutex);
            printf("Out of wait (not enough packets) [parse]\n");
        }
        
#if DELETE_DUPS
        delete_duplicate_packet();
#endif
        //sort_antSignal();
        sort_antSignal(non_duplicate_nodes);
        display_packet_queue(non_duplicate_nodes);
        printf("Signalling capture thread\n");
        pthread_cond_signal(&captureDone);
        pthread_mutex_unlock(&beaconMutex);
        printf("Mutex released in parser thread\n");
        sleep(PARSE_DELAY);
    }
}

void beacon_handler_routine(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes)
{

	// printf("Inside %s\n",__func__);

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

	const u_char *support_datarate = tagged_params + *(tagged_params + 1) + 2;
	uint8_t tag_len = *(support_datarate + 1);
	uint8_t data[tag_len];
	uint16_t ele_id = 0x32;
	int i = 0;
	float support_rate[16];
	for (i = 0; i < tag_len; i++)
	{
		data[i] = (int)*(support_datarate + 2 + i);
	}

	const u_char *k, *j;
	const u_char *lsb = NULL;
	k = support_datarate;
	j = k + 100;
	for (k; k < j; k++)
	{
		if (*k == 0x2d)
		{
			lsb = (k + 2);
			// break;
		}
	}

	
uint8_t  channel_no = extract_channel(bytes);

	/* copy all the members of structure */
	struct queue_node_arg NodeQueue;
	memset(&NodeQueue,0,sizeof(struct queue_node_arg));
	NodeQueue.tmr = timestr;
	NodeQueue.usec = usec_value;
	NodeQueue.mac = bf->transmitter_address;
	NodeQueue.tagged_params = tagged_params;
	NodeQueue.length = params_length;
	NodeQueue.da = da;
	NodeQueue.sa = sa;
	NodeQueue.ant_signal = rssi;
	NodeQueue.data = data;
	NodeQueue.tag_len = tag_len;
        NodeQueue.lsb = lsb;
        NodeQueue.channel_num = channel_no; // Assuming lsb is a single byte, adjust as needed
        insert_beacon_queue(&NodeQueue);
    
}

// Function to create a node for storing beacon packet information
int insert_beacon_queue(struct queue_node_arg *NodeQueue)
{
	if (NodeQueue == NULL || NodeQueue->lsb == NULL) {
       // printf(" NodeQueue or NodeQueue->lsb is NULL\n");
        return -1;
    }
	
	struct packet_node *BeaconNode = (struct packet_node *)malloc(1 * sizeof(struct packet_node));
	if (BeaconNode == NULL)
	{
		printf("Memory not allocated\n");
		return -1;
	}
	memset(BeaconNode, 0, sizeof(struct packet_node));

	
	// printf("malloc-s\n");
	//  Copy the time string to the timer field
	strcpy(BeaconNode->timer, NodeQueue->tmr);
	// printf("insert strcpy\n");
	BeaconNode->microsec = NodeQueue->usec;
	for (int i = 0; i < 6; i++)
	{
		BeaconNode->addr[i] = NodeQueue->mac[i];
	}
	// printf("insert mac addr\n");
	//  Copying SSID
	copy_ssid(NodeQueue->tagged_params, NodeQueue->tag_len, BeaconNode->ssid);

	// Destination Address
	for (int i = 0; i < 6; i++)
	{
		BeaconNode->addr_da[i] = NodeQueue->da[i];
	}
	// printf("insert da\n");
	//  Source Address
	for (int i = 0; i < 6; i++)
	{
		BeaconNode->addr_sa[i] = NodeQueue->sa[i];
	}
	// printf("insert sa\n");
	/*support data rate*/
	for (int i = 0; i < NodeQueue->tag_len; i++)
	{
		// Extract rate from data and convert to Mbps
		uint8_t rate = NodeQueue->data[i] & 0x7F; // Mask out the MSB, which indicates basic rate
		float rate_mbps = (float)rate / 2.0;

		BeaconNode->support_rate[i] = rate_mbps;
	}
	// printf("insert su rate\n");
	/*bandwidth calculation*/
	
	//potential error
	//BeaconNode->bandwidth = (*(NodeQueue->lsb) & 0x02);
	
	// Check NodeQueue->lsb before dereferencing it
    if (NodeQueue->lsb != NULL) {
        BeaconNode->bandwidth = (*(NodeQueue->lsb) & 0x02);
    } else {
        printf("Error: NodeQueue->lsb is NULL\n");
        free(BeaconNode); // Free allocated memory before returning
        return -1;
    }
	
	// printf("insert band\n");
	BeaconNode->suratetag_len = NodeQueue->tag_len;
	// printf("insert tag len\n");
	BeaconNode->ant_signal = NodeQueue->ant_signal;
	BeaconNode->channel_number = NodeQueue->channel_num;

	//RSN info 
	const u_char *address;
	address = NodeQueue->tagged_params;

	for(address;address<(NodeQueue->tagged_params+100);address++)
	{
		if(*address == 0x30)  //for RSN info 
		{
			BeaconNode->rsn_taglen = (int)(*(address+1));
			BeaconNode->cipher_type = *(address+7);
		}
	}

	BeaconNode->next = NULL;
	// printf("insert ant_sig\n");printf("NodeQueue address: %p\n", (void *)NodeQueue);
  //  printf("NodeQueue->lsb address: %p\n", (void *)NodeQueue->lsb);
	
	if (rear == NULL)
		front = rear = BeaconNode;
	else {
		rear->next = BeaconNode;
		rear = BeaconNode;
	}
	
	return 0;
}

// Function to extract SSID
void copy_ssid(const u_char *tagged_params, size_t length, uint8_t *buf)
{
	size_t i = 0, j;
	while (i < length)
	{
		uint8_t tag_type = tagged_params[i];
		uint8_t tag_len = tagged_params[i + 1];
		if (tag_type == 0)
		{ // SSID tag type
			for (j = 0; j < tag_len; ++j)
			{
				char ssid_char = tagged_params[i + 2 + j];
				buf[j] = ssid_char;
			}
			buf[j] = '\0'; // null terminator
			break;
		}
		i += 2 + tag_len; // Move to the next tag
	}
}

//don't consider
// Function to display packet information
void display_packet_queue(struct packet_node *non_duplicate_nodes)
{
	struct packet_node *BeaconNode = front;
	if (BeaconNode == NULL)
	{
		printf("Queue is empty\n");
		return;
	}
	while (BeaconNode != NULL)
	{
		printf("%d >", beacon_count++);
		printf("Timestamp:%s.%06ld\t ", BeaconNode->timer, BeaconNode->microsec);
		printf("  BSSID:");
		for (int i = 0; i < 5; i++)
			printf("%02x:", BeaconNode->addr[i]);
		
		//potential error
		if (BeaconNode->addr != NULL && sizeof(BeaconNode->addr) / sizeof(BeaconNode->addr[0]) >= 6) {
			printf("%02x", BeaconNode->addr[5]); // Example access
		} else {
			printf("Error: BeaconNode->addr is NULL or index out of bounds\n");
		}
#if BEACON_EXTRA_INFO
		// Destination Address
		printf("\tDA:");
		for (int i = 0; i < 5; i++)
			printf("%02x:", BeaconNode->addr_da[i]);
		printf("%02x", BeaconNode->addr_da[5]);

		// Source Address
		printf("\tSA:");
		for (int i = 0; i < 5; i++)
			printf("%02x:", BeaconNode->addr_sa[i]);
		printf("%02x", BeaconNode->addr_sa[5]);
#endif
		printf("\tSignal: %ddBm", BeaconNode->ant_signal - 256);

		/*if SSID is in hidden mode or not in hidden mode*/
		(BeaconNode->ssid == NULL) ? printf("\t Hidden SSID"):printf("\t Normal mode");

		printf("\t  SSID: %s", BeaconNode->ssid);        
		printf("\n");
		printf("\tSupported Rates: ");
		for (int i = 0; i < BeaconNode->suratetag_len; i++)
		{
			printf("%.1f", BeaconNode->support_rate[i]);
			if (i != BeaconNode->suratetag_len - 1)
				printf(",   ");
		}
		printf("\t[Mbit/sec]");
		printf("\n");
		// printf("\tsupported bandwidth is %u\n",temp->bandwidth);
		if (BeaconNode->bandwidth == 0)
		{
			printf("\tSupports only for 20MHz\t");
		}
		else
		{

			printf("\tSupports 20MHz and 40MHz  ");
		}
		printf("\tChannel %d",BeaconNode->channel_number);

		/*
		   open - No RSN field
		   WPA  - TKIP --> 00-OF-AC-02
		   WPA2 - AES  --> 00-0F-AC-04

		   Check Group Cipher Suite type: AES (CCM) (4) field in beacon field 
		   */
		//printf("RSN tag number is %d\n",temp->rsn_tagno);
		if(BeaconNode->rsn_taglen<30)
		{
			if(BeaconNode->cipher_type==0x2)
			{
				printf("\tWPA-TKIP");
			}
			else if(BeaconNode->cipher_type==0x04)
			{
				printf("\tWPA2-AES");
			}



		}
		else //no RSN field 
		{
			printf("\tno RSN field\n");
		}

		printf("\n");
		printf("\n");

		BeaconNode = BeaconNode->next;
	}
	printf("\n");
	delete_all_nodes();
	beaconCaptureCount = 0; // reset count agian to 0
	//pthread_mutex_unlock(&beaconMutex);
	printf("----------------------------------------------------------------------------------\n");
}

void delete_all_nodes() {
	struct packet_node *temp,*next;
	temp=front;
	next=NULL;
	while (temp != NULL) {
		next = temp->next;
		free(temp);
		temp = next;
	}
	front=rear=NULL;
	printf("All nodes have been deleted.\n");
}



bool is_duplicate_in_structure(struct packet_node *node) {
    if (node == NULL) {
        // Handle the case where the input node is NULL
        printf("Error: Input node is NULL\n");
        return false;
    }

    //pthread_mutex_lock(&beaconMutex);  // Lock the mutex to ensure thread safety
    struct packet_node *current = non_duplicate_nodes;
    while (current != NULL) {
        // Compare the nodes to check for duplicates
        if (memcmp(current, node, sizeof(struct packet_node)) == 0) {
            //pthread_mutex_unlock(&beaconMutex);  // Unlock the mutex before returning
            return true; // Node is a duplicate
        }
        current = current->next;
    }
    //pthread_mutex_unlock(&beaconMutex);  // Unlock the mutex after finishing the loop
    return false; // Node is not a duplicate
}


void insert_non_duplicate_node(struct packet_node *node) {
	// Allocate memory for a new non_duplicate_nodes structure
	struct non_duplicate_nodes *new_node = (struct non_duplicate_nodes *)malloc(sizeof(struct non_duplicate_nodes));
	if (new_node == NULL) {
		printf("Memory allocation failed\n");
		return;
	}
	// Assign the node to the new non_duplicate_nodes structure
	new_node->node = node;
	new_node->next = NULL;
	// If the non_duplicate_nodes structure is empty, set the new node as the head
	if (non_duplicate_head == NULL) {
		non_duplicate_head = new_node;
		return;
	}
	// Traverse the non_duplicate_nodes structure to find the last node
	struct non_duplicate_nodes *temp = non_duplicate_head;
	while (temp->next != NULL) {
		temp = temp->next;
	}
	// Insert the new node at the end
	temp->next = new_node;
}


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
                if (!is_duplicate_in_structure(s)) {
                    insert_non_duplicate_node(s);
                }
            }
        }
    }
}

//don't consider
/* sorting of nodes by their strength using bubble sort exchange by links */
void sort_antSignal(struct packet_node *non_duplicate_nodes)
{

	if (front == NULL)
	{
		printf("list is empty\n");
		return;
	}
	if (front == rear)
		return;
	struct packet_node *p, *q, *e = NULL, *s, *r, *temp;

	for (e = NULL; front->next != e; e = q)
	{
		for (r = p = front; p->next != e; r = p, p = p->next)
		{
			q = p->next;
			if (p->ant_signal < q->ant_signal)
			{
				// printf("swap\n");
				p->next = q->next;
				q->next = p;
				if (p != front)
					r->next = q;
				else
					front = q;
				if (q == rear)
					rear = p;
				temp = p;
				p = q;
				q = temp;
			}
		}
	}
}


uint8_t extract_channel(const u_char *packet)

{

    uint8_t freq1 = *(packet + 26);
    uint8_t freq2 = *(packet + 27);
    int i;
//   printf("%x %x\n", freq1, freq2);
    uint16_t freq = freq2;

    for (i = 0; i < 8; i++)
        freq = freq << 1;
    freq = freq | freq1;
//   printf("Channel Freq %d Hz\n", freq);

    if (freq >= 2412 && freq <= 2472)
        // 2.4 GHz band (Channels 1-13)
        return (freq - 2407) / 5;
    else if (freq == 2484)
        // 2.4 GHz band (Channel 14)
        return 14;
    else if (freq >= 5180 && freq <= 5825)
        // 5 GHz band
        return (freq - 5000) / 5;
    else
        // Unknown frequency
        return 0; // Or any suitable default value

}

