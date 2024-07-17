
#include <sys/types.h>
#include "MtlPktLyzer.h"
#include "func_dec.h"
#include <beacon_parser.h>
#include <stdbool.h>
#include <scan.h>
#include "logger.h"

extern FILE *logfile;

pthread_cond_t captureDone = PTHREAD_COND_INITIALIZER;
pthread_mutex_t beaconMutex = PTHREAD_MUTEX_INITIALIZER;


/* beacon queue nodes*/
struct packet_node *rear = NULL;
struct packet_node *front = NULL;

int beacon_count = 1;
int beaconCaptureCount = INTIALIZATION_VAL;

/*channels description for 2.4 and 5ghz */

//int channels_2ghz_5ghz[] = {1,2,3,4,5,6,7,8,9,10,11,36,40,44,48,149,153,157,161,165};


/* Static structure to hold sorted beacon packet information */
#define MAX_PACKETS 30  // Define the maximum number of packets the static structure can hold
struct static_beacon_node {
    char timer[16];
    long microsec;
    uint8_t addr[6];
    char ssid[32];
    uint8_t addr_da[6];
    uint8_t addr_sa[6];
    float support_rate[16];
    uint8_t suratetag_len;
    int ant_signal;
    uint8_t bandwidth;
    int channel_number;
    uint8_t rsn_taglen;
    uint8_t cipher_type;
} sorted_beacon_nodes[MAX_PACKETS];
int sorted_beacon_count = 0;



/*Funtion to switch channels*/

void switch_channel(const char *interface, int channel) 
{
	char command[100];
	snprintf(command, sizeof(command), "sudo iw dev %s set channel %d", interface, channel);
	system(command);
}

/*capturing beacon thread*/

void *beacon_capture_thread(void *args)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    pcap_t *handle = (pcap_t *)args;
   log_printf(logfile, "\n---------------------------------%s-----------------------------------------\n", __func__);
   log_printf(logfile, "capturing packets\n");

    /* Set the timeout for pcap handle outside the loop as it is applied for each packet capture attempt */
    pcap_set_timeout(handle, TIMEOUT_MS);

    while (1)
    {
        for (int i = 0; i < sizeof(channels_2ghz_5ghz) / sizeof(int); i++)
        {
            int packetsCapturedOnCurrentChannel = INTIALIZATION_VAL;
            time_t startTime = time(NULL);

            /* Switch to the next channel */
            switch_channel(INTERFACE, channels_2ghz_5ghz[i]);
            sleep(CHANNEL_SWITCH_INTERVAL);

            while (packetsCapturedOnCurrentChannel < PACKETS_PER_CHANNEL)
            {
                /*Lock the mutex before attempting to capture packets */
                pthread_mutex_lock(&beaconMutex);

                int res = pcap_next_ex(handle, &header, &packet);
                if (res == 1)  /* Successfully captured a packet */
                {
                    beaconCaptureCount++;
                    packetsCapturedOnCurrentChannel++;

                    if (beaconCaptureCount > PACKET_COUNT_PER_CYCLE)
                    {
                        log_printf(logfile, "signalling parse thread cap count: %d\n", beaconCaptureCount);
                        pthread_cond_signal(&captureDone);
                        log_printf(logfile, "waiting till parse completes\n");
                        pthread_cond_wait(&captureDone, &beaconMutex);
                        log_printf(logfile, "out of wait [cap]\n");
                        beaconCaptureCount = INTIALIZATION_VAL;
                    }

              /*    printf("packet capture %d\n", beaconCaptureCount);*/
              
               /* Extract the data from beacon  */
                    beacon_handler_routine((u_char *)handle, header, packet);
                }
                /* Handle errors */
                else if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)  
                {
                    log_printf(logfile, "Error or break in pcap capture\n");
                    pthread_mutex_unlock(&beaconMutex);
                    break;
                }

                /* Unlock the mutex after handling the packet */
                pthread_mutex_unlock(&beaconMutex);

                /* Break if no packet is captured within 1 second */
                if (time(NULL) - startTime >= TIMEOUT_PAC_CAP)
                {
                    break;
                }

                /* Small sleep to prevent tight looping */
               usleep(100);
            }
        }
    }
}



/* call back function which creates thread for beacon parser */
int beacon_thread_implement(const char *filter_exp, char *interface, pcap_t *handle, struct beacon_fptr *bfptr)
{
	struct bpf_program fp;
	pthread_t beacon_parser_id, beacon_capture_id;
	if ((pthread_create(&beacon_capture_id, NULL, bfptr->bfill_fptr, (void *)handle) != 0) ||
			(pthread_create(&beacon_parser_id, NULL, bfptr->bparse_fptr, (void *)handle) != 0))
	{
		fprintf(stderr, "Error creating beacon parser thread\n");
		pcap_freecode(&fp); /*Free the compiled filter*/
		pcap_close(handle); /* Close pcap handle  */
		return EXIT_FAILURE;
	}

	/* Wait for the packet capture thread to finish */
	pthread_join(beacon_capture_id, NULL);
	pthread_join(beacon_parser_id, NULL);
}

/* printing thread for the beacon  */

void *beacon_parser_thread(void *args) 
{
    pcap_t *handle = (pcap_t *)args;
    while (1)
     {
        log_printf(logfile, "\n---------------%s---------------------------------\n",__func__);
        log_printf(logfile, "Trying to acquire mutex in parser thread\n");
        pthread_mutex_lock(&beaconMutex);
        if (rear == NULL) 
        {
            log_printf(logfile, "Waiting for capture thread (rear is NULL)\n");
            pthread_cond_wait(&captureDone, &beaconMutex);
        } 
        else if (beaconCaptureCount < PACKET_COUNT_PER_CYCLE) 
        {
            log_printf(logfile, "Waiting for capture thread (not enough packets)\n");
            pthread_cond_wait(&captureDone, &beaconMutex);
        }
        
#if DELETE_DUPS
        delete_duplicate_packet();
#endif
      system("clear");
        sort_antSignal();
        display_sorted_beacon_nodes();
        log_printf(logfile, "Signalling capture thread\n");
        pthread_cond_signal(&captureDone);
        pthread_mutex_unlock(&beaconMutex);
        log_printf(logfile, "Mutex released in parser thread\n");
        sleep(PARSE_DELAY);
    }
}

/* beacon handle thread */
void beacon_handler_routine(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes) //inputs for this function are user info  ,len ,time, bytes
{
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

	/* Pointer to the start of the IEEE 802.11 header, right after the Radiotap header */
	const uint8_t *ieee80211_header = bytes + header_len;

	/* Destination Address is the first address field in the 802.11 header for management frames */
	const uint8_t *da = ieee80211_header + FRAME_DUR_BYTES; // Skipping Frame Control (2 bytes) and Duration (2 bytes)

	/*Source Address */
	const uint8_t *sa = ieee80211_header + FRAME_DUR_BYTES + DESTINATION_BYTES; // Skipping Frame Control (2 bytes), Duration (2 bytes), and DA (6 bytes)

	/* Extract SSID from tagged parameters */
	const u_char *tagged_params = bytes + header_len + SSID_TAG_PARM + SSID_PARM_LEN;
	size_t params_length = header->caplen - (header_len + SSID_TAG_PARM + SSID_PARM_LEN);

	/* Antenna signal strength at 30th byte */
	uint8_t *rssi_ptr = (uint8_t *)(bytes + RSN_VAL);
	int16_t rssi = (int16_t)(*rssi_ptr);

	const u_char *support_datarate = tagged_params + *(tagged_params + TAG_PARM_BYTES) + TAG_PARM_MOV_BYTE; /* TAG_PARM_MOV_BYTE=2 it helps for shifting the bytes to extarct supported rates */ 
	uint8_t tag_len = *(support_datarate + RSN_TAG_VAL);
	uint8_t data[tag_len];
	uint16_t ele_id = ELE_ID;
	int i = INTIALIZATION_VAL;
	float support_rate[SUPPORT_RATE_SIZE];
	for (i = INTIALIZATION_VAL; i < tag_len; i++)
	{
		data[i] = (int)*(support_datarate + DATA_OFFSET + i);
	}

	const u_char *k=NULL, *j=NULL;
	const u_char *lsb=NULL ;
	k = support_datarate;
	j = k + SEARCH_RANGE;
	for (k; k < j; k++)
	{
		if (*k == SEARCH_BYTE)
		{
			lsb = (k + TAG_PARM_MOV_BYTE);
		}
	}

/* extarcting the channel number from frequency  */	
uint8_t  channel_no = extract_channel(bytes);

    
    /* copy all the members of structure */
    struct queue_node_arg NodeQueue;
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
    if (lsb != NULL)
    {
        NodeQueue.lsb = lsb;
        NodeQueue.channel_num = channel_no; // Assuming lsb is a single byte, adjust as needed
        insert_beacon_queue(&NodeQueue);
    }
}



/* Function to create a node for storing beacon packet information */
int insert_beacon_queue(struct queue_node_arg *NodeQueue)
{
    struct packet_node *BeaconNode;
    BeaconNode = (struct packet_node *)malloc(1 * sizeof(struct packet_node));
    if (BeaconNode == NULL)
    {
        log_printf(logfile, "Memory not allocated\n");
        return -1;
    }
    
    /*  Copy the time string to the timer field*/
    strcpy(BeaconNode->timer, NodeQueue->tmr);
    
  
    BeaconNode->microsec = NodeQueue->usec;
    for (int i = INTIALIZATION_VAL; i < ITERATING_INSERT_LOOP_VAL; i++)
    {
        BeaconNode->addr[i] = NodeQueue->mac[i];
    }
     /* Copying SSID */
    copy_ssid(NodeQueue->tagged_params, NodeQueue->tag_len, BeaconNode->ssid);

    /* Destination Address */
    for (int i = INTIALIZATION_VAL; i < ITERATING_INSERT_LOOP_VAL; i++)
    {
        BeaconNode->addr_da[i] = NodeQueue->da[i];
    }
   
    /*  Source Address */
    for (int i = INTIALIZATION_VAL; i < ITERATING_INSERT_LOOP_VAL; i++)
    {
        BeaconNode->addr_sa[i] = NodeQueue->sa[i];
    }
   
    /*support data rate*/
    for (int i = INTIALIZATION_VAL; i < NodeQueue->tag_len; i++)
    {
        /* Extract rate from data and convert to Mbps */
        uint8_t rate = NodeQueue->data[i] & BASIC_RATE_MASK; // Mask out the MSB, which indicates basic rate
        float rate_mbps = (float)rate / RATE_DIVISOR;

        BeaconNode->support_rate[i] = rate_mbps;
    }
    
    /*bandwidth calculation*/
    BeaconNode->bandwidth = (*(NodeQueue->lsb) & CIPHER_OFFSET_WPA);
   BeaconNode->suratetag_len = NodeQueue->tag_len;
    BeaconNode->ant_signal = NodeQueue->ant_signal;
    BeaconNode->channel_number = NodeQueue->channel_num;
    
      //RSN info 
    const u_char *address;
    address = NodeQueue->tagged_params;

   for(address;address<(NodeQueue->tagged_params+SEARCH_RANGE);address++)
   {
       if(*address ==  RSN_INFO_ADD)  //for RSN info 
       {
           BeaconNode->rsn_taglen = (int)(*(address+ RSN_TAG_VAL));
           BeaconNode->cipher_type = *(address+CIPHER_TAG_VAL);
       }
   }
    
    BeaconNode->next = NULL;
   
    if (rear == NULL)
        front = rear = BeaconNode;
    else
        rear->next = BeaconNode;
    rear = BeaconNode;

    return 0;
}


/*Function to extract SSID*/
void copy_ssid(const u_char *tagged_params, size_t length, uint8_t *buf) /*inputs are tagged parametres, lenght of ssid ,buffer to store */
{
	size_t i = INTIALIZATION_VAL, j;
	while (i < length)
	{
		uint8_t tag_type = tagged_params[i];
		uint8_t tag_len = tagged_params[i + 1];
		if (tag_type == 0)
		{ // SSID tag type
			for (j = INTIALIZATION_VAL; j < tag_len; ++j)
			{
				char ssid_char = tagged_params[i + SSID_TAG_VAL + j];
				buf[j] = ssid_char;
			}
			buf[j] = '\0'; // null terminator
			break;
		}
		i += SSID_TAG_VAL + tag_len; // Move to the next tag
	}
}


/* Function to delete duplicate nodes */
void delete_duplicate_packet()
{
  struct packet_node *p, *q, *s;
    if (rear == NULL)
    {
        log_printf(logfile, "Queue is empty\n");
        return;
    }
    for (p = front; p != NULL; p = p->next)
    {
        for (s = p, q = p->next; q != NULL;)
        {
            int count = 1;
            for (int i = INTIALIZATION_VAL; i < 6; i++)
            {
                if (p->addr[i] != q->addr[i])
                {
                    count = 0;
                    break;
                }
            }
            if (count)
            {
                s->next = q->next;
                if (q == rear)
                {
                    rear = s;
                }
                struct packet_node  *temp = q;
                q = q->next;
              
                free(temp);
            }
            else
            {
                s = q;
                q = q->next;
            }
        }
    }
}




/* sorting of nodes by their strength using bubble sort exchange by links */
void sort_antSignal()
{

    if (front == NULL)
    {
        log_printf(logfile, "list is empty\n");
        return;
    }
    if (front == rear)
        return;
    struct packet_node  *p, *q, *e = NULL, *s, *r, *temp;

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
    	    // Copy the sorted data to the static structure and free the old nodes
    struct packet_node  *current = front;
    sorted_beacon_count = INTIALIZATION_VAL;
    while (current != NULL && sorted_beacon_count < MAX_PACKETS)
    {
        strncpy(sorted_beacon_nodes[sorted_beacon_count].timer, current->timer, sizeof(sorted_beacon_nodes[sorted_beacon_count].timer));
        sorted_beacon_nodes[sorted_beacon_count].microsec = current->microsec;
        memcpy(sorted_beacon_nodes[sorted_beacon_count].addr, current->addr, sizeof(sorted_beacon_nodes[sorted_beacon_count].addr));
        strncpy(sorted_beacon_nodes[sorted_beacon_count].ssid, (char*)current->ssid, sizeof(sorted_beacon_nodes[sorted_beacon_count].ssid));
        memcpy(sorted_beacon_nodes[sorted_beacon_count].addr_da, current->addr_da, sizeof(sorted_beacon_nodes[sorted_beacon_count].addr_da));
        memcpy(sorted_beacon_nodes[sorted_beacon_count].addr_sa, current->addr_sa, sizeof(sorted_beacon_nodes[sorted_beacon_count].addr_sa));
        memcpy(sorted_beacon_nodes[sorted_beacon_count].support_rate, current->support_rate, sizeof(sorted_beacon_nodes[sorted_beacon_count].support_rate));
        sorted_beacon_nodes[sorted_beacon_count].suratetag_len = current->suratetag_len;
        sorted_beacon_nodes[sorted_beacon_count].ant_signal = current->ant_signal;
        sorted_beacon_nodes[sorted_beacon_count].bandwidth = current->bandwidth;
        sorted_beacon_nodes[sorted_beacon_count].channel_number = current->channel_number;
        sorted_beacon_nodes[sorted_beacon_count].rsn_taglen = current->rsn_taglen;
        sorted_beacon_nodes[sorted_beacon_count].cipher_type = current->cipher_type;

        sorted_beacon_count++;

        struct packet_node  *temp = current;
        current = current->next;
        free(temp);
    }
    front = rear = NULL;
}

/*function for display the beacon queue  */
void display_sorted_beacon_nodes() 
{
	log_printf(logfile, "Sorted Beacon Nodes:\n");
    for (int i = INTIALIZATION_VAL; i < sorted_beacon_count; ++i) 
    {
       log_printf(logfile, "%d >", i + 1);
        log_printf(logfile, "Timestamp: %s.%06ld\t", sorted_beacon_nodes[i].timer, sorted_beacon_nodes[i].microsec);
        log_printf(logfile, "  BSSID: ");
        for (int j = INTIALIZATION_VAL; j < ITERATING_DISPLAY_LOOP_VAL; ++j)
        {
            log_printf(logfile, "%02x:", sorted_beacon_nodes[i].addr[j]);
        }
        /* Potential error */
        if (sizeof(sorted_beacon_nodes[i].addr) / sizeof(sorted_beacon_nodes[i].addr[0]) >= DESTINATION_BYTES)
         {
            log_printf(logfile, "%02x", sorted_beacon_nodes[i].addr[MAC_ADDR_LEN]); 
        } 
        else
         {
       
            log_printf(logfile, "Error: sorted_beacon_nodes[%d].addr is NULL or index out of bounds\n", i);
        }
#if BEACON_EXTRA_INFO
        /* Destination Address */
       
        log_printf(logfile, "\tDA: ");
        for (int j = INTIALIZATION_VAL; j < ITERATING_INSERT_LOOP_VA; ++j){
            log_printf(logfile, "%02x:", sorted_beacon_nodes[i].addr_da[j]);}
        log_printf(logfile, "%02x", sorted_beacon_nodes[i].addr_da[MAC_ADDR_LEN]);

        /* Source Address */
        log_printf(logfile, "\tSA: ");
        for (int j = INTIALIZATION_VAL; j < ITERATING_INSERT_LOOP_VAL; ++j)
            log_printf(logfile, "%02x:", sorted_beacon_nodes[i].addr_sa[j]);
        log_printf(logfile, "%02x", sorted_beacon_nodes[i].addr_sa[MAC_ADDR_LEN]);
#endif
        log_printf(logfile, "\tSignal: %ddBm", sorted_beacon_nodes[i].ant_signal - SIGNAL_OFFSET);

	/*Check if SSID is hidden or not */
	if (strlen(sorted_beacon_nodes[i].ssid) == INTIALIZATION_VAL) {
	
		log_printf(logfile, "\tHidden SSID");
	} else {
		log_printf(logfile, "\tNormal mode");
		log_printf(logfile, "\tSSID: %s", sorted_beacon_nodes[i].ssid);
	}
	log_printf(logfile, "\n");
        log_printf(logfile, "\tSupported Rates: ");
        for (int j = INTIALIZATION_VAL; j < sorted_beacon_nodes[i].suratetag_len; j++) {
            log_printf(logfile, "%.1f", sorted_beacon_nodes[i].support_rate[j]);
            if (j != sorted_beacon_nodes[i].suratetag_len - RSN_TAG_VAL)
                log_printf(logfile, ", ");
        }
        log_printf(logfile, "\t[Mbit/sec]\n");
	log_printf(logfile, "\n");

        if (sorted_beacon_nodes[i].bandwidth == INTIALIZATION_VAL)
         {
            log_printf(logfile, "\tSupports only for 20MHz\t");
        } 
        else 
        {
            log_printf(logfile, "\tSupports 20MHz and 40MHz  ");
        }
        log_printf(logfile, "\tChannel %d", sorted_beacon_nodes[i].channel_number);

        if (sorted_beacon_nodes[i].rsn_taglen < RSN_VAL) 
        {
            if (sorted_beacon_nodes[i].cipher_type == CIPHER_OFFSET_WPA) 
            {
                log_printf(logfile, "\tWPA-TKIP");
            }
             else if (sorted_beacon_nodes[i].cipher_type == CIPHER_OFFSET_WPA2) 
            {
                log_printf(logfile, "\tWPA2-AES");
            }
        } 
        else 
        {
            log_printf(logfile, "\tno RSN field\n");
        }

        log_printf(logfile, "\n\n");
    }
    log_printf(logfile, "\n");
    beaconCaptureCount = INTIALIZATION_VAL; /* reset count again to 0 */
    log_printf(logfile, "\n----------------------------------------------------------------------------------\n");
}



/*function for extarcting the channel number from the channel frequency */

uint8_t extract_channel(const u_char *packet)/*it takes the input as packet information*/
{
	uint8_t freq1 = *(packet + START_ADDR_FREQ1);
	uint8_t freq2 = *(packet + START_ADDR_FREQ2);
	int i;
	uint16_t freq = freq2;

	for (i = INTIALIZATION_VAL; i < 8; i++)
   		 freq = freq << SHIFTING_VAL_FREQ;
	freq = freq | freq1;

	if (freq >= FREQ_2GHZ_LOWER_BOUND && freq <= FREQ_2GHZ_UPPER_BOUND)
    	/* 2.4 GHz band (Channels 1-13)*/
    	return (freq - FREQ_2GHZ_BASE) / CHANNEL_SPACING; /* calculating the channel number from channel frequency of 2.4ghz*/
    
	else if (freq == FREQ_2GHZ_CHANNEL_14)
    	/* 2.4 GHz band (Channel 14)*/
    	return CHANNEL_14_VAL;
    
	else if (freq >= FREQ_5GHZ_LOWER_BOUND && freq <= FREQ_5GHZ_UPPER_BOUND)
    	/* 5 GHz band*/
	return (freq - FREQ_5GHZ_BASE) / CHANNEL_SPACING; /* calculating the channel number from channel frequency of 5ghz*/
    
	else
    	/* Unknown frequency*/
    	return 0; // Or any suitable default value
}

