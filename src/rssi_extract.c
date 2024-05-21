// parses radiotap info

// #include <beacon_parser.h>
#include <sys/types.h>
#include "MtlPktLyzer.h"
#include "func_dec.h"
#include "dbgprint.h"
#include <beacon_parser.h>
#include <stdbool.h>
pthread_cond_t captureDone = PTHREAD_COND_INITIALIZER;
pthread_mutex_t beaconMutex = PTHREAD_MUTEX_INITIALIZER;

/* beacon queue nodes*/
struct packet_node *rear = NULL;
struct packet_node *front = NULL;
int beacon_count = 1;
int beaconCaptureCount = 0;

/*captures beacons */
void *beacon_capture_thread(void *args)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    pcap_t *handle = (pcap_t *)args;
    printf("\n---------------------------------%s-----------------------------------------\n", __func__);
    dbg_log(MSG_DEBUG, "-----------beacon capture---------\n");
    printf("capturing packets\n");
    // Capture packets until the timeout or a fixed number of packets is reached
    while (1)
    {
         pthread_mutex_lock(&beaconMutex);
        if (pcap_next_ex(handle, &header, &packet) == 1)
        {
            
            //printf("inside while\n");
            beaconCaptureCount++;
            //pthread_mutex_lock(&beaconMutex);
            if (beaconCaptureCount > PACKET_COUNT_PER_CYCLE)
            {
                printf("signalling parse thread cap count: %d\n",beaconCaptureCount);
                pthread_cond_signal(&captureDone);
                printf("waiting till parse completes\n");
                pthread_cond_wait(&captureDone, &beaconMutex);
                printf("out of wait [cap]\n");
            }
            printf("packet capture %d\n", beaconCaptureCount);
            beacon_handler_routine((u_char *)handle, header, packet); // extract the data from beacon
            pthread_mutex_unlock(&beaconMutex);
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

/* thread which captures packets from handle */
void *beacon_parser_thread(void *args)
{
    pcap_t *handle = (pcap_t *)args;
    while (1)
    {
        printf("\n---------------------------------%s-----------------------------------------\n", __func__);
        dbg_log(MSG_DEBUG, "-----------beacon capture---------\n");
        // pcap_loop(handle, BEACON_LIMIT, beacon_handler_routine, NULL);
        // sleep(PARSE_DELAY);
        printf("trying to acquire mtx\n");
        pthread_mutex_lock(&beaconMutex);
        if (rear == NULL){
            printf("waiting for capture thread\n");
            pthread_cond_wait(&captureDone, &beaconMutex);
            printf("out of wait [parse]\n");
        }
#if DELETE_DUPS
        delete_duplicate_packet();
#endif
        sort_antSignal();
        display_packet_queue();
        printf("signalling cap thread\n");
        pthread_cond_signal(&captureDone);
         pthread_mutex_unlock(&beaconMutex);
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
    const u_char *lsb;
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
    NodeQueue.lsb = lsb;
    insert_beacon_queue(&NodeQueue);
    // printf("insert\n");
}

// Function to create a node for storing beacon packet information
int insert_beacon_queue(struct queue_node_arg *NodeQueue)
{
    // printf("new node\n");
    struct packet_node *BeaconNode;
    BeaconNode = (struct packet_node *)malloc(1 * sizeof(struct packet_node));
    if (BeaconNode == NULL)
    {
        printf("Memory not allocated\n");
        return -1;
    }
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
    BeaconNode->bandwidth = (*(NodeQueue->lsb) & 0x02);
    // printf("insert band\n");
    BeaconNode->suratetag_len = NodeQueue->tag_len;
    // printf("insert tag len\n");
    BeaconNode->ant_signal = NodeQueue->ant_signal;
    BeaconNode->next = NULL;
    // printf("insert ant_sig\n");
    if (rear == NULL)
        front = rear = BeaconNode;
    else
        rear->next = BeaconNode;
    rear = BeaconNode;

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

// Function to display packet information
void display_packet_queue()
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
        printf("%02x", BeaconNode->addr[5]);
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
            printf("\tSupports only for 20MHz\n");
        }
        else
        {

            printf("\tSupports 20MHz and 40MHz\n");
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

// Function to delete duplicate nodes
void delete_duplicate_packet()
{
    struct packet_node *p, *q, *s;
    if (rear == NULL)
    {
        printf("Queue is empty\n");
        return;
    }
    for (p = front; p != NULL; p = p->next)
    {
        for (s = p, q = p->next; q != NULL;)
        {
            int count = 1;
            for (int i = 0; i < 6; i++)
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
                struct packet_node *temp = q;
                q = q->next;
                // printf("deletion\n");
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
