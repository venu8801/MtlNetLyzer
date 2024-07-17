#include "MtlPktLyzer.h"
#include "scan.h"
#include "func_dec.h"
#include<ctype.h>
#include "beacon_parser.h"
#include "logger.h"

extern FILE *logfile;


/* Define a simple function to print MAC addresses in a readable format*/
void print_mac_address(uint8_t *addr) 
{
    for (int i = INTIALIZATION_VAL; i < ITERATING_DISPLAY_LOOP_VAL; ++i) 
    {
        log_printf(logfile,"%02x:", addr[i]);
    }
    log_printf(logfile,"%02x   ", addr[5]);
}

/*function for printing the desination address */
void print_da_address(const uint8_t *addr) 
{
    log_printf(logfile,"%02x:%02x:%02x:%02x:%02x:%02x   ", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

/*function for printing the source address */
void print_sa_address(const uint8_t *addr) 
{
    log_printf(logfile,"%02x:%02x:%02x:%02x:%02x:%02x   ", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

/* function for printing type and subtype */
void print_type_and_subtype(uint16_t frame_control)  /*it takes the input as frame and compare the frame whether it is mgmt , ctrl or data */
{
    /* Arrays of strings representing Type and Subtype */
    const char *type_strings[] = {"Mgmt", "Ctrl", "Data"};  
    /* Extract Type and Subtype */
    uint8_t type = (frame_control >> SHIFT_BIT_TYPE) & TYPE_OFFSET_VAL;   /*Bits 2-3 */
    uint8_t subtype = (frame_control >> SHIFT_BIT_SUBTYPE) & SUBTYPE_OFFSET_VAL; /* Bits 4-7 */

    if(type == MGMT_TYPE) /*MGMT_TYPE= 0 means it a managment frame */
    {
	 const char *subtype_mgt[] = {	
						"Assoc-req", "Assoc-resp", "Reassoc-request", "Reassoc-resp",
						"Probe-req", "Probe-resp", "TIM     ", "Reserved", "Beacon    ", "ATIM       ", 			/*... Management frames... */
						"Disassociation ", "Authentication ", "Deauthentication", "Reserved", "Action", "Reserved"
					};				

	    /* Print Type and Subtype as strings */
 	 
 	   log_printf(logfile,"Type: %s\t", type_strings[type]);
  	  
  	   log_printf(logfile,"Subtype: %s    ", subtype_mgt[subtype]);
     }
     
    if(type == CTRL_TYPE) /*CTRL_TYPE = 1 means it is a control frame */
    {
	 const char *subtype_ctrl[] = {
					"Reserved", "Reserved", "Reserved", "Reserved", "Beamforming Report Poll", 
					"VHT/HE NDP Announcement", "Control Frame Extension", "Control wrapper",	 				  /*... Control frames..... */
					"Block-Ack-Req", "Block-Ack", "PS-Poll", "RTS      ",
					"CTS      ", "Ack     ", "CF-End     ", "CF-End + CF-Ack    "
					};
					
          /* Print Type and Subtype as strings */
 	 
 	   log_printf(logfile,"Type: %s\t", type_strings[type]);
  	  
  	   log_printf(logfile,"Subtype: %s    ", subtype_ctrl[subtype]);
  	   
    }
    
   if(type == DATA_TYPE) /*DATA_TYPE=2 means it is a  data frame */
    {
    
    	const char *subtype_data[] = {
					"Data     ", "Data+CF-ACK", "Data+CF-Poll", "Data + CF-ACK+Poll",
					"Null-Fun", "CF-ACK(no data)", "CF-Poll(no data)", "CF-ACK+Poll(no data)",
					"QoS Data", "QoS Data + CF-ACK", "QoS Data + CF-Poll", "QoS Data+CF-ACK+CF-Poll", 				/*..... Data frames.... */
					"QoS Null", "Reserved", "QoS CF-Poll(no data)", "QoS CF-ACK+CF-Poll(no data)"
					};
					
	          /* Print Type and Subtype as strings */
 	  
 	   log_printf(logfile,"Type: %s\t", type_strings[type]);
  	  
  	   log_printf(logfile,"Subtype: %s    ", subtype_data[subtype]);
  	   
  }				


}

/* function for extarcting the ssid */
void extract_ssid(const u_char *tagged_params , size_t params_length)
{
	size_t i = INTIALIZATION_VAL,j=INTIALIZATION_VAL;

	while(i < params_length)
	{

		uint8_t tag_type = tagged_params[i];
		uint8_t tag_len = tagged_params[i + 1];
	 	if (tag_type == INTIALIZATION_VAL) { /* SSID parameter set */
		    int char_print = 1;

		    /* Check if all characters in the SSID are printable */
		    for (j = INTIALIZATION_VAL; j < tag_len; ++j) 
		    {
		        char ssid_char = tagged_params[i + SSID_TAG_VAL + j];
		        if (!isprint(ssid_char)) 
		        {
		            char_print = INTIALIZATION_VAL;
		            break;
		        }
		    }

		    if (char_print)
		     {
		        for (j = INTIALIZATION_VAL; j < tag_len; ++j) 
		        {
		            
		            log_printf(logfile,"%c", tagged_params[i + SSID_TAG_VAL + j]);
		        }
		    } else 
		    {
		        for (j = INTIALIZATION_VAL; j < tag_len; ++j)
		         {
		            
		            log_printf(logfile,"%03x", tagged_params[i + SSID_TAG_VAL + j]);
		            if(j==3)
			    {
				  
				    log_printf(logfile,"\n");
		                    return;
			     }
		        }
		    }
		    break;
		}
        i +=  SSID_TAG_VAL+ tag_len; /*Move to the next tag */

	}
}


/*function for the extracting the channel number from channel frequency */
uint16_t extract_channel_frequency(const u_char *packet) 
{
    uint16_t channel_frequency = INTIALIZATION_VAL;

	uint16_t channel_no = INTIALIZATION_VAL;

	uint16_t frequency;
    /* Skip the Radiotap header version, pad, and length fields */
    const u_char *radiotap_header = packet;
    uint16_t radiotap_len = *(uint16_t *)(radiotap_header + 2);
        
        if(radiotap_len == CH_OFFSET)
        	channel_frequency = (*(uint16_t *)(radiotap_header + CH_FREQ1_OFFSET));/* Adjust offset based on actual structure */
        else
        	channel_frequency = (*(uint16_t *)(radiotap_header + CH_FREQ2_OFFSET));/*Adjust offset based on actual structure */

       
        log_printf(logfile,"channel frq:%d\t",channel_frequency);
        	
	
	if((channel_frequency >= FREQ_2GHZ_LOWER_BAND) &&( channel_frequency <= FREQ_2GHZ_UPPER_BAND ))
	{
        channel_no =  (channel_frequency - FREQ_2GHZ_BASE) / CHANNEL_SPACING;
	
	log_printf(logfile,"channel:%d\t",channel_no);

   	} 
   	else if((channel_frequency >= FREQ_5GHZ_LOWER_BAND)&&(channel_frequency <= FREQ_5GHZ_UPPER_BAND))
   	{
        channel_no =  (channel_frequency - FREQ_5GHZ_BASE) / CHANNEL_SPACING;
	
	log_printf(logfile,"channel:%d\t", channel_no);
        } 
   	 else 
   	 {
		
		 log_printf(logfile,"Invalid");
        return -1;
	
	 }
}

int determine_offset(const uint8_t *packet) 
{
    /* Check if the packet starts with a radiotap header
     A radiotap header typically starts with a version byte (0x00) followed by a length field
    The length field indicates the total length of the radiotap header */
    if (packet[0] == 0x00 && packet[1] > 0) 
    {
        /*The length of the radiotap header is stored in the second byte */
        int radiotap_length = packet[1];

        /*The IEEE 802.11 header usually starts after the radiotap header
         Add the length of the radiotap header to get the offset */
        int offset = radiotap_length;

        return offset;
    } else 
    {
        /* If there's no radiotap header, assume the IEEE 802.11 header starts at the beginning of the packet*/
        return 0;
    }
}

/* function for scan parse thread*/
void scan_parse_thread(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{
   
    log_printf(logfile,"enter into the scan_parse_thread\n");
    while (1) 
    {
        pthread_mutex_lock(&mutex);
        while (isQueueEmpty()) 
        {
            pthread_cond_wait(&cond, &mutex);
        }
        struct PacketNode packet = dequeuePacket();
        pthread_cond_signal(&cond);
        pthread_mutex_unlock(&mutex);

        struct tm *ltime;
        char timestr[16];
        time_t local_tv_sec;

        local_tv_sec = packet.header.ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

       
        log_printf(logfile,"%s.%06ld   ", timestr, packet.header.ts.tv_usec);

        /* Assuming the packet starts with a radiotap header*/
        struct radiotap_header *rth = (struct radiotap_header *)(packet.packet);

        /* Skipping the radiotap header for simplicity; you'd parse specific fields as needed*/
        int header_len = rth->it_len;

        /*Now, get to the beacon frame*/
        struct beacon_frame *bf = (struct beacon_frame *)(packet.packet + header_len);

        /* Extract and print the BSSID (transmitter address for beacon frames)*/
      
        log_printf(logfile,"BSSID:");
        print_mac_address(bf->transmitter_address);
        

        /* Pointer to the start of the IEEE 802.11 header, right after the Radiotap header*/
        const uint8_t *ieee80211_header = packet.packet + header_len;

        /* Destination Address is the first address field in the 802.11 header for management frames*/
        const uint8_t *da = ieee80211_header + FRAME_DUR_BYTES; /* Skipping Frame Control (2 bytes) and Duration (2 bytes)*/

        /* Print the Destination Address*/
     
        log_printf(logfile,"DA:");
        print_da_address(da);

        /* Assuming the IEEE 802.11 header directly follows the Radiotap header*/
        ieee80211_header = packet.packet + header_len;

        /* In a typical management frame like a beacon, DA, SA, and BSSID can essentially hold the same value.
         For educational purposes, we're treating the third MAC address as the Source Address (SA) here.*/
        const uint8_t *sa = ieee80211_header + FRAME_DUR_BYTES + DESTINATION_BYTES; /* Skipping Frame Control (2 bytes), Duration (2 bytes), and DA (6 bytes)*/

        /* Print the Source Address*/
      
        log_printf(logfile,"SA:");
        print_sa_address(sa);
        bf = (struct beacon_frame *)(packet.packet + header_len + SSID_TAG_PARM);

        /* Tagged parameters start after the fixed parameters of the beacon frame
           Fixed parameters are 12 bytes, but this could vary, adjust accordingly */
           
        const u_char *tagged_params = packet.packet + header_len + SSID_TAG_PARM + SSID_PARM_LEN;
        size_t params_length = packet.header.caplen - (header_len + SSID_TAG_PARM + SSID_PARM_LEN);

	uint16_t frame_control = *(uint16_t *)(packet.packet + header_len);

	print_type_and_subtype(frame_control);

	extract_channel_frequency(packet.packet); /*extraction of channel number*/

        /*Extract and print the SSID*/
        extract_ssid(tagged_params, params_length);

        int ieee80211_header_offset = 0 ;/*determine_offset(packet) ........... offset value here  This needs to be determined dynamically or set based on your environment*/
        const uint8_t *frame_body = packet.packet + ieee80211_header_offset;

        /* Assuming we're directly at the frame body of a Beacon frame...
        Skip fixed parameters of Beacon frame to reach the tagged parameters*/
       
        int fixed_parameters_length = 12; /* Timestamp (8 bytes) + Beacon Interval (2 bytes) + Capability Info (2 bytes)*/
      
        tagged_params = frame_body + fixed_parameters_length;
        int tagged_params_length = packet.header.caplen - ieee80211_header_offset - fixed_parameters_length;

        /* Parse tagged parameters for Supported Rates (ID 1), Extended Supported Rates (ID 50), and DS Parameter Set (ID 3)*/
        int index = 0;
        while (index < tagged_params_length) 
        {
            uint8_t id = tagged_params[index];
            uint8_t len = tagged_params[index + 1];
            const uint8_t *data = &tagged_params[index + 2];

            index += len + 2; /* Move to the next tag*/
        }

        /* Extracting the Capability Info directly for Privacy bit*/
        const uint16_t *capability_info = (const uint16_t *)(frame_body + 10); /* Offset 10 within the beacon frame body*/

       
        log_printf(logfile,"\n");
    }

    pthread_exit(NULL);
}


/*for imx board to to read the channel shifting as it not supported sudo */

#ifdef IMX8MP_BOARD_ENABLE_CHANNEL
int setChannel_imx8mp(const char *iface, int channel) {

    struct iwreq req;

    int sockfd;
 
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {

        perror("Socket");

        return -1;

    }
 
    memset(&req, 0, sizeof(struct iwreq));

    strncpy(req.ifr_name, iface, IFNAMSIZ);

    req.u.freq.e = 0;

    req.u.freq.m = channel;
 
    if (ioctl(sockfd, SIOCSIWFREQ, &req) == -1) {

        perror("Error setting channel");

        close(sockfd);

        return -1;

    }
 
    close(sockfd);

    return 0;

}
#endif




/*function for setting the channel like shifting from one channel to another (2.4 ghz to 5ghz ))*/

int setChannel(const char *interface, int channel) 
{
    /* Calculate the length of the command*/
  
    size_t command_length = snprintf(NULL, 0, "sudo iw dev %s set channel %d", interface, channel) + 1;

    /*Allocate memory for the command*/
   
    char *command = (char *)malloc(command_length * sizeof(char));
    if (command == NULL) 
    {
        perror("Memory allocation failed");
        return -1; /* Return error*/
    }

    /* Construct the command*/
    snprintf(command, command_length, "sudo iw dev %s set channel %d",interface,channel);

    /* Execute command*/
    int ret = system(command);
    log_printf(logfile, "%s \n command =====\t",command);
    if (ret != 0) 
    {
        fprintf(stderr, "Failed to set channel %d: %s\n", channel, strerror(errno));

        free(command); /*Free dynamically allocated memory*/
        return -1; /* Return error*/
    }
    /* Free dynamically allocated memory*/
    free(command);

    return 0; /* Success*/
}

/*call back function for the scan capture thread*/
void scan_packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) 
{
	pthread_mutex_lock(&mutex);
	while (isQueueFull()) 
	{
		pthread_cond_wait(&cond, &mutex);
	}
	enqueuePacket(pkthdr, packet);
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&mutex);
}

/*function for the capturing the packet */
void scan_capture_thread(void *arg) 
{
    pcap_t *handle = (pcap_t *)arg;
    struct pcap_pkthdr *header;
    const u_char *packet;
    int timeout_ms = 1000; /* Timeout in milliseconds*/
    int packet_count = 0;
    
    int channels[MAX_CHANNELS] = {1,2,3,4,5,6,7,8,9,10,11,36,40,44,48,149,153,157,161,165}; /* channel initilazation array for both 2.4ghz and 5ghz channel*/
   
    struct timeval start, current;
    for (int i = 0; i < MAX_CHANNELS; i++) 
    {
        if (setChannel(INTERFACE, channels[i]) != 0) 
        #ifdef INVOKE_SET_CHANNEL_FOR_IMX8MP
         if (setChannel_imx8mp(INTERFACE, channels[i]) != 0) 
         #endif
        {
            fprintf(stderr, "Failed to set channel %d\n", channels[i]);
            continue;
        }
	/*sleep interval after channel shifting */
	sleep(CHANNEL_HOP_INTERVAL);
	log_printf(logfile,"Channel %d: Capturing beacons...\n", channels[i]);


        gettimeofday(&start, NULL);

        do 
        {
            if (pcap_next_ex(handle, &header, &packet) == 1) 
            {
                scan_packet_handler(NULL, header, packet); /* Process the captured packet */
            }
            gettimeofday(&current, NULL);
           
        } while ((current.tv_sec - start.tv_sec) < DWELL_TIME);
    }
	log_printf(logfile,"Capture complete.\n");
    pthread_exit(NULL);
}

/*implementation of scan threads*/
u_int8_t scan_thread_implement(char *filter, char *interface, pcap_t *handle,struct fptr *gfptr) 
{
    struct bpf_program fp;

	int channel;
	
    /*Further processing based on options*/
    initPacketQueue();

  
    log_printf(logfile,"Interface: %s, Filter: %s\n", interface, filter);
  
    log_printf(logfile,"Capturing from Interface: %s\n", interface);
    pthread_t capture_thread, parse_thread;
    if (pthread_create(&capture_thread, NULL, (void* (*)(void*))gfptr->bfill_fptr, (void *)handle) != 0 ||
        pthread_create(&parse_thread, NULL, (void* (*)(void*))gfptr->bparse_fptr, (void *)handle) != 0) 
        {
        fprintf(stderr, "Error creating packet capture or parse thread\n");
        pcap_freecode(&fp); /* Free the compiled filter*/
        pcap_close(handle); /* Close pcap handle*/
        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&cond);
        return EXIT_FAILURE;
    }
    sleep(CHANNEL_HOP_INTERVAL);
    pthread_join(capture_thread, NULL);
    pthread_join(parse_thread, NULL);
    /******* Cleanup**********/
    pcap_freecode(&fp); /* Free the compiled filter*/
    pcap_close(handle); /* Close pcap handle*/
    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&cond);
    return EXIT_SUCCESS;
}

/*reading the filter experssion from the input provided by the user using command line argument */

char* filter_extraction(int argc, char* argv[])
{

	if(argc < 3)
	{
		fprintf(stderr, "Usage: %s <interface> <subtype>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	char *subtype_str = argv[3];
	                
   	 char *frame_type=NULL;
	
	struct{
	
		char *name;
		int value;
		
		}subtype_mgmt[]={
	
		{"assoc-req", 0}, {"assoc-resp", 1}, {"reassoc-req", 2}, {"reassoc-resp", 3},
        	{"probe-req", 4}, {"probe-resp", 5}, {"beacon", 8}, {"atim", 9},
      	        {"disassoc", 10}, {"auth", 11}, {"deauth", 12}, {"action", 13},
        	{NULL, -1}
		};
            
	
	struct{
	
		char *name;
		int value;
		
		}subtype_ctrl[]={
	
			{"block-ack-req", 8}, {"block-ack", 9}, {"ps-poll", 10}, {"rts", 11},
			{"cts", 12}, {"ack", 13}, {"cf-end", 14}, {"cf-end-ack", 15},{NULL, -1}
          
              };


	struct{
	
		char *name;
		int value;
		
		}subtype_data[]={
			
			{"data", 0}, {"data-cf-ack", 1}, {"data-cf-poll", 2}, {"data-cf-ack-poll", 3},
			{"null", 4}, {"cf-ack", 5}, {"cf-poll", 6}, {"cf-ack-poll", 7}, {"qos-data", 8},
			{"qos-data-cf-ack", 9}, {"qos-data-cf-poll", 10}, {"qos-data-cf-ack-poll", 11},
			{"qos-null", 12}, { "qos-cf-poll", 14}, {"qos-cf-ack-poll", 15}, {NULL, -1}
       
               };
    




	 if((strcmp(argv[3], "mgt") == 0) || (strcmp(argv[3], "ctl") == 0)||(strcmp(argv[3], "dataa")==0))
	{
		
		if((strcmp(argv[3], "dataa") == 0)) /*To capture all data frames (we are checking with "dataa" for all data frames because we have data as type and subtype, 
						     So to differentiate "dataa" for type and "data" for subtype.*/
			frame_type = "data";
		else
		 	frame_type = argv[3];
		 subtype_str = NULL;
	}

	char *frame[] = {"mgt","ctl","data"};

	int subtype_value = SUBTYPE_COMP_VAL;

	log_printf(logfile,"string:%s\n",subtype_str);
	
		
	if(subtype_str)
	{
	
		for (int i = INTIALIZATION_VAL; subtype_mgmt[i].name != NULL; i++)
		 {
            		if (strcmp(subtype_str, subtype_mgmt[i].name) == 0)
             		{
                		subtype_value = subtype_mgmt[i].value;
                		
                		frame_type = "mgt" ;
                		break;
           		}
        	}
        	
        	
        	if(subtype_value == SUBTYPE_COMP_VAL)
        	{
		
			for (int i = INTIALIZATION_VAL; subtype_ctrl[i].name != NULL; i++)
			 {
		    		if (strcmp(subtype_str, subtype_ctrl[i].name) == 0)
		     		{
		        		subtype_value = subtype_ctrl[i].value;
		        		
		        		frame_type = "ctl" ;
		        		break;
		   		}
			}
        	}
        	
        	
        	if(subtype_value == SUBTYPE_COMP_VAL)
        	{
			for (int i = INTIALIZATION_VAL; subtype_data[i].name != NULL; i++)
			 {
		    		if (strcmp(subtype_str, subtype_data[i].name) == 0)
		     		{
		        		subtype_value = subtype_data[i].value;
		        		
		        		frame_type = "data" ;
		        		break;
		   		}
			}
        	}
        	
        	
        	if (((subtype_value == SUBTYPE_COMP_VAL)&&(frame_type==NULL))&&(strcmp(argv[3], " ")!=0)) {
        	
          	  fprintf(stderr, "Unknown frame subtype: %s\n", subtype_str);
            	  return "Unknown Type and subtype";
        	} 
        }


	
	log_printf(logfile,"%s-(type)-%s(subtype)\n",frame_type,subtype_str);
        	
	


	char *filter_exp = (char *)malloc(50 * sizeof(char));   /*allocating memory dynamically because filter_exp need to return to the main function 
							           ssif statically allocated memory then it works till this function only*/
   	 if (filter_exp == NULL) {
        	fprintf(stderr, "Memory allocation failed\n");
        	exit(EXIT_FAILURE);
   	 }
	
	 size_t buffer_size[50]; //maintaing buffer to snprintf function to copy the string to filter_exp, sizeof(filter_exp) is 8

        if(frame_type)
        {
	    	if(subtype_str)
	    	{
	    		snprintf(filter_exp, sizeof(buffer_size), " wlan type %s subtype %s", frame_type, subtype_str);
	    	}
	    	else
	    	{
	    		 snprintf(filter_exp, sizeof(buffer_size), "wlan type %s", frame_type);
	    	}
	  } 
        else
	{
	    	     snprintf(filter_exp, sizeof(buffer_size), " ");
	   	
        }  
	
	return filter_exp;
	
}




