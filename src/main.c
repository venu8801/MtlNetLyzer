#include "MtlPktLyzer.h"
#include "func_dec.h"
#include <beacon_parser.h>
#include "logger.h"
#include <stdio.h>
#include <util.h>
#include "init.h"

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

 void *(*bfill_d_fptr)(void *);
 void *(*bparse_d_fptr)(void *);

const char *config_filename = "./config.config";  // Global config filename

struct fptr gfptr;
void UsageHandler(char *str) 
{
	log_printf(logfile,"Usage: %s [interface] [-h] [-c SSID PWD ] [-p filter] [-s] [other_options]\n", str);
	/* Add help message explanations for each option here */
	log_printf(logfile,"interface: Network interface to monitor.\n");
	log_printf(logfile,"-h: Display this help message.\n");
	log_printf(logfile,"-c: connect to specific AP/ Router.\n");
	log_printf(logfile,"-p: capture packets and Specify a filter string.\n");
	log_printf(logfile,"-s: Scan for AP's/Wifi routers around you.\n");
	log_printf(logfile,"-l: Scan Nearby APs with ssi and supported rates\n");
	
	/***********************Add more**************************/
}

void exit_handler()
{
	pid_t iPid = getpid(); /* Process gets its id.*/
	close_log_file();
	kill(iPid, SIGINT); 
	exit(0);

}





int main(int argc, char *argv[]) {
    /* Initialization */
    int opt;
    char *interface = NULL;
    char *filter = " ";
	char filter_exp1[1000];
	struct bpf_program fp;  /* Compiled filter */
	open_log_file();
	u_int8_t thread_creation;
 	struct fptr *gfptr = malloc(sizeof(gfptr)); /*allocating dyanamic memory for function pointer */
 	read_config(config_filename);
	signal(SIGINT,exit_handler);

    if (pthread_mutex_init(&mutex, NULL) != 0 || pthread_cond_init(&cond, NULL) != 0)
     {
        log_printf(logfile,"Mutex or condition variable initialization failed\n");
        return EXIT_FAILURE;
    }

    /* Parse command-line options */
    if (argc < 2 || argc > 4) 
    {
        UsageHandler(argv[0]);
        return EXIT_SUCCESS;
    }

    /* Check if required arguments are provided */
	log_printf(logfile,"glob");
	
    if (optind < argc) 
    {
        interface = argv[optind++];
    } else 
    {  
	  log_printf(logfile,"Error: Missing interface");
	  log_printf(logfile,"Usage: %s <interface> -p <filter>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

	
    /* Open Wi-Fi device for packet capture */
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_t *handle = pcap_open_live(interface, BUFFSIZ, PROMISCUOUS_VAL, PACKET_BUFF, errbuf);/* BUFSIZ=8024 ,PROMISCUOUS_VAL=1( Promiscuous mode allowing all the traffic not the sepicified frames) {100=packet buffer timeout} */
    if (handle == NULL) 
    {
        log_printf(logfile,"Couldn't open device %s: %s\n", interface, errbuf);
        return EXIT_FAILURE;
    }

	while ((opt = getopt(argc, argv, "c:p:hs:w:l")) != -1) {
        switch (opt) {
		/*****************************************connecting opt****************************************/
		case 'c':
		
			/* Assign corresponding functions to function pointers */
		    gfptr->bfill_fptr = &connect_capture_thread;
			gfptr->bparse_fptr = &connect_parse_thread;
			char *filter = "";
			 /* Compile the packet filter */
			if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) 
			{
			log_printf(logfile,"Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
				return 1;
			}

			/*Set the filter */
			if (pcap_setfilter(handle, &fp) == -1) 
			{
			log_printf(logfile,"Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
				return 1;
			}
			thread_creation = connect_thread_implement(filter, interface, handle, gfptr);
			log_printf(logfile,"call connect thread implementation function");
			
			break;
		
		/**************************************packet capturing******************************************/
		case 'p':
		   
			/* Assign corresponding functions to function pointers */
			
		    gfptr->bfill_fptr = &packet_capture_thread;
			gfptr->bparse_fptr = &packet_parse_thread;
			filter = "";
			log_printf(logfile,"filter: %s\n",filter);
			 /* Compile the packet filter */
			if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) 
			{
			log_printf(logfile, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
				exit(EXIT_FAILURE);
			}

			if (pcap_setfilter(handle, &fp) == -1)
			 {
			log_printf(logfile,"Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
				exit(EXIT_FAILURE);
			}
			thread_creation = capture_thread_implement(filter, interface, handle, gfptr);
			break;
		
		/****************************************scanning************************************************/
		case 's':
			
			/* Assign corresponding functions to function pointers */
			gfptr->bfill_fptr = &scan_capture_thread;
			gfptr->bparse_fptr = &scan_parse_thread;
			char *filter_exp = filter_extraction(argc, argv);
			 /* Compile the packet filter */
			if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) 
			{
			log_printf(logfile,"Couldn't parse filter_exp %s: %s\n", filter_exp, pcap_geterr(handle));
				return 1;
			}

			/* Set the filter */
			if (pcap_setfilter(handle, &fp) == -1) 
			{
			log_printf(logfile,"Couldn't install filter_exp %s: %s\n", filter, pcap_geterr(handle));
				return 1;
			}
			
			thread_creation = scan_thread_implement(filter_exp, interface, handle, gfptr);
			break;
			
		/*****************************************handshake**************************************************/
		case 'w':
			
			strcpy(filter_exp1, "ether proto 0x888e");/*Filter expressi(filter_exp1, "ether proto 0x888e")on for EAPOL frames */
			 /* Compile the packet filter */
			if (pcap_compile(handle, &fp, filter_exp1, 0, PCAP_NETMASK_UNKNOWN) == -1) 
			{
			log_printf(logfile,"Couldn't parse filter %s: %s\n", filter_exp1, pcap_geterr(handle));
				return 1;
			}
			/*Set the filter */
			if (pcap_setfilter(handle, &fp) == -1) 
			{
			log_printf(logfile,"Couldn't install filter %s: %s\n", filter_exp1, pcap_geterr(handle));
				return 1;
			}
			handshake_implement(filter_exp1, interface, handle);
			break;
		
		/*********************************************beacon handler **********************************************/
		case 'l':
			/* capturing and parsing beacons */
			filter_exp = "type mgt and (subtype beacon)";
			struct beacon_fptr bfptr;
			bfptr.bfill_fptr = &beacon_capture_thread;
			bfptr.bparse_fptr = &beacon_parser_thread;
			 /* Compile the packet filter */
			if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) 
			{
			log_printf(logfile,"Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return 1;
			}


			/*Set the filter */
			if (pcap_setfilter(handle, &fp) == -1)
			 {
			log_printf(logfile,"Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return 1;
			}
			
			thread_creation = beacon_thread_implement(filter_exp, interface, handle, &bfptr);
			break;
		/******************************************help***************************************************************/
		case 'h':
			UsageHandler(argv[0]);
			return EXIT_SUCCESS;

		default:
			
			log_printf(logfile,"opt: %c", opt);
			
			log_printf(logfile,"calling default");
			
			UsageHandler(argv[0]);
			exit(EXIT_FAILURE);
		}	
	}
	exit_handler();

    return 0;

}
