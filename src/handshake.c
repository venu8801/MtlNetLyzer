#include "handshake.h"
#include "MtlPktLyzer.h"
#include "func_dec.h"
#include "logger.h"
/*call back function for the handshake capturing thread */
void handshake_packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
static int handshake_count = 0;
/* Assuming the packet starts with Ethernet header */
struct ether_header* eth_header = (struct ether_header*)packet;
    if (ntohs(eth_header->ether_type) != ETHER_ADDR_OFFSET_VAL) {
        /* Not an EAPOL packet, ignore */
        return;
    }
   EapolFrame* eapol = (EapolFrame*)(packet + sizeof(struct ether_header));
 
    /* Extract the MAC address of the AP from the packet */
 u_char* source_mac = eth_header->ether_shost;
    log_printf(logfile," authenticate with %02x:%02x:%02x:%02x:%02x:%02x\n",
           source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]);
           
    /* Print additional messages */
    log_printf(logfile," send auth to %02f ",(double)pkthdr->ts.tv_sec + (double)pkthdr->ts.tv_usec / 1000000);
   
    log_printf(logfile,"%02x:%02x:%02x:%02x:%02x:%02x\n", source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]);
    log_printf(logfile," authenticated %02f\n", (double)pkthdr->ts.tv_sec + (double)pkthdr->ts.tv_usec / 1000000);
    log_printf(logfile," associate with %2f ",(double)pkthdr->ts.tv_sec + (double)pkthdr->ts.tv_usec / 1000000);
    log_printf(logfile,"%02x:%02x:%02x:%02x:%02x:%02x\n",source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]);
    log_printf(logfile," RX AssocResp from %02f ",(double)pkthdr->ts.tv_sec + (double)pkthdr->ts.tv_usec / 1000000);
    log_printf(logfile,"%02x:%02x:%02x:%02x:%02x:%02x \n", source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]);
    
    
    /* Print information about the EAPOL frame */
    log_printf(logfile,"EAPOL Version: %d\n", eapol->version);
    log_printf(logfile,"EAPOL Type: %d\n", eapol->type);
    log_printf(logfile,"EAPOL Length: %d\n", ntohs(eapol->length));
    log_printf(logfile,"Descriptor Type: %d\n", eapol->descriptor_type);
    log_printf(logfile,"Key Info: 0x%x\n", ntohs(eapol->key_info));
    log_printf(logfile,"Key Length: %d\n", ntohs(eapol->key_length));
    log_printf(logfile,"Replay Counter: %" PRIu64 "\n", eapol->replay_counter);
    
    /*Print Key Nonce */
    log_printf(logfile,"Key Nonce: ");
    for (int i = 0; i < sizeof(eapol->key_nonce); ++i) {
        log_printf(logfile,"%02x ", eapol->key_nonce[i]);
    }
    log_printf(logfile,"\n");
    log_printf(logfile,"Key IV: %" PRIu64 "\n", eapol->key_iv);
    log_printf(logfile,"Key RSC: %" PRIu64 "\n", eapol->key_rsc);
    log_printf(logfile,"Key ID: %" PRIu64 "\n", eapol->key_id);
    // Print Key MIC
    log_printf(logfile,"Key MIC: ");
    for (int i = 0; i < sizeof(eapol->key_mic); ++i) {
        log_printf(logfile,"%02x ", eapol->key_mic[i]);
    }
    log_printf(logfile,"\n");

    log_printf(logfile,"Key Data Length: %d\n", ntohs(eapol->key_data_length));

   /* Print Key Data */
 
    log_printf(logfile,"\n\n");
    if (++handshake_count == MAX_HANDSHAKE_COUNT) {
            log_printf(logfile,"4-way handshake captured!\n");
            /* You can add code here to handle the captured handshake */
            exit(0); /* Exit the program after capturing the handshake */
        }
}

/* implementation of handshake function */
void handshake_implement(char *filter, char *interface, pcap_t *handle) {
	
	/*Start capturing packets and call packetHandler for each captured packet */
    pcap_loop(handle, -1, handshake_packetHandler, NULL);

    /*Close the capture handle when done */
    pcap_close(handle);
}
