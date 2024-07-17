#include <arpa/inet.h>
#include <time.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/if_link.h>
#include <errno.h>
#include <unistd.h> 
#include <sys/time.h>

#define SNAP_LEN 1518  // Max bytes per packet
#define SIZE_ETHERNET 14
#define WLAN_RADIO_HDR_LEN 8
//#define MAX_CHANNELS 11
//#define NUM_CHANNELS 20
#define CHANNEL_HOP_INTERVAL 5
//#define CHANNEL_HOP_INTERVAL 10 
#define INTERFACE "wlp0s20f3"
//#define PACKET_COUNT_PER_CHANNEL 5
#define DWELL_TIME 5
#define IMX8MP_BOARD_ENABLE_CHANNEL 0
#define INVOKE_SET_CHANNEL_FOR_IMX8MP 0
#define MAX_CHANNELS 20
int setChannel_imx8mp(const char *iface, int channel);
extern int channels_2ghz_5ghz[MAX_CHANNELS];
extern int num_channels_2ghz_5ghz;


extern void initPacketQueue();

extern int isQueueEmpty();
extern int isQueueFull();

extern void enqueuePacket(const struct pcap_pkthdr *header, const u_char *packet);

extern struct PacketNode dequeuePacket();


#define FREQ_2GHZ_LOWER_BAND 2401/* starting freq of 2.4ghz */
#define FREQ_2GHZ_UPPER_BAND 2473/* ending freq of 2.4ghz */
#define FREQ_5GHZ_LOWER_BAND 5000/* starting freq of 5ghz */
#define FREQ_5GHZ_UPPER_BAND 5873
#define CH_FREQ1_OFFSET 26/*starting address of the frequecy */
#define CH_FREQ2_OFFSET 18
#define CH_OFFSET 56 /*radiotap header offset vaule*/
#define MGMT_TYPE 0 /*management frame value */
#define CTRL_TYPE 1 /*control frame value */
#define DATA_TYPE 2 /*data frame vaule */
#define SUBTYPE_COMP_VAL -1 /*value for comparsion of the subtype value*/
#define TYPE_OFFSET_VAL 0x03 /*offset value of the type*/
#define SUBTYPE_OFFSET_VAL 0x0F /*offset value of subtype */
#define SHIFT_BIT_TYPE 2 /* offset valuee for the bit shifting for type */
#define SHIFT_BIT_SUBTYPE 4 /* offset valuee for the bit shifting for subtype */
#define ETHER_LEN 6 /*ethernet lenght */
#define OFFSET_VAL_TYPE 0x0C /*offset value for type*/
