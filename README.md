------------------------------------MtlNetLyzer_v1.1_b-----------------------------------------------
MtlNetLyzer_v1.1_b
May 17 10:53PM
-added new option 'l'
    -prints unique APs with BSSID and MAC address
    -all the APs are sorted according to their RSSI
    -added supported data rates for each unique APs
    -added bandwidth info 
    -verify the ssid is hidden or not
    -Verify which security the ssid have.
    -added channel info for the ssid.
    -operated in 2.4ghz and 5ghz channel.


------------------------------------------------------------------------------------------------------

--------------------------------MtlNetLyzer_june_21------------------------------------------------------------

IN OPTION -l
	-created static structure 
	-cleared pervious prints on terminal before printing new prints
	
/******************************************************************************/

Added new .c file i.e logger.c and .h file i.e logger.h

Description:-- this file is used to design one customize printf . 
which will print the output on terminal as well as in the text file.

/*******************************************************************************/

Make file :-

made adjustments, such as if a user does the "make clean" command. It used to simply clean object files. 
however it now deletes the log files as well. 

----------------------------------------------------------------------------------------------------------------

--------------------------------MtlNetLyzer_june_27------------------------------------------------------------

IN OPTION -s
	-added ioctl functionality for set channel for the compactablity to imx8mp board to run this application
	
---------------------------------------------------------------------------------------------------------------

