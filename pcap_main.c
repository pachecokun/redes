/**********************************************************************
* file:   pcap_main.c
* date:   Tue Jun 19 20:07:49 PDT 2001  
* Author: Martin Casado
* Last Modified:2001-Jun-23 12:55:45 PM
*
* Description: 
* main program to test different call back functions
* to pcap_loop();
*
* Compile with:
* gcc -Wall -pedantic pcap_main.c -lpcap (-o foo_err_something) 
*
* Usage:
* a.out (# of packets) "filter string"
*
**********************************************************************/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <net/ethernet.h>
#include <netinet/ether.h> 

/*
 * workhorse function
 */ 

void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
	int i;
	for(i = 0;i<12;i++){
		if(packet[i]!=0x0a){
			return;
		}
	}
	
	for(i=0;i<pkthdr->len;i++)
	{
		printf("%02X ",packet[i]);
		if(!((i+1)%16))
			printf("\n");
	}
	char comando = packet[12];
	printf("comando: %02X",comando);
	printf("\n");
}


int main(int argc,char **argv)
{ 
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    u_char* args = NULL;

    /* grab a device to peak into... */
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    { printf("%s\n",errbuf); exit(1); }


    /* open device for reading. NOTE: defaulting to
     * promiscuous mode*/
    descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }


    /* ... and loop */ 
    pcap_loop(descr,0,my_callback,args);

    fprintf(stdout,"\nfinished\n");
    return 0;
}
