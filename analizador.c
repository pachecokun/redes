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

const char *bb(char x)
{
    static char b[9];
    b[0] = '\0';

    int z;
    for (z = 128; z > 0; z >>= 1)
    {
        strcat(b, ((x & z) == z) ? "1" : "0");
    }

    return b;
}

unsigned char invn(unsigned char n){
	int ni = 0;
	int i;
	for(i = 0;i<7;i++){
		ni |= ((n>>i)&1)<<(6-i);
	}
	return ni&0b01111111;
}

int llc(unsigned char trama[], int longitud, char resultado[], int longresultado){
	int i;
	unsigned short len = (trama[12]<<8)|trama[13];
	
	if(len>1500){
		return;
	}
	
	for(i = 0;i<6;i++){
		printf("%02x ",trama[i]);
	}
	printf("\t");
	for(i = 6;i<12;i++){
		printf("%02x ",trama[i]&255);
	}
	printf("\t");
	
	
	if(len<1500){
		printf("LLC\t");
	}
	else{
		printf("ETHER\t");
		printf("\n");
		return;
	}
	printf("c\t");
	printf("%02x\t%02x\t",trama[14],trama[15]);
	
	
	unsigned char c0 = trama[16];
	unsigned char c1 = trama[17];
	char* b0 = bb(0);
	char* b1 = bb(1);
	
	char nr;
	char ns;
	char pf;
	char clave;
	char tipo []="";
	char tipo_t;
	
	
	if(len == 3){
		tipo_t = 'U';
		pf = c0 & 0b00010000>>4;
		clave = ((c0 & 11100000)>>3)|((c0&0b1100)>>2);
		switch(clave){
			case 0b10000:
				strcat(tipo,"SNRM");
				break;
			case 0b11011:
				strcat(tipo,"SNRME");
				break;
			case 0b00111:
				strcat(tipo,"SABM");
				break;
			case 0b01111:
				strcat(tipo,"SABME");
				break;
			case 0b00000:
				strcat(tipo,"UI");
				break;
			case 0b01100:
				strcat(tipo,"UA");
				break;
			case 0b01000:
				strcat(tipo,"DISC");
				break;
			case 0b00001:
				strcat(tipo,"SIM");
				break;
			case 0b00100:
				strcat(tipo,"UP");
				break;
			case 0b10011:
				strcat(tipo,"RSET");
				break;
			case 0b10111:
				strcat(tipo,"XID");
				break;
			case 0b10001:
				strcat(tipo,"FRMR");
				break;
		}
		printf("U\t%d\t-\t-\t%s",pf,tipo);
	}
	else if(c0&1){
		tipo_t = 'S';
		pf = c1&1;
		nr = invn(c1>>1); 
		clave = (c0 & 0b00001100)>>2;
		switch(clave){
			case 0b00:
				strcat(tipo,"RR");
				break;
			case 0b01:
				strcat(tipo,"RNR");
				break;
			case 0b10:
				strcat(tipo,"REJ");
				break;
			case 0b11:
				strcat(tipo,"SREJ");
				break;
		} 
		printf("S\t%d\t%d\t-\t%s",pf,nr,tipo);
	}
	else{
		tipo_t = 'I';
		pf = invn(c1&1);
		nr = invn(c1>>1);
		ns = c0>>1;
		printf("I\t%d\t%d\t%d\t-",pf,nr,ns);
	}
	
	
	
	
	
	printf("\n");
}

void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
	char res[100];
	int lon = 0;
	llc(packet,pkthdr->len,res,lon);
}

int main(int argc,char **argv)
{ 
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    u_char* args = NULL;

	if(argc < 2){
		printf("parametros: \n\nanalizador intefaz\nanalizador -t trama\n\n");
		exit(0);
	}
	if(!strcmp(argv[1],"-t")){
		if(argc < 3){
			printf("parametros: \n\nanalizador intefaz\nanalizador -t trama\n\n");
			exit(0);
		}
		int n = strlen(argv[2])/3+1;
		printf("Longitud: %d\n",n);
		unsigned char trama[n];
		char car[3];
		car[2] = 0;
		int i;
		for(i = 0;i<n;i++){
			memcpy(car,argv[2]+3*i,2);
			trama[i] = strtol(car,NULL,16);
		}		
		printf("DIR D\t\t\tDIR O\t\t\t¿LLC?\tC/R\tSAP O\tSAP D\tTipo\tP/F\tNR\tNS\tCMD/RSP\n");
		char res[100];
		int lon = 0;
		llc(trama,n,res,lon);
	}
	else{
		/* grab a device to peak into... */
		/*dev = pcap_lookupdev(errbuf);
		if(dev == NULL)
		{ printf("%s\n",errbuf); exit(1); }*/


		/* open device for reading. NOTE: defaulting to
		 * promiscuous mode*/
		descr = pcap_open_live(argv[1],BUFSIZ,1,-1,errbuf);
		if(descr == NULL)
		{ printf("pcap_open_live(): %s\n",errbuf); exit(1); }

		printf("DIR D\t\t\tDIR O\t\t\t¿LLC?\tC/R\tSAP O\tSAP D\tTipo\tP/F\tNR\tNS\tCMD/RSP\n");

		/* ... and loop */ 
		pcap_loop(descr,0,my_callback,args);

		fprintf(stdout,"\nfinished\n");
	}

    
    return 0;
}
