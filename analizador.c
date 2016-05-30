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

const char *bb(unsigned char x)
{
    char* b=(char*)malloc(9);
    b[0] = 0;

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
	
	
	printf("%d\t",len);
	
	
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
	char* b0 = bb(c0);
	char* b1 = bb(c1);
	
	char nr;
	char ns;
	char pf;
	char clave;
	char tipo []="";
	char tipo_t;
	
	
	if(len == 3){
		tipo_t = 'U';
		pf = c0 & (0b00010000>>4)&1;
		clave = ((c0 & 11100000)>>3)|((c0&0b1100)>>2);
		switch(clave){
			case 0b10000:
				strcat(tipo,"SNRM");
				break;
			case 0b11011:
				strcat(tipo,"SNRME");
				break;
			case 0b00111:
				strcat(tipo,"SABM/DM");
				break;
			case 0b01111:
				strcat(tipo,"SABME");
				break;
			case 0b00000:
				strcat(tipo,"UI/UI");
				break;
			case 0b01100:
				strcat(tipo,"UA");
				break;
			case 0b01000:
				strcat(tipo,"DISC/RD");
				break;
			case 0b00001:
				strcat(tipo,"SIM/RIM");
				break;
			case 0b00100:
				strcat(tipo,"UP");
				break;
			case 0b10011:
				strcat(tipo,"RSET");
				break;
			case 0b10111:
				strcat(tipo,"XID/XID");
				break;
			case 0b10001:
				strcat(tipo,"/FRMR");
				break;
		}
		printf("U\t%d\t-\t-\t%s\t%s",pf,tipo,b0);
	}
	else if(c0&1){
		tipo_t = 'S';
		pf = invn(c1)&1;
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
		printf("S\t%d\t%d\t-\t%s\t%s %s",pf,nr,tipo,b0,b1);
	}
	else{
		tipo_t = 'I';
		pf = invn(c1)&1;
		nr = invn(c1>>1);
		ns = c0>>1;
		printf("I\t%d\t%d\t%d\t-\t%s %s",pf,nr,ns,b0,b1);
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
    
    char header []= "DIR D\t\t\tDIR O\t\t\tLEN\t¿LLC?\tC/R\tSAP O\tSAP D\tTipo\tP/F\tNR\tNS\tCMD/RSP\n";
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
		//printf("Longitud: %d\n",n);
		unsigned char trama[n];
		char car[3];
		car[2] = 0;
		int i;
		for(i = 0;i<n;i++){
			memcpy(car,argv[2]+3*i,2);
			trama[i] = strtol(car,NULL,16);
		}		
		printf("%s",header);
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

		printf("%s",header);

		/* ... and loop */ 
		pcap_loop(descr,0,my_callback,args);

		fprintf(stdout,"\nfinished\n");
	}

    
    return 0;
}
