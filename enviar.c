#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#define ltrama 100


pcap_t* pcap;
char dir;
char packet[100];
FILE* f;
FILE*copia;

void procesar(int comando,char*datos,int len){
	//printf("comando: %d, longitud: %d, datos: %s\n",comando,len,datos);
	if(comando == 1){
		char nfile[8+len];
		sprintf(nfile,"%s","copia/");
		strcat(nfile,datos);
		printf("recibiendo archivo %s\n",datos);
		if(!(copia = fopen(nfile,"wb"))){
			printf("Error al crear archivo %s\n",nfile);
			exit(0);
		}
	}
	else if(comando == 2){
		int w = fwrite(&datos[0],1,len,copia);
	}
	else if(comando == 3){
		fclose(copia);
		printf("archivo recibido\n");
		exit(0);
	}
}

void ptrama(char*trama,int len){
	int i;
    for(i=0;i<20;i++)
	{
		printf("%02X ",packet[i]);
		if(!((i+1)%16))
			printf("\n");
	}
}

void enviar(char dest,char comando, char* datos,char len){
	char packet[15+len];
	int i;
		
	for(i = 0;i<6;i++){
		packet[i]=0xff;
	}
	for(i = 6;i<12;i++){
		packet[i]=0x0a;
	}
	
    packet[12] = dest;
    packet[13] = comando;
    packet[14] = len;
    
    memcpy(&packet[15],datos,len);
    
    
    if (pcap_inject(pcap,&packet,sizeof(packet))==-1) {
		pcap_perror(pcap,0);
		pcap_close(pcap);
		exit(1);
	}
    
}

void callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
	int i;
	
	char dest = packet[12];
	for(i = 0;i<6;i++){
		if(packet[i]!=0xff){
			return;
		}
	}
	for(i = 6;i<12;i++){
		if(packet[i]!=0x0a){
			return;
		}
	}
	if(dest != dir && dest!=0xff){
		return;
	}
	
	char comando = packet[13];
	int len = packet[14];
	char datos[len];
	memcpy(datos,&packet[15],len);
	procesar(comando,&datos[0],len);
	
}

int main(int argc,char* argv[]){
	char ok = 1;
	char dir_dest = 0;
	char* file;
	if(argc < 3){
		ok = 0;
	}
	else if(strcmp(argv[2],"s")!=0&&strcmp(argv[2],"r")!=0){
		ok = 0;
	}
	else{
		dir = atoi(argv[1]);
		if(strcmp(argv[2],"s")==0){
			if (argc<5){
				ok = 0;
			}
			else{
				dir_dest = atoi(argv[3]);
				file = argv[4];
			}
		}
	}
	if(!ok){
		printf("USO:\n\nenviar dir s dir_destino archvo\n\nenviar dir r\n\n");
		exit(0);
	}
	
	
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_errbuf[0]='\0';
    char *dev = pcap_lookupdev(pcap_errbuf);
    if(dev == NULL)
    { printf("%s\n",pcap_errbuf); exit(1); }
    pcap = pcap_open_live(dev,BUFSIZ,1,-1,pcap_errbuf);
    printf("Utilizando interfaz %s\n",dev);
	if (pcap_errbuf[0]!='\0') {
		fprintf(stderr,"%s",pcap_errbuf);
	}
	if (!pcap) {
		exit(1);
	}

	if(dir_dest){
		printf("Enviando archivo...\n");
		char pos = 0,i;
    	if(!(f = fopen(file,"r"))){
    		printf("No se pudo abrir archivo %s\n",file);
    		exit(0);
    	}
		for(i = 0;i<strlen(file);i++){
			if(file[i]=='/'){
				pos = i+1;
			}
		}
    	enviar(dir_dest,1,file+pos,strlen(file)-pos+1);
    	char c[10];
    	int e=0,leidos;
    	float env;
    	while(leidos=fread(&c,1,ltrama,f)){
    		enviar(dir_dest,2,&c[0],leidos);
    		//e+=leidos;
    		//env = (float)e/1024;
    		//printf("Enviados %f kB\n",env);
    	}
    	enviar(dir_dest,3,NULL,0);
    	printf("Archivo enviado\n");
    }
    else{
    	pcap_loop(pcap,0,callback,NULL);
	}
    return 0;
}
