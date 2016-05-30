#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#define ltrama 100
#define ventana 3
#define maxn 4

pcap_t* pcap;
char dir;
char packet[100];
FILE* f;
FILE*copia;
char nr,ns;
char ack;

void procesar(char orig,int comando,char*datos,int len){
	//printf("comando: %d, longitud: %d, datos: %s\n",comando,len,datos);
	if(comando == 1){
		char nfile[8+len];
		sprintf(nfile,"%s","copia/");
		strcat(nfile,datos);
		printf("recibiendo archivo %s\n",datos);
		umask(0);
		if(!(copia = fopen(nfile,"wb"))){
			printf("Error al crear archivo %s\n",nfile);
			exit(0);
		}
	}
	else if(comando == 2){
		int w = fwrite(&datos[0],1,len,copia);
		enviar(orig,dir,4,NULL,0);
	}
	else if(comando == 3){
		fclose(copia);
		printf("archivo recibido \n");
		exit(0);
	}
	else if(comando == 4){
		ack = 1;
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

void enviar(char dest,char orig,char comando, char* datos,char len){
	char packet[16+len];
	int i;
		
	for(i = 0;i<12;i++){
		packet[i]=0x0a;
	}
	
    packet[12] = dest;
    packet[13] = orig;
    packet[14] = comando;
    packet[15] = len;
    
    memcpy(&packet[16],datos,len);
    
    
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
	char orig = packet[13];
	for(i = 0;i<12;i++){
		if(packet[i]!=0x0a){
			return;
		}
	}
	if(dest != dir && dest!=0xff){
		return;
	}
	
	char comando = packet[14];
	int len = packet[15];
	char datos[len];
	memcpy(datos,&packet[16],len);
	procesar(orig,comando,&datos[0],len);
	
}

int main(int argc,char* argv[]){
	char ok = 1;
	char dir_dest = 0;
	char* file;
	if(argc < 3){
		ok = 0;
	}
	else if(strcmp(argv[3],"s")!=0&&strcmp(argv[3],"r")!=0){
		ok = 0;
	}
	else{
		dir = atoi(argv[2]);
		if(strcmp(argv[3],"s")==0){
			if (argc<5){
				ok = 0;
			}
			else{
				dir_dest = atoi(argv[4]);
				file = argv[5];
			}
		}
	}
	if(!ok){
		printf("USO:\n\nenviar interfaz dir s dir_destino archvo\n\nenviar intefaz dir r\n\n");
		exit(0);
	}
	
	
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_errbuf[0]='\0';
    char *dev = pcap_lookupdev(pcap_errbuf);
    if(dev == NULL)
    { printf("%s\n",pcap_errbuf); exit(1); }
    //sprintf(dev,"%s","lo");
    int to = -1;
    if(dir_dest){
    	to = 1000;
    }
    pcap = pcap_open_live(dev,BUFSIZ,1,to,pcap_errbuf);
    sprintf(dev,"%s",argv[1]);
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
    	enviar(dir_dest,dir,1,file+pos,strlen(file)-pos+1);
    	char c[10];
    	int e=0,leidos;
    	float env;
    	int cont = 0;
    	while(leidos=fread(&c,1,ltrama,f)){
    		ack = 0;
    		int in = 0;
    		while(!ack){
    			enviar(dir_dest,dir,2,&c[0],leidos);
    			pcap_loop(pcap,1,callback,NULL);
    			in++;
    		}
    		//printf("%d intentos \n",in);
    		e+=leidos;
    		env = (float)e/1024;
    		printf("Enviados %f kB\n",env);
    	}
    	enviar(dir_dest,dir,3,NULL,0);
    	printf("Archivo enviado\n");
    }
    else{
    	pcap_loop(pcap,0,callback,NULL);
	}
    return 0;
}
