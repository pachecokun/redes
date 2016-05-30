#define maxn 7

int nr = 0,ns = 0;

char * msg [maxn];

int procesarEnlace(char*cadena,len,char*res){
	for(i = 0;i<12;i++){
		if(packet[i]!=0x0a){
			return 0;
		}
	}
	char tipo = packet[13];
	if(tipo == 1){
		return 1;
	}
}
