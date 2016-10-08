/*
*Programa que utiliza el protocolo de comunicacion ARP
*Creado por Martinez Moran Diego de Jesus
*IPN-ESCOM 2CM9
*/


#include <sys/socket.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>

unsigned char ethertype[2] = {0x08, 0x06};
unsigned char tramaEnv[1514];
unsigned char ARPenvia[2]={0x00,0x01};
unsigned char TipoProt[2]={0x08,0x00};
unsigned char MACbroadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

unsigned char MACOrigen[6];
unsigned char IPOrigen[4];
unsigned char IPDestino[4];

typedef struct _arp_hdr arp_hdr;

struct _arp_hdr {
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint8_t opcode;
 };

void ingresaIP(){

	struct sockaddr_in adr_inet;
    unsigned char ip[15];
	printf("\nIngrese la IP a la que desea jackiar con ARP:");
    scanf("%s",ip);
    fflush(stdin);
    memset(&adr_inet,0,sizeof adr_inet);
	inet_aton(ip,&adr_inet.sin_addr);
	memcpy(IPDestino,&adr_inet.sin_addr,4);

}

void imprimeTrama(unsigned char *paq, int len){
	int i;
	for(i=0;i<len;i++){
		if(i%16==0){
			printf("\n");
		}
		printf("%.2x ",paq[i]);		
	}
	printf("\n");
}

void estructuraTramaEnvio(unsigned char *trama){

	struct ifreq nic;
	struct _arp_hdr arphdr;
	
	// ethernet
	arphdr.htype = htons (1);

	// IP
	arphdr.ptype = htons (ETH_P_IP);
	// MAC address
	arphdr.hlen = 6;

	// IPv4
	arphdr.plen = 4;

	// ARP
	arphdr.opcode = htons (ARPOP_REQUEST);

	ingresaIP();

	imprimeTrama(IPOrigen, 4);

	memcpy(trama+0,MACbroadcast,6);
	memcpy(trama+6,MACOrigen,6);
	memcpy(trama+12,ethertype,2);
	memcpy(trama+14,&arphdr.htype,2);
	memcpy(trama+16,TipoProt,2);
	memcpy(trama+18,&arphdr.hlen,1);//trama[18]=6
	memcpy(trama+19,&arphdr.plen,1);
	memcpy(trama+20,ARPenvia,2);
	memcpy(trama+22,MACOrigen,6);
	memcpy(trama+28,IPOrigen,4);
	memcpy(trama+38,IPDestino,4);

}

int validaIP(unsigned char * a, unsigned char * b){
	int i,aux=0,aux2=0;
	for (i = 0; i < 4; i++){
		if (a[i] == b[i]){
			aux2++;
		}
	}
	if (aux2==4){
		aux=1;
	}else{
		aux=0;
	}
	return aux;
}

int validaEthertype(unsigned char * a, unsigned char * b){
	
	int i,aux=0,aux2=0;

	for (i = 0; i < 2; i++){
		if (a[i] == b[i]){
			aux2++;
		}
	}
	if (aux2==2){
		aux=1;
	}else{
		aux=0;
	}
	return aux;
}

int verificaTramaARP(unsigned char *trama,int tam){
	int i,aux=0;
	unsigned char ethertypeTrama[2],IPorigenTrama[4],IPdestinoTrama[4];
	memcpy(ethertypeTrama,trama+12,2);
	memcpy(IPorigenTrama,trama+28,4);
	memcpy(IPdestinoTrama,trama+38,4);
	
	if (validaEthertype(ethertypeTrama,ethertype) && validaIP(IPdestinoTrama,IPOrigen) && validaIP(IPDestino,IPorigenTrama)){
		aux=1;
	}
	return aux;
}

void enviarTrama(int ds, int index, unsigned char *trama){
	int tam;
	struct sockaddr_ll interfaz;
	memset(&interfaz, 0x00, sizeof(interfaz));
	interfaz.sll_family = AF_PACKET;
	interfaz.sll_protocol = htons(ETH_P_ALL);
	interfaz.sll_ifindex = index;
	tam = sendto(ds, trama, 42, 0, (struct sockaddr *)&interfaz, sizeof(interfaz));
	if(tam == -1){
		perror("Error al enviar\n");
		exit(0);
	}else{
		printf("Exito al enviar\n");
		imprimeTrama(trama,tam);
		printf("\n");
	}
}
void recibeTrama(int ds, unsigned char *trama){
	int tam;
	while(1){
		tam=recvfrom(ds,trama,1514,0,NULL,0);
		if(tam==-1){
			perror("\nError al recibir");
			exit(0);
		}else{
			if (!memcmp(trama,MACOrigen,6) && verificaTramaARP(trama,tam)){
				printf("\nRecibe la trama respuesta de ARP\n");
				imprimeTrama(trama,tam);
				break;
			}
		}
	}
}

int obtenDatos( int ds ){
	
	struct ifreq nic;
	int index;
	printf("\n Inserta el nombre: ");
	gets(nic.ifr_name);

	if(ioctl(ds, SIOCGIFINDEX, &nic) == -1){
		perror("\nError al obtener el indice");
		exit(0);
	}else{
		index = nic.ifr_ifindex;
	}

	//obtener MAC
	if(ioctl(ds, SIOCGIFHWADDR, &nic) == -1){
		perror("\nError al obtener la MAC");
		exit(0);
	}else{
		memcpy(MACOrigen, nic.ifr_hwaddr.sa_data, 6);
		/*for(int i = 0; i < 6; i++){
			printf("%.2x:", MACOrigen[i]);
		}*/		
	}

	//obtener IP
	nic.ifr_addr.sa_family = AF_INET;
	if(ioctl(ds, SIOCGIFADDR, &nic) == -1){
		perror("\nError al obtener la IP");
		exit(0);
	}else{
		memcpy(IPOrigen, nic.ifr_addr.sa_data+2, 4);
		/*printf("\n");
		for(int i = 0; i < 4; i++){
			printf("%i.", IPOrigen[i]);
		}	*/
	}
	
	return index;	
}

int main(){
		
	int packet_socket, indice;
	packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(packet_socket == -1){
		perror("\nNo se pudo abrir el socket\n");
		exit(0);	
	}else{
		printf("\nConcectado al socket chido\n");
		indice = obtenDatos(packet_socket);
		printf("\nEste es el indice: %d\n", indice);
		estructuraTramaEnvio(tramaEnv);
		enviarTrama(packet_socket, indice, tramaEnv);
		recibeTrama(packet_socket, tramaEnv);
	}
	close(packet_socket);
}