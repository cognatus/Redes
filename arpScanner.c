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
#include <mysql/mysql.h>

unsigned char ethertype[2] = {0x08, 0x06};
unsigned char tramaEnv[1514];
unsigned char ARPenvia[2]={0x00,0x01};
unsigned char TipoProt[2]={0x08,0x00};
unsigned char MACbroadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};


int ini = 0;
int max = 0;
char queryChida[1024];

unsigned char MACOrigen[6];
unsigned char MACdestino[6];
unsigned char toip[15];
unsigned char IPOrigen[4];
unsigned char IPDestino[4]={0x00,0x00,0x00,0x00};
unsigned char MascaraRed[4];
unsigned char MascaraComparacion[4] = {0xff, 0xff, 0xff, 0x00};
unsigned char MascaraComparacion2[4] = {0xff, 0xff, 0x00, 0x00};
unsigned char MascaraComparacion3[4] = {0xff, 0x00, 0x00, 0x00};

typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint8_t opcode;
 };

void ingresaIP(unsigned char *IPvolatil){

	struct sockaddr_in adr_inet;
    memset(&adr_inet,0,sizeof adr_inet);
	inet_aton(IPvolatil,&adr_inet.sin_addr);
	memcpy(IPDestino,&adr_inet.sin_addr,4);

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

	//ingresaIP();

	memcpy(trama+0,MACbroadcast,6);
	memcpy(trama+6,MACOrigen,6);
	memcpy(trama+12,ethertype,2);
	memcpy(trama+14,&arphdr.htype,2);
	memcpy(trama+16,TipoProt,2);
	memcpy(trama+18,&arphdr.hlen,1);
	memcpy(trama+19,&arphdr.plen,1);
	memcpy(trama+20,ARPenvia,2);
	memcpy(trama+22,MACOrigen,6);
	memcpy(trama+28,(nic.ifr_addr.sa_data)+2,4);
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
		//imprimeTrama(trama,tam);
	}
}

void recibeTrama(int ds, unsigned char *trama, MYSQL *conn2){
	int tam;
	struct timeval start, end;
	long mtime=0, seconds, useconds;

	gettimeofday(&start, NULL);
	while(mtime < 100){
		tam=recvfrom(ds,trama,1514,0,NULL,0);
		if(tam==-1){
			perror("\nError al recibir");
			exit(0);
		}else{
			if (!memcmp(trama,MACOrigen,6) && verificaTramaARP(trama,tam)){
				printf("\nLa IP existe\n");
				memcpy(MACdestino,trama+6,6);
				sprintf(queryChida,"INSERT INTO datos (ip,mac) values('%d.%d.%d.%d','%.2x.%.2x.%.2x.%.2x.%.2x.%.2x')",IPDestino[0],IPDestino[1],IPDestino[2],IPDestino[3],MACdestino[0],MACdestino[1],MACdestino[2],MACdestino[3],MACdestino[4],MACdestino[5]);
			    if(mysql_query(conn2,queryChida))
					printf("ERROR AL INSERTAR\n");
				//imprimeTrama(trama,tam);
				break;
			}
		}

		gettimeofday(&end, NULL);

		seconds = end.tv_sec - start.tv_sec;
		useconds = end.tv_usec - start.tv_usec;

		mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;
	}
	printf("No lo encontro\n");
	printf("\n");
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

	//obtener Mascara
	if (ioctl(ds,SIOCGIFNETMASK,&nic) == -1){
		perror("\nError al obtener Mascara de red");
	}else{
		memcpy(MascaraRed,(nic.ifr_netmask.sa_data)+2,4);
		printf("\n");
		/*int i = 0;
		for(i = 0; i < 4; i++){
			printf(".%d",MascaraRed[i]);
		}*/
		if (!memcmp(MascaraRed,MascaraComparacion,4)){
			printf("La mascara es 255.255.255.0\n");
			//memcpy(IPDestino,0xC0,1);
			ini = 192;
			max = 223;
		}else if(!memcmp(MascaraRed,MascaraComparacion2,4)){
			printf("La mascara es 255.255.0.0\n");
			//memcpy(IPDestino,0x80,1);
			ini = 128;
			max = 191;
		}else if (!memcmp(MascaraRed,MascaraComparacion3,4)){
			printf("La mascara es 255.0.0.0\n");
			printf("Veeeerrrrrgaaa!!!! Esto va a tardar");
			ini = 0;
			max = 127;
		}else{
			perror("\nQue pedo con tu mascara?");
		}
	}
	return index;	
}

/*void calculaIP(int inicio, int maximo){
	int i = 0, j = 0, k = 0, x = 0;
	unsigned char IPaux[15];
	for(i = inicio; i <= maximo; i++){
		for (j = 0; j <= 255; j++){
			for (k = 0; k <= 255; k++){
				for (x = 0; x < 255; x++){
					sprintf(IPaux,"%i.%i.%i.%i",i,j,k,x);
					ingresaIP(IPaux);
					estructuraTramaEnvio(tramaEnv);
					enviarTrama(packet_socket, indice, tramaEnv);
					recibeTrama(packet_socket, tramaEnv);
				}
			}
		}
	}
}*/

int main(){
	MYSQL *conn; /* variable de conexión para MySQL */
	MYSQL_RES *res; /* variable que contendra el resultado de la consuta */
	MYSQL_ROW row; /* variable que contendra los campos por cada registro consultado */
	char *server = "localhost"; /*direccion del servidor 127.0.0.1, localhost o direccion ip */
	char *user = "root"; /*usuario para consultar la base de datos */
	char *password = "n0m3l0"; /* contraseña para el usuario en cuestion */
	char *database = "scanner"; /*nombre de la base de datos a consultar */
	conn = mysql_init(NULL); /*inicializacion a nula la conexión */

	/* conectar a la base de datos */
	if (!mysql_real_connect(conn, server, user, password, database, 0, NULL, 0)){ /* definir los parámetros de la conexión antes establecidos */
		fprintf(stderr, "%s\n", mysql_error(conn)); /* si hay un error definir cual fue dicho error */
		exit(1);
	}else{
		printf("Conectado a MySQL Papu\n");
	}

	int packet_socket, indice;
	packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(packet_socket == -1){
		perror("\nNo se pudo abrir el socket\n");
		exit(0);	
	}else{
		printf("\nConcectado al socket chido\n");
		indice = obtenDatos(packet_socket);
		//calculaIP(ini,max);
		int i = 0, j = 0, k = 0, x = 0;
		unsigned char IPaux[15];
		for(i = ini; i <= max; i++){
			for (j = 0; j <= 255; j++){
				for (k = 0; k <= 255; k++){
					for (x = 0; x < 255; x++){
						int y = 0;
						sprintf(IPaux,"%i.%i.%i.%i",i,j,k,x);//con esto generamos la IP
						ingresaIP(IPaux);//enviamos la IP generada para que se guarde en hex 
						estructuraTramaEnvio(tramaEnv);
						printf("Comprobando IP ");
						for(y = 0; y < 4; y++){
							printf("%i.", IPDestino[y]);
						}
						printf("\n");
						enviarTrama(packet_socket, indice, tramaEnv);
						recibeTrama(packet_socket, tramaEnv, conn);
							
					}
				}
			}
		}
	}
	close(packet_socket);
}

/*
Para compilar y así 
gcc arpScanner.c -o chido  `mysql_config --cflags --libs`
*/