#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <net/ethernet.h> 
#include <sys/ioctl.h>
#include <net/if.h>
//Variables globales
unsigned char tramaEnv[1514];

unsigned char ethertype[2]={0x08,0x06};
unsigned char TipoHdw[2]={0x00,0x01};
unsigned char TipoProt[2]={0x08,0x00};
unsigned char OpCode[2]={0x00,0x01};
unsigned char MACorigen[6]={0x64, 0x66, 0xb3, 0x1b, 0xce, 0x3a};
unsigned char MACbroadcast[6]={0xff,0xff,0xff,0xff,0xff,0xff};
unsigned char Mascr[4];
unsigned char IP[4];
unsigned char IPdestino[4]={192,168,0,4};
unsigned char tramaRec[1514];
//Struct para crear el encabezdo de ARP
typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint8_t opcode;
 };
//funcion que ensambla la trama ARP
void ingresaIPdest()
{
	struct sockaddr_in adr_inet;
    unsigned char ipt[15];
	printf("\nIngrese la dirección IP a la que desea hacer la solicitd ARP:");
    scanf("%s",ipt);
    fflush(stdin);
    memset(&adr_inet,0,sizeof adr_inet);
	inet_aton(ipt,&adr_inet.sin_addr);
	memcpy(IPdestino,&adr_inet.sin_addr,4);
}
void estructuraTramaARP(unsigned char *trama,unsigned char *IPdestino,unsigned char *MACorigen)//,
{
	struct ifreq nic;
	struct _arp_hdr arphdr;
	
	// Hardware type (16 bits): 1 for ethernet
	arphdr.htype = htons (1);

	// Protocol type (16 bits): 2048 for IP
	arphdr.ptype = htons (ETH_P_IP);
	// Hardware address length (8 bits): 6 bytes for MAC address
	arphdr.hlen = 6;

	// Protocol address length (8 bits): 4 bytes for IPv4 address
	arphdr.plen = 4;

	// OpCode: 1 for ARP request
	arphdr.opcode = htons (ARPOP_REQUEST);
	ingresaIPdest();
	memcpy(trama+0,MACbroadcast,6);
	memcpy(trama+6,MACorigen,6);
	memcpy(trama+12,ethertype,2);
	memcpy(trama+14,&arphdr.htype,2);
	memcpy(trama+16,TipoProt,2);
	memcpy(trama+18,&arphdr.hlen,1);
	memcpy(trama+19,&arphdr.plen,1);
	memcpy(trama+20,OpCode,2);
	memcpy(trama+22,MACorigen,6);
	memcpy(trama+28,(nic.ifr_addr.sa_data)+2,4);
	memcpy(trama+38,IPdestino,4);
}
//Funcion que imprime la trama
void imprimeTrama(unsigned char *paq,int tam)
{
	int i;
	for (i = 0; i < tam; i++)
	{
		if (i%16 == 0)
			printf("\n");
		printf("%.2x ",paq[i]);
	}
	printf("\n");
}
//Funcion que compara el ethertype
int comparaETH(unsigned char * a, unsigned char * b)
{
	int i,flag=0,cont=0;
	for (i = 0; i < 2; i++)
	{
		if (a[i] == b[i])
		{
			cont++;
		}
	}
	if (cont==2)
	{
		flag=1;
	}else{
		flag=0;
	}
	return flag;
}
//Funcion que compara las IP's
int comparaIP(unsigned char * a, unsigned char * b)
{
	int i,flag=0,cont=0;
	for (i = 0; i < 4; i++)
	{
		if (a[i] == b[i])
		{
			cont++;
		}
	}
	if (cont==4)
	{
		flag=1;
	}else{
		flag=0;
	}
	return flag;
}
//Funcion que realiza el filtrado de las tramas que entran
int verificaTramaARP(unsigned char *trama,int tam)
{
	int i,flag=0;
	unsigned char ethertypeTrama[2],senderIP[4],targetIP[4];
	memcpy(ethertypeTrama,trama+12,2);//copia la parte de la trama que contiene el ethertype
	memcpy(senderIP,trama+28,4);//copia la parte de la trama que contiene el ip origen
	memcpy(targetIP,trama+38,4);//copia la parte de la trama que contiene el ip objetivo
	
	if (comparaETH(ethertypeTrama,ethertype) && comparaIP(targetIP,IP) && comparaIP(IPdestino,senderIP))
	{
		flag=1;// si la bandera es uno las IP y los ethertypes coinciden con los de la trama enviada anteriormente
	}
	return flag;
}

//En esta funcion recibimos las tramas
void recibeTrama(int ds, unsigned char *trama)
{
	int tam,checkTrama;
	while(1)
	{
		tam=recvfrom(ds,trama,1514,0,NULL,0);
		if(tam==-1)
		{
    		perror("\nError al recibir");
    		exit(0);
		}else{
    		if(!memcmp(trama,MACorigen,6) && verificaTramaARP(trama,tam))//filtramos a las que tengan como destino nuestra MAC,IPdestino,IPorigen y el etherype 0806
    		{
    			printf("\nRespuesta recibida:\n");
    			imprimeTrama(trama,tam);
    			break;
    		}
		}
	}
}
//Obtenemos el índice de la interfaz de red
int obtenDatos(int ds)
{
	int index,i;
	struct ifreq nic;
	printf("\nIngrese el nombre de la interfaz por la que desea realizar la solicitud ARP:");
	scanf("%s",nic.ifr_name);
	printf("\nDatos de la interfaz\n");
	if(ioctl(ds,SIOCGIFINDEX,&nic) == -1)
	{
		perror("\nError al obtener el índice\n");
		exit(0);
	}else{
		index=nic.ifr_ifindex;
	}
	return index;
}
//obtenemos nuestra MAC 
void obtenMAC(int ds)
{
	struct ifreq nic;
	int i;
	if (ioctl(ds,SIOCGIFHWADDR,&nic) == -1)
	{
		perror("\nError al obtener MAC");
	}else{
		memcpy(MACorigen,nic.ifr_hwaddr.sa_data,6);
		printf("\nMAC");
		for (i = 0; i < 6; i++)
		{
			printf(":%.2x",MACorigen[i]);
		}
		printf("\n");
	}
}
//Obtenemos nuestra Mascara de red
void obtenMascr(int ds)
{
	struct ifreq nic;
	int i;
	if (ioctl(ds,SIOCGIFNETMASK,&nic) == -1)
	{
		perror("\nError al obtener Mascara de red");
	}else{
		memcpy(Mascr,(nic.ifr_netmask.sa_data)+2,4);
		printf("\nMascara:");
		for (i = 0; i < 4; i++)
		{
			printf(".%d",Mascr[i]);
		}
		printf("\n");
	}
}
//Obtenemos nuestra IP
void obtenIP(int ds)
{
	struct ifreq nic;
	int i;
	if (ioctl(ds,SIOCGIFADDR,&nic) == -1)
	{
		perror("\nError al obtener IP");
	}else{
		memcpy(IP,(nic.ifr_addr.sa_data)+2,4);
		printf("\nIP:");
		for (i = 0; i < 4; i++)
		{
			printf(".%d",IP[i]);
		}
		printf("\n");
	}
} 
//funcion que envía la trama ARP al broadcast  
void enviaTramaARP(int ds, int index,unsigned char *trama)
{
	int tam;
	struct sockaddr_ll interfaz;
	memset(&interfaz,0x00,sizeof(interfaz));
	interfaz.sll_family=AF_PACKET;
	interfaz.sll_protocol=htons(ETH_P_ALL);
	interfaz.sll_ifindex=index;
	tam=sendto(ds,trama,42,0,(struct sockaddr*)&interfaz,sizeof(interfaz));
	if (tam==-1)
	{
		perror("\nError al enviar\n");
	}else{
		printf("\nExito al enviar %d Bytes\n",tam);
		imprimeTrama(trama,tam);
		printf("\n");
	}
}
int main()
{
    int packet_socket,indice;
    packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    printf("\nProtocolo ARP\n");
    if(packet_socket == -1)
    {
        perror("\nError al abrir el socket");
        exit(0);
    }else{
    	indice=obtenDatos(packet_socket);
    	obtenMAC(packet_socket);
        obtenMascr(packet_socket);
        obtenIP(packet_socket);
        estructuraTramaARP(tramaEnv,IPdestino,MACorigen);
        enviaTramaARP(packet_socket,indice,tramaEnv);
        recibeTrama(packet_socket,tramaRec);
    }
    close(packet_socket);
}
