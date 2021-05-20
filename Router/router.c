//BUCUR CALIN-ANDREI
//322CB


#include "skel.h"
#include <netinet/if_ether.h>
#include "list.h"
#include "queue.h"

//Structura reprezinta o intrare din tabela de routare
typedef struct {
	uint32_t prefix;
	uint8_t next_hop[4];
	uint32_t mask;
	unsigned int interface;
} Route;


//Structura reprezinta o intrare din tabela ARP
typedef struct {
	uint32_t ip;
	uint8_t mac[6];
} ARP_entry;

uint16_t checksum(void* vdata,size_t length) {
	char* data=(char*)vdata;
	uint64_t acc=0xffff;
	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}
	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;
	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}
	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}
	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}
	return htons(~acc);
}

void merge(Route arr[], int l, int m, int r) 
{ 
    int i, j, k; 
    int n1 = m - l + 1; 
    int n2 =  r - m; 
    Route L[n1], R[n2]; 
    for (i = 0; i < n1; i++) 
        L[i] = arr[l + i]; 
    for (j = 0; j < n2; j++) 
        R[j] = arr[m + 1+ j]; 
    i = 0;
    j = 0;
    k = l;
    while (i < n1 && j < n2) 
    { 
        if (L[i].prefix < R[j].prefix) 
        { 
            arr[k] = L[i]; 
            i++; 
        } 
        else if(L[i].prefix == R[j].prefix) {
        	if(L[i].mask < R[j].mask) {
        		arr[k] = L[i]; 
            	i++;
        	}
        	else {
        		arr[k] = R[j]; 
            	j++; 
        	}
        }
        else
        { 
            arr[k] = R[j]; 
            j++; 
        } 
        k++; 
    } 
    while (i < n1) 
    { 
        arr[k] = L[i]; 
        i++; 
        k++; 
    } 
    while (j < n2) 
    { 
        arr[k] = R[j]; 
        j++; 
        k++; 
    } 
}

//Functia sorteaza tabela de routare folosind algoritmul merge sort
//Tabela e sortata crescator dupa prefix
//In caz de prefixe egale e sortata crescator dupa masca
void Sort_table(Route arr[], int l, int r) { 
    if (l < r) { 
        int m = l+(r-l)/2; 
        Sort_table(arr, l, m); 
        Sort_table(arr, m+1, r); 
        merge(arr, l, m, r); 
    } 
} 

//Adresele sunt stocate in 3 forme: string, array si int
//Am nevoie de functii de conversie intre ele
//Converteste un string adresa in  array adresa
void addr_to_arr (char *addr, uint8_t arr[4]) {
	char *token;
	token = strtok(addr, ".");
	arr[0] = atoi(token);
	token = strtok(NULL, ".");
	arr[1] = atoi(token);
	token = strtok(NULL, ".");
	arr[2] = atoi(token);
	token = strtok(NULL, ".");
	arr[3] = atoi(token);
}

//Converteste string adresa in int
uint32_t addr_to_long (char *addr) {
	char *token;
	token = strtok(addr, ".");
	uint32_t rez = atoi(token);
	token = strtok(NULL, ".");
	rez = rez << 8;
	rez = rez | atoi(token);
	token = strtok(NULL, ".");
	rez = rez << 8;
	rez = rez | atoi(token);
	token = strtok(NULL, ".");
	rez = rez << 8;
	rez = rez | atoi(token);
	return rez;
}

//Converteste array adresa in int
uint32_t pa_to_long (uint8_t pa[]) {
	uint32_t rez = 0;
	for(int i = 0; i < 4; i++) {
		rez = rez << 8;
		rez = rez | pa[i];
	}
	return rez;
}

//Parcurge fisierul in care se afla tabela de routare
//Determina nr de intrari in tabela
long get_entry_count () {
	FILE* fp = fopen("rtable.txt", "r");
	char ch;
	long count = 0;
	while(!feof(fp)) {
  		ch = fgetc(fp);
  		if(ch == '\n') {
    		count++;
  		}
	}
	fclose(fp);
	return count;
}

//Parseaza tabela de routare
void parse_rtable (Route *rtable, long entry_count) {
	FILE* fp = fopen("rtable.txt", "r");
	unsigned long i;
	Route route;
	char *addr = calloc(15, sizeof(char));
	//Citeste fiecare intrare string cu string, o converteste si o adauga
	for(i = 0; i < entry_count; i++) {
		fscanf(fp, "%s", addr);
		route.prefix = addr_to_long(addr);
		fscanf(fp, "%s", addr);
		addr_to_arr(addr, route.next_hop);
		fscanf(fp, "%s", addr);
		route.mask = addr_to_long(addr);
		fscanf(fp, "%u", &route.interface);
		rtable[i] = route;
	}
	fclose(fp);
}

//Cauta ruta cea mai optima in tabela
//Algoritmul folosit este cautarea binara usor modificata (log n)
int find_route (Route *rtable, uint32_t dest, int l, int r) {
	if(r >= l) {
		int mid = l + (r - l)/2;
		//Daca gaseste un prefix potrivit
		//Verifica recursiv in dreapta daca exista un prefix potrivit mai lung
		if((dest & rtable[mid].mask) == rtable[mid].prefix) {
			if((dest & rtable[mid].mask) == rtable[mid + 1].prefix) {
				int i = find_route(rtable, dest, mid + 1, r);
				if(i > 0)
					return i;
				else
					return mid;
			}
			else
				return mid;
		}
		if((dest & rtable[mid].mask) > rtable[mid].prefix)
			return find_route(rtable, dest, mid + 1, r);
		return find_route(rtable, dest, l, mid - 1);
	}
	return -1;
}

int main(int argc, char *argv[]) {
	packet m;
	int rc;
	init();

	//Aloc si parsez tabela de routare
	long entry_count = get_entry_count();
	Route* rtable = malloc(entry_count * sizeof(Route));
	parse_rtable(rtable, entry_count);
	//Sortez tabela de routare
	Sort_table(rtable, 0, entry_count - 1);
	//Pe post de ARP table folosesc o lista pt ca nu ii cunosc size exact
	list arp_table = NULL;
	//Coada in care tin pachetele ce asteapta pana primesc un ARP Reply
	queue q = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		//Header-ul Ethernet pachetului primit
		struct ether_header *eth_hdr = (struct ether_header*) m.payload;

		//Cazul in care pachetul primit e de tip ARP
		if (htons(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			//Header-ul ARP al pachetului
			struct ether_arp *arp_hdr = (struct ether_arp*)(m.payload
			 + sizeof(struct ether_header));

			//Cazul in care pachetul e de tip ARP Request
			if(htons(arp_hdr->ea_hdr.ar_op) == ARPOP_REQUEST) {
				//Aici am adresa MAC a interfetei "interogate"
				uint8_t *mac = malloc(6 * sizeof(uint8_t));
				get_interface_mac(m.interface, mac);
				//Nu imi construiesc alt pachet, ci il refolosesc pe cel primit
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				memcpy(eth_hdr->ether_shost, mac, 6);
				memcpy(arp_hdr->arp_tha, arp_hdr->arp_sha, 6);
				uint8_t *aux = malloc(4 * sizeof(uint8_t));
				memcpy(aux, arp_hdr->arp_spa, 4);
				memcpy(arp_hdr->arp_spa, arp_hdr->arp_tpa, 4);
				memcpy(arp_hdr->arp_tpa, aux, 4);
				memcpy(arp_hdr->arp_sha, mac, 6);
				//Setez tipul ARP Reply
				arp_hdr->ea_hdr.ar_op = htons(ARPOP_REPLY);
				//Trimit pachetul inapoi de unde l-am primit
				send_packet(m.interface, &m);

				free(aux);
				free(mac);
				continue;
			}
			//Cazul in care pachetul e de tip ARP Reply
			else if (htons(arp_hdr->ea_hdr.ar_op) == ARPOP_REPLY) {
				list lista;
				//Construiesc o noua intrare de tip ARP
				ARP_entry* entry = malloc(sizeof(ARP_entry));
				int ok;
				entry->ip = pa_to_long(arp_hdr->arp_spa);
				memcpy(entry->mac, arp_hdr->arp_sha, 6);
				ok = 0;
				//Daca intrarea deja exista nu o salvez duplicat, o arunc
				for(lista = arp_table; lista != NULL; lista = lista->next) {
					if(((ARP_entry*)(lista->element))->ip == entry->ip)
						ok = 1;
				}
				//Daca nu e duplicat, o adaug la tabela
				if(ok == 0) {
				arp_table = cons(entry, arp_table);
				}
				else {
					free(entry);
				}
				//Daca in coada de asteptare se afla un pachet
				//Il scot pt a fi trimis catre destinatie
				if(!queue_empty(q)) {
					memcpy(&m, queue_deq(q), sizeof(packet));
				}
			}
		}
		//Cazul in care pachetul e de tip IP
		if(htons(eth_hdr->ether_type) == ETHERTYPE_IP) {
			//Header-ul IP al pachetului
			struct iphdr *ip_hdr = (struct iphdr*)(m.payload
			 + sizeof(struct ether_header));
			//Header-ul ICMP al pachetului
			struct icmphdr *icmp_hdr = (struct icmphdr*)(m.payload
			 + sizeof(struct ether_header) + sizeof(struct iphdr));
			//Daca checksum-ul e gresit, il arunca
			if(checksum(ip_hdr, sizeof(struct iphdr) ) != 0)
				continue;
			//Cazul in care pachetul e destinat router-ului
			if(ntohl(ip_hdr->daddr) == addr_to_long(get_interface_ip(m.interface))) {
				//Daca pachetul e de tip ICMP ECHO Request
				if(icmp_hdr->type == ICMP_ECHO) {
					//Transform pachetul in ECHO reply
					uint8_t *aux_mac = malloc(6 * sizeof(uint8_t));
					memcpy(aux_mac, eth_hdr->ether_shost, 6);
					memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
					memcpy(eth_hdr->ether_dhost, aux_mac, 6);
					free(aux_mac);
					uint32_t aux_addr;
					aux_addr = ip_hdr->saddr;
					ip_hdr->saddr = ip_hdr->daddr;
					ip_hdr->daddr = aux_addr;
					icmp_hdr->type = ICMP_ECHOREPLY;
					//Il trimit de unde a venit
					send_packet(m.interface, &m);
					continue;
				}
				//Altfel arunc pachetul
				else
					continue;
			}
			//Cazul in care "expira" ttl-ul
			if(ip_hdr->ttl <= 1) {
				//Construiesc un nou pachet
				//Contine o copie a pachetului primit
				packet p;
				p.interface = m.interface;
				struct ether_header* eth_t = (struct ether_header *) p.payload;
				struct iphdr* ip_t = (struct iphdr*)(p.payload
				 + sizeof(struct ether_header));
				struct icmphdr* icmp_t = (struct icmphdr*)(p.payload
				 + sizeof(struct ether_header) + sizeof(struct iphdr));
				memcpy(p.payload + sizeof(struct ether_header)
				 + sizeof(struct iphdr) + sizeof(struct icmphdr), m.payload
				 + sizeof(struct ether_header),
				 m.len - sizeof(struct ether_header));
				p.len = sizeof(struct ether_header) + sizeof(struct iphdr) +
				 sizeof(struct icmphdr) + m.len - sizeof(struct ether_header);
				memcpy(eth_t->ether_dhost, eth_hdr->ether_shost, 6);
				memcpy(eth_t->ether_shost, eth_hdr->ether_dhost, 6);
				eth_t->ether_type = htons(ETHERTYPE_IP);
				ip_t->ihl = 5;
				ip_t->version = 4;
				ip_t->tos = 0;
				ip_t->tot_len = htons(sizeof(struct iphdr) +
				 sizeof(struct icmphdr) + m.len - sizeof(struct ether_header));
				ip_t->id = htons(1234);
				ip_t->frag_off = htons(0);
				ip_t->ttl = 100;
				ip_t->protocol = IPPROTO_ICMP;
				ip_t->daddr = ip_hdr->saddr;
				ip_t->saddr = htons(addr_to_long(get_interface_ip(p.interface)));
				ip_t->check = 0;
				ip_t->check = checksum(ip_t, sizeof(struct iphdr));
				//Seteaza tipul pachetului ICMP Timeout
				icmp_t->type = 11;
				icmp_t->code = 0;
				icmp_t->checksum = 0;
				icmp_t->checksum = checksum(ip_hdr, sizeof(struct iphdr));
				//Trimit inapoi noul pachet
				send_packet(p.interface, &p);
				continue;
			}
			list l;
			uint8_t *mac = NULL;
			//Cauta ruta potrivita pt a trimite mai departe pachetul
			Route best;
			int i = find_route(rtable, htonl(ip_hdr->daddr), 0, entry_count - 1);
			if(i >= 0) {
				best = rtable[i];
			}
			//Daca nu gaseste o ruta
			else {
				//Construiesc un nou pachet asemanator cazului de timeout
				packet p;
				p.interface = m.interface;
				struct ether_header* eth_t = (struct ether_header *) p.payload;
				struct iphdr* ip_t = (struct iphdr*) (p.payload
				 + sizeof(struct ether_header));
				struct icmphdr* icmp_t = (struct icmphdr*) (p.payload +
				 sizeof(struct ether_header) + sizeof(struct iphdr));
				memcpy(p.payload + sizeof(struct ether_header) +
				 sizeof(struct iphdr) + sizeof(struct icmphdr), m.payload +
				 sizeof(struct ether_header), m.len - sizeof(struct ether_header));
				p.len = sizeof(struct ether_header) + sizeof(struct iphdr) +
				 sizeof(struct icmphdr) + m.len - sizeof(struct ether_header);
				memcpy(eth_t->ether_dhost, eth_hdr->ether_shost, 6);
				memcpy(eth_t->ether_shost, eth_hdr->ether_dhost, 6);
				eth_t->ether_type = htons(ETHERTYPE_IP);
				ip_t->ihl = 5;
				ip_t->version = 4;
				ip_t->tos = 0;
				ip_t->tot_len = htons(sizeof(struct iphdr) +
				 sizeof(struct icmphdr) + m.len - sizeof(struct ether_header));
				ip_t->id = htons(1234);
				ip_t->frag_off = htons(0);
				ip_t->ttl = 100;
				ip_t->protocol = IPPROTO_ICMP;
				ip_t->daddr = ip_hdr->saddr;
				ip_t->saddr = htons(addr_to_long(get_interface_ip(p.interface)));
				ip_t->check = 0;
				ip_t->check = checksum(ip_t, sizeof(struct iphdr));
				//Setez tipul pachetului ICMP Unreachable
				icmp_t->type = 3;
				icmp_t->code = 0;
				icmp_t->checksum = 0;
				icmp_t->checksum = checksum(ip_hdr, sizeof(struct iphdr));
				//Trimite inapoi noul pachet
				send_packet(p.interface, &p);
				continue;
			}
			//Cauta in tabela ARP o intrare corespunzatoare adresei next hop
			uint8_t *hop = malloc(4 * sizeof(uint8_t));
			memcpy(hop, best.next_hop, 4);
			for(l = arp_table; l != NULL; l = l->next) {
				if(((ARP_entry*)(l->element))->ip == pa_to_long(hop)) {
					mac = ((ARP_entry*)(l->element))->mac;
					break;
				}
			}
			//Daca nu gaseste o intrare corespunzatoare
			if(mac == NULL) {
				for(int j = 0; j < 6; j++) {
					eth_hdr->ether_dhost[j] = 0;
				}
				packet pkt;
				memcpy(&pkt, &m, sizeof(packet));
				//Salvez pachetul in coada de asteptare pana primesc ARP Reply
				queue_enq(q, &pkt);
				packet pkg;
				pkg.interface = best.interface;
				//Creez un pachet de tip ARP Request
				struct ether_header *eth = (struct ether_header *) pkg.payload;
				struct ether_arp *arp = (struct ether_arp *) (pkg.payload + sizeof(struct ether_header));
				pkg.len = sizeof(struct ether_header) + sizeof(struct ether_arp);
				get_interface_mac(best.interface, eth->ether_shost);
				for(int j = 0; j < 6; j++) {
					eth->ether_dhost[j] = 255;
				}
				eth->ether_type = htons(ETHERTYPE_ARP);
				arp->ea_hdr.ar_hrd = 256;
				arp->ea_hdr.ar_pro = 8;
				arp->ea_hdr.ar_hln = 6;
				arp->ea_hdr.ar_pln = 4;
				arp->ea_hdr.ar_op = htons(ARPOP_REQUEST);
				memcpy(arp->arp_sha, eth->ether_shost, 6);
				addr_to_arr(get_interface_ip(best.interface), arp->arp_spa);
				for(int j = 0; j < 6; j++) {
					arp->arp_tha[j] = 0;
				}
				memcpy(arp->arp_tpa, best.next_hop, 4);
				//Trimit ARP Request-ul prin broadcast
				send_packet(best.interface, &pkg);
				continue;
			}
			else {
				//Complete pachetul cu adresa MAC a interfetei
				get_interface_mac(best.interface, eth_hdr->ether_shost);
				memcpy(eth_hdr->ether_dhost, mac, 6);
				//Decrementez durata de viata
				ip_hdr->ttl--;
				//Recalculez checksum
				ip_hdr->check = 0;
				ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));
				//Trimit pachetul mai departe
				send_packet(best.interface, &m);
			}
		}
	}
	while(arp_table != NULL) {
		arp_table = cdr_and_free(arp_table);
	}
	free(rtable);
}

