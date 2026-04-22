#include <stdio.h>
#include <pcap.h>

typedef struct ethernet_header{
    unsigned char destination[6];
    unsigned char source[6];
    unsigned short type; //Contém 2 bytes pra identificar o tipo de header da camada de rede (IP ou outro). u_short é usado poi é mais fácil de verificar que u_char[2]
}__attribute__((packed)) ETHERNET_HEADER;

typedef struct ip_header{
    unsigned char version; //[1 byte] - Versão do IP (IPv4 ou IPv6)(4 bits) + Tamanho do Header em bloco de 4 bytes  (4 bits)
    unsigned char type_service; //[1 byte] - DSCP (Differentiated Services Code Point) que marca a prioridade do pacote (6 bits) + (2 bits) ECN (Explicit Congestion Notification)
    unsigned short length; //[2 bytes] Diz o tamanho do pacote IP (header + data)
    unsigned short id; //[2 bytes] Id pra quando o pacote vem fragmentado
    unsigned short flag_offset; //[2 bytes] flags (3 bits) + (13 bits) de offset, onde 1 de offset significa 1 bloco de 8 bytes

}__attribute__((packed)) IP_HEADER;

//Tem que tomar cuidado com a questão do Big e Little Endian

unsigned short inverte_bytes(unsigned short x){
    return (x >> 8) | (x << 8);
}


int main(int argc, char* argv[]){

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t* devices; //Struct de interface de rede

    pcap_findalldevs(&devices, error_buffer); //Retorna lista encadeada de interfaces. 

    char* dev = devices->name;

    printf("\nDevice %s\n", dev);

    pcap_t* handle = pcap_open_live(dev, 262144, 1, 1000, error_buffer); //Faz uma chamada de sistema pra colocar a interface de rede em modo promíscuo e outra pra criar um buffer para qual o SO vai redirecionar todos os pacotes que chegam da interface

    if(!handle){
        printf("Erro ao abrir conexão: %s\n", error_buffer);
    }
    

    int link_type = pcap_datalink(handle);

    if (link_type != DLT_EN10MB) {
	    fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
	    return 0;
    }

    printf("\nTipo do Header da camada de enlace: %d\n", link_type);

    struct pcap_pkthdr header; //Vai armazenar o header do pacote recebido

    const unsigned char* packet; //Ponteiro para o início dos bytes do pacote capturado

    packet = pcap_next(handle, &header);

    if(!packet) printf("Erro ao capturar pacote o nenhum pacote chegou");

    printf("Pacote de tamanho %d bytes capturado!\n", header.caplen);

    ETHERNET_HEADER* eth_hdr = (ETHERNET_HEADER*)(packet);

    printf("MAC de destino: %02X:%02X:%02X:%02X:%02X:%02X\n",
    eth_hdr->destination[0], eth_hdr->destination[1], eth_hdr->destination[2],eth_hdr->destination[3],eth_hdr->destination[4],eth_hdr->destination[5]
    );

    printf("MAC de origem: %02X:%02X:%02X:%02X:%02X:%02X\n",
    eth_hdr->source[0], eth_hdr->source[1], eth_hdr->source[2],eth_hdr->source[3],eth_hdr->source[4],eth_hdr->source[5]
    );

    IP_HEADER* ip_hdr = (IP_HEADER*)(packet + sizeof(ETHERNET_HEADER));

    unsigned char ip_version = ip_hdr->version >> 4; //Dessloca 4 bits pra direita pra ler só os 4 bits da versão

    unsigned char ip_hdr_len = ip_hdr->version & 0x0F; //Usa a máscara 00001111 em hexa pra pegar os últimos 4 bits

    printf("\n\nVersão IP: %d\n", ip_version);
    printf("Tamanho do cabeçalho IP: %d\n", ip_hdr_len*4);
    
    unsigned char dscp = ip_hdr->type_service >> 2;
    unsigned char ecn = ip_hdr->type_service & 0x03;

    printf("\nDSCP: %d\n", dscp);
    printf("ECN: %d\n", ecn);

    unsigned short ip_len = inverte_bytes(ip_hdr->length);
    unsigned short ip_id  = inverte_bytes(ip_hdr->id);

    printf("Tamanho do pacote IP (bytes): %d\n", ip_len);
    printf("ID do pacote IP : %d\n", ip_id);

    unsigned short flag_offset = inverte_bytes(ip_hdr->flag_offset);
    unsigned char flag = flag_offset >> 13;
    unsigned char flag_reservado = (flag & 0x04)>>2;
    unsigned char flag_dont_fragment = flag & 0x02>>1;
    unsigned char flag_more_fragments = flag & 0x01;
    unsigned short offset = (flag_offset & 0x1FFF)*8;

    printf("Flags - Reservado: %d - Don't Fragment: %d - More Fragments: %d\n", flag_reservado, flag_dont_fragment, flag_more_fragments);
    printf("Offset: %d\n", offset);

    // for (int i = 0; i < header.caplen; i++)
    // {
    //     printf("\n%2X  ", (packet[i])); //Printa byte por byte do pacote em formato hexadecimal com 2 dígitos
    // }
    
    pcap_close(handle);

    return 0;
}