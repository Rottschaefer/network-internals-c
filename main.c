#include <stdio.h>
#include <pcap.h>


int main(int argc, char* argv[]){

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t* devices; //Struct de interface de rede

    pcap_findalldevs(&devices, error_buffer); //Retorna lista encadeada de interfaces. 

    pcap_t* handle = pcap_open_live(devices->name, 262144, 1, 1000, error_buffer); //Faz uma chamada de sistema pra colocar a interface de rede em modo promíscuo e outra pra criar um buffer para qual o SO vai redirecionar todos os pacotes que chegam da interface

    if(!handle){
        printf("Erro ao abrir conexão: %s\n", error_buffer);
    }
    
    printf("Device %s\n", devices->name);

    struct pcap_pkthdr header; //Vai armazenar o header do pacote recebido

    const unsigned char* packet; //Ponteiro para o início dos bytes do pacote capturado

    packet = pcap_next(handle, &header);

    if(!packet) printf("Erro ao capturar pacote o nenhum pacote chegou");

    printf("Pacote de tamanho %d capturado!\n", header.caplen);

    for (int i = 0; i < header.caplen; i++)
    {
        printf("\n%2X  ", (packet[i])); //Printa byte por byte do pacote em formato hexadecimal com 2 dígitos
    }
    

    return 0;
}