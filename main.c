#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices;
    pcap_if_t *d;

	pcap_findalldevs(&devices, errbuf);
	if (devices == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}

    d = devices;
    while(d){
	    printf("Device: %s\n", d->name);
        d = d->next;
    }

	return(0);
}