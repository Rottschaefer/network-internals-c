#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices;
    pcap_if_t *d;


	//Acha todas as interfaces de rede (bluetooth, Ethernet, mais quais?)
	pcap_findalldevs(&devices, errbuf);
	
	if (devices == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}

    d = devices;
    while(d){
	    printf("Device: %s\n", d->name);

		if (d->addresses != NULL && d->addresses->addr != NULL) {
        	printf("Address: %s\n", d->addresses->addr->sa_data);
		
		}       
		else {
			printf("Sem address\n");
		};
	
		d = d->next;
 	}

	bpf_u_int32 mask;		/* The netmask of our sniffing device */
	bpf_u_int32 net;		/* The IP of our sniffing device */

	if (pcap_lookupnet(devices->name, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", devices->name);
		net = 0;
		mask = 0;
	}

	pcap_t *handle;

	handle = pcap_open_live(devices->name, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", devices->name, errbuf);
		return(2);
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
	fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", devices->name);
	return(2);
}

	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[] = "port 23";	/* The filter expression */


	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	return(0);
}