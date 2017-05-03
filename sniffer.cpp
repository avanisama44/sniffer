#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <set>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include "net.h"

#define SIZE_ETHERNET_HEADER 14
using namespace std;
int packetcounter=0;
map<pair<int,int>,string> mk;

map<pair<int,int>,int> counter;
//if counter is 1 request
//if counter is 2 response


string print_payload(const u_char *payload, int packetlen)
{
	const u_char *tprint= payload;
	const u_char *tosend= payload;
	  string sg = "";
	int i;
	for(i=0;i<packetlen;i++)
	{
		if (isprint(*tprint) || *tprint == '\n' )
		{
		
		sg.push_back(*tprint);

		}

		
		else
		{

				char tp[5];
				sprintf(tp,"%d",*tprint);
				sg.append(tp);
		}
		

	tprint++;
	

	}

	return sg;
}

void processPacket(u_char* protocol, const struct pcap_pkthdr* pkthdr, const u_char * packet)
{ 
    const struct sniff_ethernet *eth_pkt; 
    const struct sniff_ip *ip_pkt; 
    const struct sniff_tcp *tcp_pkt; 
    const u_char *payload; 
    string stringtoappend="";
    string k="";
  
    eth_pkt = (const struct sniff_ethernet*)(packet);
    ip_pkt = (const struct sniff_ip*)(packet + SIZE_ETHERNET_HEADER);
    u_int size_ip_header;
    u_int size_tcp_header; 
    
    

    size_ip_header=IP_HL(ip_pkt)*4;
    if(size_ip_header<20)
    	return;

    tcp_pkt = (const struct sniff_tcp*)(packet + SIZE_ETHERNET_HEADER+size_ip_header);
	size_tcp_header=TH_OFF(tcp_pkt)*4;
	if (size_tcp_header < 20) 
	return;
	int srcport=ntohs(tcp_pkt->th_sport);
	int destport= ntohs(tcp_pkt->th_dport);


	if(*protocol==1)
	{
		if(srcport!=80 && destport!=80)	//port not for http
			return;
	}
	else if(*protocol==2)
	{
		if(srcport!=20 && destport!=20 && srcport!=21 && destport!=21 )
			return; //port not for ftp
	}
	else if(*protocol==3)
	{
		if(srcport!=23 && destport!=23)
			return;//port not for telnet
	}
	


map<pair<int,int>,string>::iterator it;
int ipaddress;
int size_payload=((pkthdr->len)- (SIZE_ETHERNET_HEADER+size_ip_header+size_tcp_header));
if (size_payload==0)
	return;
if((destport==80 && *protocol==1)||(destport==20 && *protocol==2)||(destport==21 && *protocol==2)||(destport==23 && *protocol==3))
{
	ipaddress=ip_pkt->ip_src.s_addr;
	if (!mk.count({ipaddress,srcport}))
	{
		mk.insert({{ipaddress,srcport},string()});
		counter.insert({{ipaddress,srcport},1});
		
		
	}
auto ct = counter.find({ipaddress,srcport});

if(ct->second==1)
{
	
	k=print_payload((const u_char *)(packet + SIZE_ETHERNET_HEADER+size_ip_header+size_tcp_header),size_payload);
	if (k!="" || k!="\n")
{
	auto kt = mk.find({ipaddress,srcport});
	stringtoappend.append(kt->second);
	stringtoappend.append("\nRequest from client\n");
	stringtoappend.append(k);
	mk.erase({ipaddress,srcport});
	mk.insert({{ipaddress,srcport},stringtoappend});
	
	counter.erase({ipaddress,srcport});
	counter.insert({{ipaddress,srcport},2});
}


}
else if (ct->second==2 ) 
{
	
	k=print_payload((const u_char *)(packet + SIZE_ETHERNET_HEADER+size_ip_header+size_tcp_header),size_payload);
	if (k!="" || k!="\n")
{	auto kt = mk.find({ipaddress,srcport});
	stringtoappend.append(kt->second);
	stringtoappend.append(k);
	mk.erase({ipaddress,srcport});
	mk.insert({{ipaddress,srcport},stringtoappend});
	
}
}


}


else if((srcport==80 && *protocol==1)||(srcport==20 && *protocol==2)||(srcport==21 && *protocol==2)||(srcport==23 && *protocol==3))
{ipaddress=ip_pkt->ip_dst.s_addr;
	if (!mk.count({ipaddress,destport}))
{
	mk.insert({{ipaddress,destport},string()});
	counter.insert({{ipaddress,destport},2});
	
}
auto ct = counter.find({ipaddress,destport});

if(ct->second==2)
{	auto kt = mk.find({ipaddress,destport});
	stringtoappend.append(kt->second);
	stringtoappend.append("\nResponse from server\n");
	stringtoappend.append(print_payload((const u_char *)(packet + SIZE_ETHERNET_HEADER+size_ip_header+size_tcp_header),size_payload));
	mk.erase({ipaddress,destport});
	mk.insert({{ipaddress,destport},stringtoappend});
	counter.erase({ipaddress,destport});
	counter.insert({{ipaddress,destport},1});
}
else if (ct->second==1 )
{	auto kt = mk.find({ipaddress,destport});
	stringtoappend.append(kt->second);
	stringtoappend.append(print_payload((const u_char *)(packet + SIZE_ETHERNET_HEADER+size_ip_header+size_tcp_header),size_payload));
	mk.erase({ipaddress,destport});
	mk.insert({{ipaddress,destport},stringtoappend});
}

}
return;

}

int main(int argv,char **argc)
{
	u_char proto_type;
	char errbuf[PCAP_ERRBUF_SIZE];
	char filename[100];
	printf("Enter trace file path\n");
	scanf("%s",filename);
	printf("Specify protocol- 1-HTTP\t 2-FTP\t 3-telnet\n");
	scanf("%d",(int *)&proto_type);
	pcap_t* pcap;
	pcap_t* exp;
	pcap= pcap_open_offline(filename, errbuf);
	if (pcap == NULL)
    {
	fprintf(stderr, "error reading pcap file: %s\n", errbuf);
	return 1;
    }
    if ( pcap_loop(pcap, -1, processPacket,&proto_type) == -1){
        fprintf(stderr, "ERROR: %s\n", pcap_geterr(exp) );
 	}
 	if (proto_type == 1)
	printf("Protocal HTTP:\n" );
    else if (proto_type == 2)
	printf("Protocal FTP:\n" );
    else if (proto_type == 3)
	printf("Protocal TELNET:\n" );
 	

 	for (auto pt=mk.begin();pt!=mk.end(); pt++)
 	{
 		 unsigned char bytes[4];
    	bytes[0] = pt->first.first & 0xFF;
    	bytes[1] = (pt->first.first >> 8) & 0xFF;
    	bytes[2] = (pt->first.first >> 16) & 0xFF;
    	bytes[3] = (pt->first.first >> 24) & 0xFF;	
    	printf("Session Between Server :" );
    	printf("%d.%d.%d.%d ", bytes[0], bytes[1], bytes[2], bytes[3]);  
		printf(" and Client Port: %d : \n" ,pt->first.second);
	cout << pt->second << endl;

 	}

	return 0;


}

