/********************************************
 *  client.c
 *  Adam Robert Critchley
 *  CS 4953 - Steganography
 *  Client used to decode hidden DNS message
 *  sent by server within the compression
 *  scheme.
 *  07/27/2008
 ********************************************/

#include <pcap.h>
#include <dnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <math.h>
#include <time.h>
#include <sys/fcntl.h>
#include "client.h"

// #define _DEBUG

// dns type constants used in decoding
#define DNS_TYPE_A               1  // a host address
#define DNS_TYPE_NS              2  // an authoritative name server
#define DNS_TYPE_MD              3  // a mail destination (Obsolete - use MX)
#define DNS_TYPE_MF              4  // a mail forwarder (Obsolete - use MX)
#define DNS_TYPE_CNAME           5  // the canonical name for an alias
#define DNS_TYPE_SOA             6  // marks the start of a zone of authority
#define DNS_TYPE_MB              7  // a mailbox domain name (EXPERIMENTAL)
#define DNS_TYPE_MG              8  // a mail group member (EXPERIMENTAL)
#define DNS_TYPE_MR              9  // a mail rename domain name (EXPERIMENTAL)
#define DNS_TYPE_NULL            10 // a null RR (EXPERIMENTAL)
#define DNS_TYPE_WKS             11 // a well known service description
#define DNS_TYPE_PTR             12 // a domain name pointer
#define DNS_TYPE_HINFO           13 // host information
#define DNS_TYPE_MINFO           14 // mailbox or mail list information
#define DNS_TYPE_MX              15 // mail exchange
#define DNS_TYPE_TEXT            16 // text strings

// decoding constants
#define NaN                            (-1)
#define START_COMPRESSION              0xC0

// pcap related constants
#define TCP_DNS                        53
#define UDP_DNS                        53
#define MAX_PKTSIZE           	       65536
#define PCAP_MAGIC                     0xa1b2c3d4
#define PCAP_SWAPPED_MAGIC             0xd4c3b2a1
#define PCAP_MODIFIED_MAGIC            0xa1b2cd34
#define PCAP_SWAPPED_MODIFIED_MAGIC    0x34cdb2a1

// time constants in microseconds
#define SLEEP_DELAY                    500000
#define SLEEP_RANDOM                   2000000

// memory allocation constants
#define CONFIGURATION_FILE "client.conf"
#define MAX_PACKET_SIZE    1024
#define MAX_DOMAIN_NAME    256
#define MAX_FILENAME       256
#define MAX_RECVBUFFER     100

struct pcap32_pkthdr
{
   bpf_u_int32 tv_sec;
   bpf_u_int32 tv_usec;
   bpf_u_int32 caplen;
   bpf_u_int32 len;
};

struct LABELENTRY
{
   int offset;
   char label[MAX_DOMAIN_NAME];
   struct LABELENTRY *next;
};

struct CONFIGINFO
{
   char dumpfile[MAX_FILENAME];
   char servername[MAX_FILENAME];
   char protocol[MAX_FILENAME];
   char timing[MAX_FILENAME];
   int  port;
   unsigned long serverip;

   void (*curMode)( struct CONFIGINFO,int pktlen, void * );
   int  (*sendMode)( int, int, struct CONFIGINFO, int, void * );
};

void zeroTerm( char *str );
int  readConfig( FILE *fp, struct CONFIGINFO *ci );
void continuousMode( struct CONFIGINFO ci, int pktlen, void *pktload );
void delayMode( struct CONFIGINFO ci, int pktlen, void *pktload );
void randomMode( struct CONFIGINFO ci, int pktlen, void *pktload );
int  sendQueryUDP( int ndx, int val, struct CONFIGINFO ci, int pktlen, void *pktload);
int  sendQueryTCP( int ndx, int val, struct CONFIGINFO ci, int pktlen, void *pktload);
int  decodeResponse( int pktlen, void *pktload );
void initLabel( struct LABELENTRY **head );
void deleteLabel( struct LABELENTRY *head );
int  insertLabel( int offset, char *label, struct LABELENTRY **head);
int  parseString( char *string, char *data );
void outputHex( char *buffer, int length );
int  concatString( char *dest, char *cur, char *data );

struct LABELENTRY *g_Labels;
char *g_PktPos;

int main()
{
   struct pcap32_pkthdr phdr;
   struct pcap_file_header fhdr;

   // ethernet stuff
   struct eth_hdr *ethhdr;

   // ip stuff
   struct ip_hdr *iphdr;

   // tcp stuff
   struct tcp_hdr *tcphdr;

   // udp stuff
   struct udp_hdr *udphdr;

   int          ioerror, pktread;
   char         pktload[MAX_PKTSIZE];
   char        *pktptr;
   unsigned int pktlen;

   struct CONFIGINFO fCi;
   FILE  *fConfig;
   int    infd;

   if( !(fConfig = fopen(CONFIGURATION_FILE,"r")) )
   {
      exit(-1);
   }
   
   if( readConfig(fConfig,&fCi) )
   {
      exit(-1);
   }

   if( (infd = open(fCi.dumpfile, O_RDONLY)) == -1 )
   {
      exit(-1);
   }
   
   if( read(infd,&fhdr,sizeof(fhdr)) != sizeof(fhdr))
   {
      printf("Was not able to read header from stdin: %25s",strerror(errno));
      exit(-1);
   }

   if( fhdr.magic != PCAP_MAGIC)
   {
      printf("There is no support for dump files other than PCAP_MAGIC!");
      exit(-1);
   }

   printf("PCAP_MAGIC\n");
   printf("Version major number = %d\n",fhdr.version_major);
   printf("Version minor number = %d\n",fhdr.version_minor);
   printf("GMT to local correction = %d\n",fhdr.thiszone);
   printf("Timestamp accuracy = %d\n",fhdr.sigfigs);
   printf("Snaplen = %d\n",fhdr.snaplen);
   printf("Linktype = %d\n",fhdr.linktype);
   
   while( read(infd,&phdr,sizeof(phdr)) == sizeof(phdr) )
   {
      pktread = 0;

      while( (pktread += (ioerror = read(infd, 
         &(pktload[pktread]), phdr.caplen-pktread))) < phdr.caplen){
         if( ioerror < 0 ){
            printf("Error reading from stdin: %25s",strerror(errno));
            exit(-1);
         }
      }

      initLabel( &g_Labels );
      pktptr = pktload;
      ethhdr = (struct eth_hdr*)(pktptr);
      pktptr += ETH_HDR_LEN;

      if(ntohs(ethhdr->eth_type) == ETH_TYPE_IP)
      {

         iphdr = (struct ip_hdr*)(pktptr);
         pktptr += IP_HDR_LEN;

         switch(iphdr->ip_p)
         {
         case IP_PROTO_TCP:
            tcphdr = (struct tcp_hdr*)(pktptr);
            pktptr += tcphdr->th_off * 4;

            pktlen = ntohs((*((unsigned int *) pktptr)));
            pktptr += 2;
            if( ntohs(tcphdr->th_dport) == TCP_DNS )
            {
               printf("Valid TCP DNS packet... preparing to send to %-30s\n",fCi.servername);
               fCi.curMode(fCi, pktlen, pktptr);
            }
            break;
         case IP_PROTO_UDP:
            udphdr = (struct udp_hdr*)(pktptr);
            pktptr += UDP_HDR_LEN;

            pktlen = pktread - ETH_HDR_LEN - IP_HDR_LEN - UDP_HDR_LEN;
            if(ntohs(udphdr->uh_dport) == UDP_DNS)
            {
               printf("Valid UDP DNS packet... preparing to send to %-30s\n",fCi.servername);
               fCi.curMode(fCi, pktlen, pktptr);
            }
            break;
         }
         break;
      }

      deleteLabel( g_Labels );
   }

   return EXIT_SUCCESS;
}

int readConfig( FILE *fp, struct CONFIGINFO *ci )
{
   struct hostent  *ptrh;  /* pointer to a host table entry */
   char port[10];

   if( !fgets(ci->dumpfile, MAX_FILENAME, fp) )
      return -1;
   zeroTerm(ci->dumpfile);

   if( !fgets(ci->servername, MAX_FILENAME, fp) )
      return -2;
   zeroTerm(ci->servername);

   if( !fgets(port, sizeof(port), fp) )
      return -3;
   zeroTerm(port);
   sscanf(port,"%d",&ci->port);

   if( !fgets(ci->protocol, MAX_FILENAME, fp) )
      return -4;
   zeroTerm(ci->protocol);

   if( !fgets(ci->timing, MAX_FILENAME, fp) )
      return -5;
   zeroTerm(ci->timing);

   /* Convert host name to equivalent IP address and copy to serverip */
   ptrh = gethostbyname(ci->servername);
   if ( ((char *)ptrh) == NULL ) 
   {
      return -6;
   }

   memcpy(&ci->serverip, ptrh->h_addr, ptrh->h_length);

   if( !strcasecmp( ci->timing, "continuous" ) )
   {
      ci->curMode = continuousMode;
   }else if( !strcasecmp( ci->timing, "delay" ) )
   {  
      ci->curMode = delayMode;
   }else if( !strcasecmp( ci->timing, "random" ) )
   {
      srand( (unsigned int)time(NULL) );
      ci->curMode = randomMode;
   }else{
      return -7; // unrecognized mode
   }

   if( !strcasecmp( ci->protocol, "tcp" ) )
   {  
      ci->sendMode = sendQueryTCP;
   }else if( !strcasecmp( ci->protocol, "udp" ) )
   {
      ci->sendMode = sendQueryUDP;
   }else{
      return -8; // unrecognized mode
   }

   return 0;
}

void zeroTerm( char *str )
{
   str[strlen(str)-1] = '\0';
}

void continuousMode( struct CONFIGINFO ci, int pktlen, void *pktload )
{
    // send query
    ci.sendMode( 0, 0, ci, pktlen, pktload );
}

void delayMode( struct CONFIGINFO ci, int pktlen, void *pktload )
{
    usleep( SLEEP_DELAY ); // sleep for 500 ms
	
    // send query
    ci.sendMode( 0, 0, ci, pktlen, pktload );
}

void randomMode( struct CONFIGINFO ci, int pktlen, void *pktload )
{
    usleep( rand() % SLEEP_RANDOM ); // sleep for no more than 2 secs

    // send query
    ci.sendMode( 0, 0, ci, pktlen, pktload );
}

int sendQueryUDP( int ndx, int val, struct CONFIGINFO ci, int pktlen, void *pktload) 
{
   int sock;
   struct sockaddr_in sa, from;
   int bytes_sent, fromlen;
   struct dns_header *hdr;
   char buffer[MAX_PACKET_SIZE];

   hdr = (struct dns_header *) pktload;
   if( ndx && val )
   {
      hdr->id = htons(MAKE_TRANSID(ndx,val));
   }

   outputHex( pktload, pktlen );

   /* send the query */
   sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
   if (-1 == sock) 
   {
      return -1;
   }
   sa.sin_family = AF_INET;
   sa.sin_port = htons(ci.port);
   sa.sin_addr.s_addr = ci.serverip;

   printf("Message Length = %d\n", pktlen);
   bytes_sent = sendto(sock, pktload, pktlen, 0, (struct sockaddr*) &sa, sizeof(struct sockaddr_in));
   if (bytes_sent < 0)
   {
      return -2;
   }

   /* receive reponse */
   bzero(buffer, MAX_PACKET_SIZE);
   bzero(&from, sizeof(struct sockaddr_in));
   printf("Waiting reply...\n");
   fromlen = sizeof(struct sockaddr_in);

   bytes_sent = recvfrom(sock, buffer, MAX_PACKET_SIZE, 0,(struct sockaddr *) &from, (unsigned int *) &fromlen);
   printf("Received reply...\n");
   if (bytes_sent < 0) {
      return -3;
   }

   outputHex( buffer, bytes_sent );

   decodeResponse( bytes_sent, buffer );

   return 0;
}

int sendQueryTCP( int ndx, int val, struct CONFIGINFO ci, int pktlen, void *pktload) 
{
   int sock, bytes_sent;
   struct sockaddr_in sa;
   char sbuffer[MAX_PACKET_SIZE], rbuffer[MAX_PACKET_SIZE], *offset;
   struct dns_header *hdr;
   unsigned short *length_field;

   /* build the query */
   bzero(sbuffer, MAX_PACKET_SIZE);

   length_field = (unsigned short *) sbuffer;
   *length_field = htons(pktlen);

   offset = sbuffer + 2;
   memcpy( offset, pktload, pktlen );

   hdr = (struct dns_header *) offset;
   if( ndx && val )
   {
      hdr->id = htons(MAKE_TRANSID(ndx,val));
   }

   outputHex( sbuffer, pktlen + 2 );

   /* send the query */
   sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
   if (-1 == sock) 
   {
      return 0;
   }
   sa.sin_family = AF_INET;
   sa.sin_port = htons(ci.port);
   sa.sin_addr.s_addr = ci.serverip;

   printf("Message Length = %d\n", pktlen);
   if (-1 == connect(sock, (struct sockaddr *) &sa, sizeof(struct sockaddr_in))) 
   {
      return 0;
   }

   bytes_sent = write(sock, sbuffer, pktlen+2);
   if (bytes_sent != (pktlen+2)) 
   {
      return 0;
   }

   /* receive response */
   bzero(rbuffer, MAX_PACKET_SIZE);
   printf("Waiting reply...\n");
   bytes_sent = read(sock, rbuffer, MAX_PACKET_SIZE);
   printf("Received reply...\n");
   if (bytes_sent < 0) {
      return -3;
   }

   outputHex( rbuffer, bytes_sent );

   decodeResponse( bytes_sent, (rbuffer+2) );

   close(sock);
   return 0;
}

int decodeResponse( int pktlen, void *pktload )
{
   struct dns_header *ptr_hdr;
   struct dns_question *ptr_question;
   struct dns_response *ptr_response;
   struct dns_authoritative *ptr_auth;
   struct dns_additional *ptr_add;
   int    bitReturned, i, recvBits,message;
   int    bits[MAX_RECVBUFFER];

   recvBits = 0;

   printf("Decoding Response...\nParsing header of %d bytes...\n",DNS_HEADER_SIZE);
   g_PktPos = (char*)pktload;
   ptr_hdr = (struct dns_header*) g_PktPos;
   g_PktPos += DNS_HEADER_SIZE;

   printf("Parsing %d questions...\n",ntohs(ptr_hdr->q_count));
   for( i = 0; i < ntohs(ptr_hdr->q_count); i++)
   {
      printf("Stripping question %d\n",i);
      bitReturned = parseString( g_PktPos, pktload );
      if( bitReturned != -1 )
      {
         bits[recvBits] = bitReturned;
         recvBits++;
      }

      ptr_question = (struct dns_question*) g_PktPos;
      g_PktPos += DNS_QUESTION_SIZE;
      printf("Parsed question result = %d\nStripped question %d\n\n",bitReturned,i);
   }

   printf("Parsing %d responses...\n",ntohs(ptr_hdr->ans_count));
   for( i = 0; i < ntohs(ptr_hdr->ans_count); i++)
   {
      printf("Stripping response %d\n",i);
      bitReturned = parseString( g_PktPos, pktload );
      if( bitReturned != -1 )
      {
         bits[recvBits] = bitReturned;
         recvBits++;
      }

      ptr_response = (struct dns_response*) g_PktPos;
      g_PktPos += DNS_RESPONSE_SIZE;
      printf("Parsed response result = %d\n",bitReturned);

      switch( ntohs(ptr_response->type) )
      {
         case DNS_TYPE_A:
            g_PktPos += 4;
            printf("Skipping octet address\n");
            break;
         case DNS_TYPE_NS:
         case DNS_TYPE_MB:
         case DNS_TYPE_MD:
         case DNS_TYPE_MF:
         case DNS_TYPE_MG:
         case DNS_TYPE_MR:
         case DNS_TYPE_PTR:
         case DNS_TYPE_CNAME:
            bitReturned = parseString( g_PktPos, pktload );
            if( bitReturned != -1 )
            {
               bits[recvBits] = bitReturned;
               recvBits++;         
            }

            printf("Parsed response result = %d\n",bitReturned);
            break;
         case DNS_TYPE_SOA:
            bitReturned = parseString( g_PktPos, pktload );
            if( bitReturned != -1 )
            {
               bits[recvBits] = bitReturned;
               recvBits++;         
            }

            printf("Parsed response result = %d\n",bitReturned);
            bitReturned = parseString( g_PktPos, pktload );
            if( bitReturned != -1 )
            {
               bits[recvBits] = bitReturned;
               recvBits++;         
            }

            printf("Parsed response result = %d\n",bitReturned);
            g_PktPos += 20;
            break;
         case DNS_TYPE_MX:
            g_PktPos += 2;
            bitReturned = parseString( g_PktPos, pktload );
            if( bitReturned != -1 )
            {
               bits[recvBits] = bitReturned;
               recvBits++;         
            }

            printf("Parsed response result = %d\n",bitReturned);
            break;
         default:
            printf("Warning: Unknown DNS Response Type.\n");
            break;
      }

      printf("Stripped response %d\n\n",i);
   }

   printf("Parsing %d authoritative...\n",ntohs(ptr_hdr->auth_count));
   for( i = 0; i < ntohs(ptr_hdr->auth_count); i++)
   {
      printf("Stripping authoritative %d\n",i);
      bitReturned = parseString( g_PktPos, pktload );
      if( bitReturned != -1 )
      {
         bits[recvBits] = bitReturned;
         recvBits++;         
      }

      ptr_auth = (struct dns_authoritative*) g_PktPos;
      g_PktPos += DNS_AUTH_SIZE;
      printf("Parsed response result = %d\n",bitReturned);

      switch( ntohs(ptr_auth->type) )
      {
         case DNS_TYPE_A:
            g_PktPos += 4;
            printf("Skipping octet address\n");
            break;
         case DNS_TYPE_NS:
         case DNS_TYPE_MB:
         case DNS_TYPE_MD:
         case DNS_TYPE_MF:
         case DNS_TYPE_MG:
         case DNS_TYPE_MR:
         case DNS_TYPE_PTR:
         case DNS_TYPE_CNAME:
            bitReturned = parseString( g_PktPos, pktload );
            if( bitReturned != -1 )
            {
               bits[recvBits] = bitReturned;
               recvBits++;         
            }

            printf("Parsed response result = %d\n",bitReturned);
            break;
         case DNS_TYPE_SOA:
            bitReturned = parseString( g_PktPos, pktload );
            if( bitReturned != -1 )
            {
               bits[recvBits] = bitReturned;
               recvBits++;         
            }

            printf("Parsed response result = %d\n",bitReturned);
            bitReturned = parseString( g_PktPos, pktload );
            if( bitReturned != -1 )
            {
               bits[recvBits] = bitReturned;
               recvBits++;         
            }

            printf("Parsed response result = %d\n",bitReturned);
            g_PktPos += 20;
            break;
         case DNS_TYPE_MX:
            g_PktPos += 2;
            bitReturned = parseString( g_PktPos, pktload );
            if( bitReturned != -1 )
            {
               bits[recvBits] = bitReturned;
               recvBits++;         
            }

            printf("Parsed response result = %d\n",bitReturned);
            break;
         default:
            printf("Warning: Unknown DNS Response Type.\n");
            break;
      }

      printf("Stripped response %d\n\n",i);
   }

   printf("Parsing %d additional...\n",ntohs(ptr_hdr->add_count));
   for( i = 0; i < ntohs(ptr_hdr->add_count); i++)
   {
      printf("Stripping additional %d\n",i);
      bitReturned = parseString( g_PktPos, pktload );
      if( bitReturned != -1 )
      {
         bits[recvBits] = bitReturned;
         recvBits++;         
      }

      ptr_add = (struct dns_additional*) g_PktPos;
      g_PktPos += DNS_ADD_SIZE;
      printf("Parsed additional result = %d\n",bitReturned);

      switch( ntohs(ptr_add->type) )
      {
         case DNS_TYPE_A:
            g_PktPos += 4;
            printf("Skipping octet address\n");
            break;
         case DNS_TYPE_NS:
         case DNS_TYPE_MB:
         case DNS_TYPE_MD:
         case DNS_TYPE_MF:
         case DNS_TYPE_MG:
         case DNS_TYPE_MR:
         case DNS_TYPE_PTR:
         case DNS_TYPE_CNAME:
            bitReturned = parseString( g_PktPos, pktload );
            if( bitReturned != -1 )
            {
               bits[recvBits] = bitReturned;
               recvBits++;         
            }

            printf("Parsed additional result = %d\n",bitReturned);
            break;
         case DNS_TYPE_SOA:
            bitReturned = parseString( g_PktPos, pktload );
            if( bitReturned != -1 )
            {
               bits[recvBits] = bitReturned;
               recvBits++;         
            }

            printf("Parsed additional result = %d\n",bitReturned);
            bitReturned = parseString( g_PktPos, pktload );
            if( bitReturned != -1 )
            {
               bits[recvBits] = bitReturned;
               recvBits++;         
            }

            printf("Parsed additional result = %d\n",bitReturned);
            g_PktPos += 20;
            break;
         case DNS_TYPE_MX:
            g_PktPos += 2;
            bitReturned = parseString( g_PktPos, pktload );
            if( bitReturned != -1 )
            {
               bits[recvBits] = bitReturned;
               recvBits++;         
            }

            printf("Parsed additional result = %d\n",bitReturned);
            break;
         default:
            printf("Warning: Unknown DNS Additional Type.\n");
            break;
      }

      printf("Stripped additional %d\n\n",i);
   }

   printf("\nReceived bit stream is...\n");
   message = 0;
   for( i = 0; i < recvBits; i++ )
   {
      printf(".%d",bits[i]);
      message += ( pow(2,i) * bits[i] );
   }

   printf("\nWe received %d bits with a final message of %d\n\n",recvBits,message);
   return 0;
}

int parseString( char *string, char *data )
{
   int   notCompressed, offset;
   char  fqdn[MAX_DOMAIN_NAME];

   notCompressed = concatString( fqdn, string, data );
#ifdef _DEBUG
   printf("result = %s\n",fqdn);
#endif
   // add our new found fully qualified domain to our linked-list sorted by
   // offset if it exists in our linked-list then the function returns a 1
   offset = abs(data - string);
#ifdef _DEBUG
   printf("offset = %d, fqdn = %s\n", offset, fqdn );
#endif
   if( notCompressed )
   {
      // returns true if it already exists
      if( insertLabel( offset, fqdn,  &g_Labels) )
      {
         // it wasn't compressed and we already encountered this string
         return 1;
      }
   }
   else
   {
      insertLabel( offset, fqdn,  &g_Labels);

      // string was compressed
      return 0;
   }

   // string is a new occurrence
   return NaN;
}

int concatString( char *dest, char *cur, char *data )
{
   int lbl_length, offset;

   if( *cur != '\0' )
   {
      if( ((unsigned char)*cur) >= START_COMPRESSION )
      {
         // this is a short with the first two most significant bits being 11
#ifdef _DEBUG
         printf("Found pointer...\n");
         printf("offcode = %d minus code = %d\n",ntohs(*((unsigned short*)cur)), START_COMPRESSION << 8);
#endif
         offset = ntohs(*((unsigned short*)cur)) - (START_COMPRESSION << 8);
#ifdef _DEBUG
         printf("offset = %d\n",offset);
#endif
         // we found a compressed string (compression offset starts from 1)
         concatString(dest, data + offset, data );

         // continue parsing after poiinter
         g_PktPos = (cur+2);

         return 0;
      }else{
         lbl_length = *cur;
         strncpy( dest, (cur+1), lbl_length );
         dest[lbl_length] = '.';
         dest[lbl_length+1] = '\0';
#ifdef _DEBUG
         printf("label = %s\n", dest);
#endif
         // we're done with this label so continue parsing
         return concatString(&dest[lbl_length+1], cur + lbl_length + 1, data );
      }
   }

   // we reached the end of a string that was not compressed
   // zero term
   *(dest-1) = '\0';

   // continue parsing after terminator
   g_PktPos = (cur+1);

   return 1;
}

int insertLabel( int offset, char *label, struct LABELENTRY **head )
{
   int i, j;
   struct LABELENTRY *cur, *temp;

   if( *head == NULL )
   {
      *head = (struct LABELENTRY*)malloc( sizeof(struct LABELENTRY) );
      (*head)->next = NULL;
      strcpy((*head)->label, label);
      (*head)->offset = offset;
      return 0;
   }

   if( !strcasecmp(label, (*head)->label) )
   {
      return 1;
   }else
   {
      i = strlen(label)-1;
      j = strlen((*head)->label)-1;

      while( i > 0 && j > 0 )
      {
         if( label[i] != (*head)->label[j] )
            break;
         else if( label[i] == '.' )
            break;
         i--;
         j--;
      }

      if( label[i] == '.' )
         return 1;
   }

   cur = *head;
   while( cur->next != NULL && cur->next->offset < offset)
   {
      if( !strcasecmp(label, cur->next->label) )
      {
         return 1;
      }else
      {
         i = strlen(label)-1;
         j = strlen(cur->next->label)-1;

         while( i > 0 && j > 0 )
         {
            if( label[i] != cur->next->label[j] )
               break;
            else if( label[i] == '.' )
               break;
            i--;
            j--;
         }

         if( label[i] == '.' )
            return 1;
      }

      cur = cur->next;
   }

   temp = (struct LABELENTRY*)malloc( sizeof(struct LABELENTRY) );
   temp->next = cur->next;
   strcpy(temp->label, label);
   temp->offset = offset;
   cur->next = temp;

   return 0;
}

void initLabel( struct LABELENTRY **head )
{
   *head = NULL;
}

void deleteLabel( struct LABELENTRY *head )
{
   struct LABELENTRY *tmp;

   if( head == NULL )
      return;

   tmp = head->next;
   free( head );

   deleteLabel( tmp );
}

void outputHex(char * data, int length) {
   char buffer[17];
   int i;

   printf("====:  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  :===============\n");
   for (i = 0; i < length; i++) {
      if (i % 16 == 0) {
         printf("%.04x: ", i);
         bzero(buffer, 17);
      }

      printf("%02x ", (unsigned char) data[i]);
      if (isgraph(data[i])) {
         buffer[i % 16] = data[i];
      } else {
         buffer[i % 16] = '.';
      }
      if (i % 16 == 15) {
         printf(" %s\n", buffer);
      }
   }

   while (i++ % 16 != 0) {
      printf("   ");
   }

   printf(" %s\n", buffer);
}
