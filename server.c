/*
 * Steganography DNS Server
 * Author: Jeremy Shoemaker <jeremy@codingkoi.com>
 * 
 * This program acts as a DNS proxy server and hides messages in the
 * responses by altering the compression of domain name strings in the
 * original response message.
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <math.h>
#include <ctype.h>
#include <stdlib.h>
#include <netdb.h>

#define MAX_DOMAIN_LENGTH     256      /* RFC 1034, Section 3.1 */
#define MAX_LABEL_LENGTH      64       /* RFC 1034, Section 3.1 */
#define START_COMPRESSION     0xc0     /* RFC 1035, Section 4.1.4 */
#define MAX_CONFIG_STRING     256
#define MAX_TCP_PACKET        1024
#define MAX_UDP_PACKET        512

/* configuration information */
struct configinfo {
   char hostname[MAX_DOMAIN_LENGTH];
   char protocol[MAX_CONFIG_STRING];
   unsigned long serverip;
   unsigned short serverport;
   unsigned short listenport;
   unsigned char message;
};

int load_config_file(char * filename, struct configinfo *config);

/* dns network structures */
struct dns_header {
   unsigned short id;         /* id */
   unsigned char rd  :1;      /* recursion desired */
   unsigned char tc  :1;      /* truncated message */
   unsigned char aa  :1;      /* authorative answer */
   unsigned char opcode :4;      /* purpose of message */
   unsigned char qr  :1;      /* query/response flag */
   
   unsigned char rcode  :4;      /* response code */
   unsigned char cd  :1;      /* checking disabled */
   unsigned char ad  :1;      /* authenticated data */
   unsigned char res :1;      /* reserved */
   unsigned char ra  :1;      /* recursion available */

   unsigned short q_count;    /* question count */
   unsigned short ans_count;  /* answer count */
   unsigned short auth_count; /* authority count */
   unsigned short add_count;  /* resource count */
};

struct dns_packet {
   unsigned short length;
   struct dns_header hdr;
   char data[1];
};

struct dns_question {
   unsigned short qtype;
   unsigned short qclass;
};

#define RTYPE_A               1 /* a host address */
#define RTYPE_NS              2 /* an authoritative name server */
#define RTYPE_MD              3 /* a mail destination (Obsolete - use MX) */
#define RTYPE_MF              4 /* a mail forwarder (Obsolete - use MX) */
#define RTYPE_CNAME           5 /* the canonical name for an alias */
#define RTYPE_SOA             6 /* marks the start of a zone of authority */
#define RTYPE_MB              7 /* a mailbox domain name (EXPERIMENTAL) */
#define RTYPE_MG              8 /* a mail group member (EXPERIMENTAL) */
#define RTYPE_MR              9 /* a mail rename domain name (EXPERIMENTAL) */
#define RTYPE_NULL            10 /* a null RR (EXPERIMENTAL) */
#define RTYPE_WKS             11 /* a well known service description */
#define RTYPE_PTR             12 /* a domain name pointer */
#define RTYPE_HINFO           13 /* host information */
#define RTYPE_MINFO           14 /* mailbox or mail list information */
#define RTYPE_MX              15 /* mail exchange */
#define RTYPE_TXT             16 /* text strings */

struct dns_resource {
   unsigned short rtype;
   unsigned short rclass;
   unsigned int ttl;
   unsigned short rdlength;
   char data[1];
};

int dns_server_udp(struct configinfo * config);
int dns_server_tcp(struct configinfo * config);
int read_query_udp(int fd, char * pkt, struct sockaddr_in * from);
int read_query_tcp(int fd, char * pkt);
int query_dns_udp(char * pkt, struct configinfo * config);
int query_dns_tcp(char * pkt, struct configinfo * config);
int send_response_udp(int fd, char * pkt, struct sockaddr_in * from);
int send_response_tcp(int fd, char * pkt);
void output_hex(char * data, int length);

/* structures to store meta data about domain name strings */
/* list head */
struct name_list {
   struct name_meta * next;
};
/* list node */
struct name_meta {
   struct name_meta * next;   /* pointer to the next item */
   int offset;                /* the original offset */
   int delta;                 /* the delta to the new offset */
   char * name;
};

struct name_list * new_list();
struct name_meta * add_item(struct name_list * list, int offset, int delta, char * name);
int del_list(struct name_list * list);
void print_name_list(struct name_list * list, char * pkt);

/* response alteration fucntions */
void alter_response(char * pkt, struct configinfo * config);
int bit(int byte, int index);

int main(int argc, char ** argv) {
   struct configinfo config;

   /* read the config file */
   if (load_config_file("server.conf", &config) < 0) {
      perror(argv[0]);
      return -1;
   }

   /* run the correct version of the server based on protocol */
   if (strcasecmp(config.protocol, "tcp") == 0) {
      if (0 > dns_server_tcp(&config)) {
         perror(argv[0]);
         return -1;
      }
   }
   else if (strcasecmp(config.protocol, "udp") == 0) {
      if (0 > dns_server_udp(&config)) {
         perror(argv[0]);
         return -1;
      }
   }
   else {
      fprintf(stderr, "%s: Unknown network protocol\n", argv[0]);
      return -1;
   }
   return 0;
}

#define ZERO_TERM(x)  x[strlen(x) - 1] = '\0'
/* read the configuration file */
int load_config_file(char * filename, struct configinfo * config) {
   FILE *fp;
   char buffer[MAX_CONFIG_STRING];
   struct hostent *host;

   if ((fp = fopen(filename, "r")) == NULL) {
      return -1;
   }
   /* read the hostname */
   if (!fgets(config->hostname, MAX_CONFIG_STRING, fp)) {
      return -1;
   }
   ZERO_TERM(config->hostname);
   /* read the server port number */
   if (!fgets(buffer, MAX_CONFIG_STRING, fp)) {
      return -1;
   }
   ZERO_TERM(buffer);
   config->serverport = atoi(buffer);
   /* read the listen port number */
   if (!fgets(buffer, MAX_CONFIG_STRING, fp)) {
      return -1;
   }
   ZERO_TERM(buffer);
   config->listenport = atoi(buffer);
   /* read the protocol */
   if (!fgets(config->protocol, MAX_CONFIG_STRING, fp)) {
      return -1;
   }
   ZERO_TERM(config->protocol);
   /* read the message */
   if (!fgets(buffer, MAX_CONFIG_STRING, fp)) {
      return -1;
   }
   ZERO_TERM(buffer);
   config->message = atoi(buffer);
   /* get the ip from the hostname */
   if (!(host = gethostbyname(config->hostname))) {
      return -1;
   }
   memcpy(&config->serverip, host->h_addr, host->h_length);
   return 1;
}

/* simple function to return the selected bit from a byte */
int bit(int byte, int index) {
   #if 0
   return (rand() % 2);  /* for testing */
   #endif
   return (byte & (int)pow(2, index)) >> index; 
}

/* determine if the string is compressed or not */
int is_compressed(char * str) {
   /* if the string is not compressed it will be null terminated */
   unsigned char *p;
   p = (unsigned char *) str;
   while (*p) {
      if (*p >= 0xc0) {
         /* found the first byte of a pointer */
         return 1;
      }
      p++;
   }
   return 0;
}

/* determine the length of a name field
 * this doesn't follow pointers, just returns length of the actual field */
int name_len(char * str) {
   unsigned char *p;
   int count = 1;
   p = (unsigned char *) str;
   while (*p) {
      if (*p >= 0xc0) {
         /* count the next byte and return the value */
         return count + 1;
      }
      count++;
      p++;
   }
   return count;
}

/* get the actual FQDN, following pointers
 * note: this function is not thread safe, but I'm being lazy */
char * full_dns_name(char * name, char * pkt) {
   static char full_name[MAX_DOMAIN_LENGTH];
   unsigned char * p = (unsigned char *) name;
   int i = 0, p_value;
   /* the root name will end with a null byte so loop until then */
   while(*p && i < MAX_DOMAIN_LENGTH) {
      /* check for a pointer */
      if (*p >= START_COMPRESSION) {
         /* follow the pointer */
         p_value = (*p ^ START_COMPRESSION) + *(p + 1);
         p = (unsigned char *)pkt + p_value + 2;
      }
      full_name[i++] = *(p++);
   }
   full_name[i] = '\0';
   return full_name;
}

/* returns a printable version of the domain name name */
char * printable_name(char * name) {
   static char print_name[MAX_DOMAIN_LENGTH];
   unsigned char *p = (unsigned char *) name;
   int i = 0;
   while (*p && i < MAX_DOMAIN_LENGTH) {
      if (*p >= START_COMPRESSION) {
         break;
      }
      if (isgraph(*p)) {
         print_name[i++] = *(p++);
      }
      else {
         print_name[i++] = '.';
         p++;
      }
   }
   print_name[i] = '\0';
   return print_name;
}

/* get the value of a domain name pointer */
int pointer_value(char * name) {
   unsigned char *p;
   p = (unsigned char *) name;
   while (*p) {
      if (*p >= START_COMPRESSION) {
         return (*p ^ START_COMPRESSION) + *(p + 1);
      }
      p++;
   }
   return -1;
}

/* update a domain name pointer value */
int update_pointer(struct name_meta * name) {
   int value;
   unsigned char * p;
   struct name_meta * node;
   if (!name) {
      return -1;
   }
   /* make sure there is a pointer */
   if (!is_compressed(name->name)) {
      return -1;
   }
   /* find the pointer in the string */
   p = (unsigned char *) name->name;
   while (*p) {
      if (*p >= START_COMPRESSION) {
         value = (*p ^ START_COMPRESSION) + *(p + 1);
         break;
      }
      p++;
   }
   /* find the new value */
   node = name->next;
   while (node) {
      if (node->delta == 0) {
         return value;
      }
      if (value >= node->offset && value <= node->offset + name_len(node->name)) {
         /* we found the string, now update the offset */
         value += node->delta;
         *p = (value >> 8) | START_COMPRESSION;
         *(p + 1) = value % 256;
         return value;
      }
      node = node->next;
   }
   return -2;
}

/* store the bit into the new packet at write, return the new length */
int encode_bit(char * read, char * write, char * pkt, int bit) {
   int compressed, length = 0;
   char * fullname;
   /* check to see if it can be altered (i.e. is it compressed) */
   compressed = is_compressed(read);   
   if (compressed) {
      printf("Name is compressed\n");
      /* if so, then alter the compression based on the next message bit */
      /* 1... remove the compression from the name field in the response */
      if (bit) {
         printf("Encoding bit: 1\n");
         fullname = full_dns_name(read, pkt);
         length = name_len(fullname);
         memcpy(write, fullname, length);
      }
      /* 0... leave the compression alone */
   }
   if (!compressed || !bit) {
      /* copy the packet unaltered */
      length = name_len(read);
      memcpy(write, read, length);
      if (!compressed) {
         printf("Not compressed, skipping\n");
         /* negative length means the bit wasn't encoded */
         length = -length;
      }
      else {
         printf("Encoding bit: 0\n");
      }
   }
   /* add the name to the name list */
   return length;
}

/* update the pointers in each of the domain names in the list */
void update_domain_pointers(struct name_list * list, char * pkt) {
   struct name_meta * node;
   int index = 0;
   node = list->next;
   while(node) {
      printf(";;; Domain Name %d\n", (index++) + 1);
      printf("Original Offset: 0x%.02x\n", node->offset);
      printf("Delta Offset: %d (0x%.02x)\n", node->delta, 
         node->offset + node->delta);
      printf("Length: %d\n", name_len(node->name));
      if (is_compressed(node->name)) {
         printf("Pointer Value: 0x%.02x\n", pointer_value(node->name));
         printf("Updated Value: 0x%.02x\n", update_pointer(node));
      }
      printf("Name: %s\n\n", printable_name(full_dns_name(node->name, pkt)));
      node = node->next;
   }
}

/* alter the response to hide the message bits 
 * this function assumes that there is a short at the beginning
 * containing the lenght of the packet, like when using TCP */
void alter_response(char * pkt, struct configinfo * config) {
   int i, bi, length, res_count, offset, delta;
   unsigned int message;
   char new_pkt[512];
   char *read_point, *write_point, *base;
   struct dns_packet * pack, * new_pack;
   struct dns_resource * response, * new_res;
   struct name_list * names;

   /* get the message handy */
   message = config->message;
   /* create the name list */
   names = new_list();
   /* point the dns_packet structs at the packets for accessing the
    * length fields later */
   pack = (struct dns_packet *) pkt;
   new_pack = (struct dns_packet *) new_pkt;
   /* get past the questions */
   read_point = pack->data;
   res_count = ntohs(pack->hdr.q_count);
   for (i = 0; i < res_count; i++) {
      offset = read_point - pkt - 2;
      /* questions don't change so delta is zero and the pointer is to the original data */
      add_item(names, offset, 0, read_point);
      read_point += (name_len(read_point) + sizeof(struct dns_question));
   }
   /* copy everything up to this point */
   memcpy(new_pkt, pkt, (read_point - pkt));
   write_point = new_pkt + (read_point - pkt);

   /* set the bit index to zero */
   bi = 0;
   /* for each resource in the reply... */
   res_count = ntohs(pack->hdr.ans_count) + ntohs(pack->hdr.auth_count) +
      ntohs(pack->hdr.add_count);
   for (i = 0; i < res_count; i++) {
      printf("Resource %d\n", i + 1);
      printf("Full name: %s\n", printable_name(full_dns_name(read_point, pkt)));
      offset = read_point - pkt - 2;
      delta = (write_point - new_pkt - 2) - offset;

      /* encode the next bit of the message */
      length = encode_bit(read_point, write_point, pkt, bit(message, bi));
      add_item(names, offset, delta, write_point);

      /* check to see that the bit was encoded and advance bit index */
      if (length > 0) {
         bi++;
      }

      /* advance the read/write points to the next record */
      write_point += abs(length);
      read_point += name_len(read_point);
      
      /* process the rest of the resource */
      base = read_point; /* mark where we are so we can copy later */
      response = (struct dns_resource *) read_point;
      new_res = (struct dns_resource *) write_point;
      #if 0
      read_point = response->data + ntohs(response->rdlength);
      #endif
      /* copy the resource structure to the new packet */
      memcpy(write_point, read_point, sizeof(struct dns_resource) - 1);
      /* move the read/write pointers up to the RDATA field */
      read_point = response->data;
      write_point = new_res->data;
      /* calculate the offsets */
      offset = read_point - pkt - 2;
      delta = (write_point - new_pkt - 2) - offset;
      /* check for domain names in the RDATA field of the resource */
      switch (ntohs(response->rtype)) {
         /* this type holds a single domain name after a short in its RDATA */
         case RTYPE_MX: {
            /* copy the short to the new packet */
            memcpy(write_point, read_point, sizeof(short));
            write_point += sizeof(short);
            read_point += sizeof(short);
         } /* fall through to the next part */

         /* these types hold a single domain name in their RDATA field */
         case RTYPE_CNAME:
         case RTYPE_NS:
         case RTYPE_MB:
         case RTYPE_MD:
         case RTYPE_MF:
         case RTYPE_MG:
         case RTYPE_MR:
         case RTYPE_PTR: {
            /* encode data into the domain name if possible */
            length = encode_bit(read_point, write_point, pkt, bit(message, bi)); 
            /* check to see that the bit was encoded and advance bit index */
            if (length > 0) {
               bi++;
            }
            /* add the domain name to the list */
            add_item(names, offset, delta, write_point);
            /* advance the read/write points to the end of the record */
            write_point += abs(length);
            read_point += name_len(read_point);
         }
         break;

         /* these types hold two domain names sequentially in their RDATA */
         case RTYPE_MINFO:
         case RTYPE_SOA: {
            /* encode data into the domain name if possible */
            length = encode_bit(read_point, write_point, pkt, bit(message, bi)); 
            /* check to see that the bit was encoded and advance bit index */
            if (length > 0) {
               bi++;
            }
            /* add the domain name to the list */
            add_item(names, offset, delta, write_point);
            /* advance the read/write points to the end of the record */
            write_point += abs(length);
            read_point += name_len(read_point);

            /* now the next name, first calculate the offsets */
            length = name_len(new_res->data);
            offset += length;
            delta += length - offset;

            /* encode data into the domain name if possible */
            length = encode_bit(read_point, write_point, pkt, bit(message, bi)); 
            /* check to see that the bit was encoded and advance bit index */
            if (length > 0) {
               bi++;
            }
            /* add the domain name to the list */
            add_item(names, offset, delta, write_point);
            /* advance the read/write points to the end of the record */
            write_point += abs(length);
            /* calculate the amount left to copy */
            length = ntohs(response->rdlength) - name_len(read_point);
            read_point += name_len(read_point);
            /* copy what's left */
            memcpy(write_point, read_point, length);
            /* advance the pointers */
            write_point += length;
            read_point += length;
         }
         break;
         default: {
            /* just copy rdlength bytes to the new message */
            length = ntohs(response->rdlength);
            memcpy(write_point, read_point, length);
            write_point += length;
            read_point += length;
         }
         /* do nothing */
      }
      #if 0
      /* copy to the new packet */
      memcpy(write_point, base, (read_point - base));
      write_point += (read_point - base);
      #endif
   }
   printf("\n Updating domain name pointers...\n");
   /* update the domain name pointers and delete the name list */
   update_domain_pointers(names, new_pkt);
   del_list(names);
   /* recalculate the length of the message and update the packet accordingly */
   new_pack->length = htons(write_point - new_pkt - 2);
   memcpy(pkt, new_pkt, ntohs(new_pack->length) + 2);
   printf("New Packet Length: %d\n", ntohs(new_pack->length));
   output_hex(new_pkt + 2, ntohs(new_pack->length) - 2);
}

void output_hex(char * data, int length) {
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

/* ----  LINKED LIST FUNCTIONS  ---- */

struct name_list * new_list() {
   struct name_list *list;
   list = (struct name_list *) malloc(sizeof(struct name_list));
   list->next = NULL;
   return list;
}

struct name_meta * add_item(struct name_list * list, int offset, int delta, char * name) {
   struct name_meta * node;
   node = list->next;
   list->next = (struct name_meta *) malloc(sizeof(struct name_meta));
   list->next->next = node;
   /* store the data */
   node = list->next;
   node->offset = offset;
   node->delta = delta;
   node->name = name;
   return node;
}

int del_list(struct name_list * list) {
   struct name_meta * node, * temp;
   node = list->next;
   while (node) {
      temp = node->next;
      free(node);
      node = temp;
   }
   free(list);
   return 1;
}

/* ----  NETWORK CODE  ---- */

int dns_server_udp(struct configinfo * config) {
   char packet[MAX_UDP_PACKET + 2];
   int client;
   struct sockaddr_in sa, from;

   /* create the client socket */
   client = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
   if (-1 == client) {
      return -1;
   }
   /* bind the client socket to the listenport */
   bzero(&sa, sizeof(sa));
   sa.sin_addr.s_addr = INADDR_ANY;
   sa.sin_port = htons(config->listenport);
   printf("Binding on local UDP port %d...\n", config->listenport);
   if (-1 == bind(client, (struct sockaddr *) &sa, sizeof(sa))) {
      return -1;
   }

   while (1) {
      /* wait for a query from the client */
      printf("Waiting for message...\n");
      if (0 > read_query_udp(client, packet, &from)) {
         return -1;
      }
      printf("Message received...\n");
      /* forward the query to the real server and get response */
      if (0 > query_dns_udp(packet, config)) {
         return -1;
      }
      /* encode the data into the response packet */
      alter_response(packet, config);
      /* send the altered response to the client */
      if (0 > send_response_udp(client, packet, &from)) {
         return -1;
      }
      printf("Hidden message: %d\n", config->message);
   }
   return 1;
}

int dns_server_tcp(struct configinfo * config) {
   char packet[MAX_TCP_PACKET];
   int client, cfd;
   struct sockaddr_in sa;

   /* create the client socket */
   client = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
   if (-1 == client) {
      return -1;
   }
   /* bind the client socket to the listenport */
   bzero(&sa, sizeof(sa));
   sa.sin_family = AF_INET;
   sa.sin_port = htons(config->listenport);
   sa.sin_addr.s_addr = htons(INADDR_ANY);
   printf("Binding on local TCP port %d...\n", config->listenport);
   if (-1 == bind(client, (struct sockaddr *) &sa, sizeof(sa))) {
      return -1;
   }
   /* set the client socket to a listening socket */
   if (-1 == listen(client, 10)) {
      return -1;
   }

   while (1) {
      /* wait for a query from the client */
      printf("Waiting for connection...\n");
      cfd = accept(client, NULL, NULL);
      if (0 > cfd) {
         return -1;
      }
      printf("Connection established...\n");
      /* read the query from the client */
      if (0 > read_query_tcp(cfd, packet)) {
         return -1;
      }
      /* forward the query to the real server and get response */
      if (0 > query_dns_tcp(packet, config)) {
         return -1;
      }
      /* encode the data into the response packet */
      alter_response(packet, config);
      /* send the altered response to the client */
      if (0 > send_response_tcp(cfd, packet)) {
         return -1;
      }
      printf("Hidden message: %d\n", config->message);
   }
   return 1;
}

/* read_query(fd, *pkt)
 * reads an incoming query from the provided file descriptor and stores it
 * in the memory pointed to by pkt
 * 
 * returns 1 on success, -1 on error
 */
int read_query_udp(int fd, char * pkt, struct sockaddr_in * from) {
   int result;
   char * offset;
   unsigned int fromlen;
   struct dns_packet *pack;

   /* udp dns messages don't have a length before them
    * so we'll add it later so the alter function can use it */
   pack = (struct dns_packet *) pkt;
   offset = pkt + 2;
   /* read the message */
   bzero(pkt, MAX_UDP_PACKET);
   bzero(from, sizeof(struct sockaddr_in));
   fromlen = (unsigned int) sizeof(struct sockaddr_in);
   result = recvfrom(fd, offset, MAX_UDP_PACKET, 0,
      (struct sockaddr *) from, &fromlen);
   if (0 > result) {
      return -1;
   }
   /* set the length field for the alter function */
   printf("Client request length, %d bytes\n", result);
   pack->length = htons(result);
   return 1;
}

int read_query_tcp(int fd, char * pkt) {
   int result;
   char * offset;
   unsigned short length;
   struct dns_packet *pack;

   /* read the first two bytes from the client */
   bzero(pkt, MAX_TCP_PACKET);
   result = read(fd, pkt, 2);
   if (0 > result) {
      return -1;
   }
   /* read the length */
   pack = (struct dns_packet *) pkt;
   length = ntohs(pack->length);
   printf("Client request length, %d bytes\n", length);
   /* read the rest of the packet */
   offset = pkt + 2;
   result = read(fd, offset, length);
   if (0 > result) {
      return -1;
   }
   return 1;
}

/* query_dns(*pkt)
 * takes the provided packet and forwards it to the DNS server then
 * reads the response and stores it back into the memory pointed to by pkt
 *
 * returns 1 on success, -1 on error
 */
int query_dns_udp(char * pkt, struct configinfo * config) {
   int sock, length, result, fromlen;
   struct sockaddr_in sa, from;
   struct dns_packet * pack;
   /* query the real server for the dns packet */
   pack = (struct dns_packet *) pkt;
   length = ntohs(pack->length);
   printf("Querying DNS server %s:%d...\n",
      config->hostname, config->serverport);
   sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
   if (-1 == sock) {
      return -1;
   }
   sa.sin_family = AF_INET;
   sa.sin_addr.s_addr = config->serverip;
   sa.sin_port = htons(config->serverport);
   printf("Message Length: %d bytes\n", length);
   output_hex(pkt + 2, length);
   printf("Sending message...\n");

   result = sendto(sock, pkt + 2, length, 0,
      (struct sockaddr *) &sa, sizeof(struct sockaddr_in));
   if (0 > result) {
      return -1;
   }
   /* receive the response */
   bzero(pkt, MAX_UDP_PACKET);
   bzero(&from, sizeof(struct sockaddr_in));
   fromlen = sizeof(struct sockaddr_in);
   printf("Waiting reply...\n");
   result = recvfrom(sock, pkt + 2, MAX_UDP_PACKET, 0,
      (struct sockaddr *) &from, (unsigned int *) &fromlen);
   if (0 > result) {
      return -1;
   }
   printf("Received reply... %d bytes\n", result);
   pack->length = htons(result);
   
   output_hex(pkt + 2, result);
   return 1;
}

int query_dns_tcp(char * pkt, struct configinfo * config) {
   int sock, length, result, fromlen;
   struct sockaddr_in sa, from;
   struct dns_packet * pack;
   /* query the real server for the dns packet */
   pack = (struct dns_packet *) pkt;
   length = htons(pack->length);
   printf("Querying DNS server %s:%d...\n", 
      config->hostname, config->serverport);
   sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
   if (-1 == sock) {
      return -1;
   }
   sa.sin_family = AF_INET;
   sa.sin_addr.s_addr = config->serverip;
   sa.sin_port = htons(config->serverport);
   printf("Message Length: %d\n", length);
   output_hex(pkt + 2, length);
   printf("Sending message...\n");
   if (-1 == connect(sock, (struct sockaddr *) &sa, sizeof(struct sockaddr_in))) {
      return -1;
   }

   result = write(sock, pkt, (length + 2));
   if (result != (length + 2)) {
      return -1;
   }
   /* receive the response */
   bzero(pkt, MAX_TCP_PACKET);
   bzero(&from, sizeof(from));
   printf("Waiting reply...\n");
   fromlen = sizeof(from);
   result = read(sock, pkt, MAX_TCP_PACKET);
   if (0 > result) {
      return -1;
   }
   printf("Received reply... %d bytes\n", result);
   
   output_hex(pkt + 2, result - 2);
   return 1;
}

int send_response_udp(int fd, char * pkt, struct sockaddr_in * from) {
   int result, length;
   struct dns_packet * pack;
   /* send the altered packet to the client */
   pack = (struct dns_packet *) pkt;
   length = ntohs(pack->length);
   result = sendto(fd, pkt + 2, length, 0,
      (struct sockaddr *) from, sizeof(struct sockaddr_in));
   if (0 > result) {
      perror("Problem!");
      return -1;
   }
   return 1;
}

int send_response_tcp(int fd, char * pkt) {
   int result;
   struct dns_packet * pack;
   /* send the altered packet to the client */
   pack = (struct dns_packet *) pkt;
   result = write(fd, pkt, (ntohs(pack->length) + 2));
   if (0 > result) {
      return -1;
   }
   return 1;
}

