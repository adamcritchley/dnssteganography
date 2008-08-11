#ifndef CLIENT_H
#define CLIENT_H

#define MAKE_TRANSID(a,b) (((a) << 8) | (b))
#define GET_INDEX(a) ((a) >> 8)
#define GET_VALUE(a) ((a) & 0xFF)

#define DNS_HEADER_SIZE   12
#define DNS_QUESTION_SIZE 4
#define DNS_RESPONSE_SIZE 10
#define DNS_AUTH_SIZE     DNS_RESPONSE_SIZE
#define DNS_ADD_SIZE      DNS_RESPONSE_SIZE

struct dns_header {
	unsigned short id;			/* id */
#ifdef LITTLE_ENDIAN
	unsigned char qr	:1;		/* query/response flag */
	unsigned char opcode	:4;		/* purpose of message */
	unsigned char aa	:1;		/* authorative answer */
	unsigned char tc	:1;		/* truncated message */
	unsigned char rd	:1;		/* recursion desired */

	unsigned char ra	:1;		/* recursion available */
	unsigned char res	:1;		/* reserved */
	unsigned char ad	:1;		/* authenticated data */
	unsigned char cd	:1;		/* checking disabled */
	unsigned char rcode	:4;		/* response code */
#else
	unsigned char rd	:1;		/* recursion desired */
	unsigned char tc	:1;		/* truncated message */
	unsigned char aa	:1;		/* authorative answer */
	unsigned char opcode	:4;		/* purpose of message */
	unsigned char qr	:1;		/* query/response flag */

	unsigned char rcode	:4;		/* response code */
	unsigned char cd	:1;		/* checking disabled */
	unsigned char ad	:1;		/* authenticated data */
	unsigned char res	:1;		/* reserved */
	unsigned char ra	:1;		/* recursion available */

#endif	
	unsigned short q_count;		/* question count */
	unsigned short ans_count;	/* answer count */
	unsigned short auth_count;	/* authority count */
	unsigned short add_count;	/* resource count */
};

struct dns_question {
	unsigned short qtype;
	unsigned short qclass;
};

struct dns_response{
	unsigned short type;
	unsigned short rclass;
	unsigned long  ttl;
	unsigned short datalength;
};

#define dns_authoritative dns_response
#define dns_additional dns_response

#endif
