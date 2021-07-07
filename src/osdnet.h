/* OSDNET.H - OS Dependent Network definitions
*/
/* $Id: osdnet.h,v 2.5 2001/11/19 10:34:01 klh Exp $
*/
/*  Copyright © 1999, 2001 Kenneth L. Harrenstien
**  All Rights Reserved
**
**  This file is part of the KLH10 Distribution.  Use, modification, and
**  re-distribution is permitted subject to the terms in the file
**  named "LICENSE", which contains the full text of the legal notices
**  and should always accompany this Distribution.
**
**  This software is provided "AS IS" with NO WARRANTY OF ANY KIND.
**
**  This notice (including the copyright and warranty disclaimer)
**  must be included in all copies or derivations of this software.
*/
/*
 * $Log: osdnet.h,v $
 * Revision 2.5  2001/11/19 10:34:01  klh
 * Solaris port fixups.  Removed conflicting ether/arp includes.
 *
 * Revision 2.4  2001/11/10 21:28:59  klh
 * Final 2.0 distribution checkin
 *
 */

/* XXX Eventually standardize facility names to use OSDNET_ or OSN_
 * and remove KLH10_ references.
 */

#ifndef OSDNET_INCLUDED
#define OSDNET_INCLUDED 1

#include "klh10.h"	/* Ensure have config params */

/* Determine whether only doing IP stuff, or if all ethernet interface
 * capabilities are desired.
 */
#ifndef OSN_USE_IPONLY
# define OSN_USE_IPONLY 0	/* Default is to include everything */
#endif


/* Ensure this is defined in order to get right stuff for DECOSF */
#define _SOCKADDR_LEN

#if CENV_SYS_UNIX
# include <unistd.h>		/* Standard Unix syscalls */
# include <errno.h>
# include <fcntl.h>		/* For O_RDWR */
# include <sys/types.h>
# include <sys/ioctl.h>
# include <sys/socket.h>
# include <net/if.h>
# include <netinet/in.h>	/* For ntohl, htonl, in_addr */
# include <netinet/if_ether.h>	/* Semi-std defs for:
				   ether_addr, ether_header, ether_arp */

# define ossock_t int		/* No typedef until code revised */
#endif /* CENV_SYS_UNIX */

#if HAVE_NET_IF_TUN_H && OSN_USE_IPONLY
# include <net/if_tun.h>
# define KLH10_NET_TUN	1
#endif
#if HAVE_NET_IF_TAP_H
# include <net/if_tap.h>
# define KLH10_NET_TAP	1
#endif
#if HAVE_LINUX_IF_TUN_H
# include <linux/if_tun.h>
# define KLH10_NET_TUN	1
# define KLH10_NET_TAP	1
#endif
#if HAVE_LINUX_IF_PACKET_H
# include <linux/if_packet.h>	/* For struct sockaddr_ll with AF_PACKET */
#endif
# if HAVE_NET_IF_DL_H
# include <net/if_dl.h>		/* For sockaddr_dl with AF_LINK */
# include <net/if_types.h>	/* For IFT_ETHER */
#endif
#if HAVE_LIBPCAP
# undef BPF_MAJOR_VERSION	/* some stupid linux header defines this:
				 * <linux_filter.h> included from
				 * <linux/if_tun,h>; only in SOME versions.
				 */
# include <pcap/pcap.h>
# include <pcap/bpf.h>
# define KLH10_NET_PCAP 1
#endif
#if HAVE_GETIFADDRS
# include <ifaddrs.h>
#endif
#if !defined(KLH10_NET_BRIDGE) && KLH10_NET_TAP && (CENV_SYS_XBSD || CENV_SYS_LINUX)
# define KLH10_NET_BRIDGE 1	/* Use bridge if possible, unless disabled */
#endif

#if HAVE_NET_NIT_H
# define KLH10_NET_NIT	1
# include <sys/stropts.h>	/* For stream operations */
# include <net/nit.h>		/* For NIT */
# include <net/nit_if.h>	/* For NIT */
# include <net/nit_pf.h>	/* For packet filtering */
# include <net/packetfilt.h>	/* For packet filtering */

#elif HAVE_SYS_DLPI_H
# define KLH10_NET_DLPI	1
# include <sys/sockio.h>
# include <sys/stropts.h>
# include <sys/dlpi.h>
# include <sys/pfmod.h>		/* For packet filtering */
# include <arpa/inet.h>

#endif

/* Set KLH10_NET_* values to default, if not set yet.
 */
#ifndef  KLH10_NET_NIT	/* SunOS Network Interface Tap */
# define KLH10_NET_NIT 0
#endif
#ifndef  KLH10_NET_DLPI	/* Solaris Data Link Provider Interface */
# define KLH10_NET_DLPI 0
#endif
#ifndef  KLH10_NET_TUN	/* IP Tunnel device */
# define KLH10_NET_TUN 0
#endif
#ifndef  KLH10_NET_TAP /* Ethernet Tunnel device */
# define KLH10_NET_TAP 0
#endif
#ifndef  KLH10_NET_BRIDGE /* Bridge (used with an Ethernet tunnel) */
# define KLH10_NET_BRIDGE 0
#endif
#ifndef  KLH10_NET_PCAP	/* pretty generic libpcap interface */
# define KLH10_NET_PCAP 0
#endif
#ifndef FALSE
# define FALSE 0
#endif
#ifndef TRUE
# define TRUE 1
#endif

/* Additional definitions that need to be shared by both
   osdnet.c and its including module (dpni20 or dpimp).
   XXX This location and the names are temporary until the OSDNET API is
   made more complete and opaque.
*/

/* Packet filter definitions */

/* IP packet byte offsets, network order */
#define IPBOFF_SRC  (3*4)	/* Byte offset to start of IP source addr */
#define IPBOFF_DEST (4*4)	/* Byte offset to start of IP dest addr */

/* Packet byte offsets for interesting fields (in network order) */
#define PKBOFF_EDEST 0		/* 1st shortword of Ethernet destination */
#define PKBOFF_ETYPE 12		/* Shortwd offset to Ethernet packet type */
#define PKBOFF_SAPS  14		/* Shortwd offset to DSAP/SSAP if 802.3 */
#define PKBOFF_IPDEST (14+IPBOFF_DEST)	/* 1st byte of IP dest  */

/* Packet shortword offsets for interesting fields */
#define PKSWOFF_EDEST 0		/* 1st shortword of Ethernet destination */
#define PKSWOFF_ETYPE 6		/* Shortwd offset to Ethernet packet type */
#define PKSWOFF_SAPS  7		/* Shortwd offset to DSAP/SSAP if 802.3 */
#define PKSWOFF_IPDEST (7+(IPBOFF_DEST/2))	/* 1st (high) sw of IP dest  */


#ifdef SIOCGARP
# define NETIF_HAS_ARPIOCTL 1
#else
# define NETIF_HAS_ARPIOCTL 0
#endif

#if !HAVE_LIBPCAP && !HAVE_GETIFADDRS
#error "Sorry, can't lookup ethernet interfaces without getifaddrs(3) or libpcap"
#endif

/* Interface table entry.
   This is needed to provide a more generic format that can
   be used regardless of the actual system being compiled for.
   Note re interface name: kernel code (at least in FreeBSD) is schizo
   as to whether it is always null-terminated or not.  Names shorter
   than IFNAMSIZ chars are always terminated, but in at least some places
   the kernel allows the name to occupy a full IFNAMSIZ chars with no
   terminating null byte, so the format here must allow for that.
 */
struct ifent {
	char ife_name[IFNAMSIZ+1];	/* +1 so always null-terminated */
	int  ife_flags;			/* IFF_ flags */
	int  ife_mtu;			/* MTU (not really used) */
	int  ife_gotip4;		/* TRUE if IPv4 addr set */
	union {
	    struct in_addr ifeu_ia;
	    unsigned char ifeu_chr[4];
	} ife_uip;			/* IPv4 address */
	union {
	    struct in_addr ifeu_ia;
	    unsigned char ifeu_chr[4];
	} ife_nm;			/* netmask */
	int ife_gotea;			/* TRUE if E/N addr set */
	unsigned char ife_ea[6];	/* E/N address */
};
#define ife_ipia  ife_uip.ifeu_ia		/* IP address as in_addr */
#define ife_ipint ife_uip.ifeu_ia.s_addr	/* IP address as integer */
#define ife_ipchr ife_uip.ifeu_chr		/* IP address as bytes */

#define ife_nmia  ife_nm.ifeu_ia		/* netmask as in_addr */
#define ife_nmint ife_nm.ifeu_ia.s_addr		/* netmask as integer */
#define ife_nmchr ife_nm.ifeu_chr		/* netmask as bytes */

/* Option arguments to iftab_init */
#define IFTAB_IPS	0x1	/* Accept IP-bound interface */
#define IFTAB_ETHS	0x2	/* Accept Ether-like LINK interface */
#define IFTAB_OTH	0x4	/* Accept all other interfaces */
#define IFTAB_ALL (IFTAB_IPS|IFTAB_ETHS|IFTAB_OTH)

/* Define a variety of utilities to manipulate IP and Ethernet
** addresses and headers.  These need to be provided for portability
** because not all platforms define a "struct ether_addr" and even
** the venerable "struct in_addr" can vary.
**
** Furthermore, code which attempts to impose a structure on top of
** a raw data stream is inherently unportable.  Despite the fact
** it usually works on most platforms, ANSI C does not guarantee
** that, for example, the typical "struct ether_addr" will always
** have a sizeof 6.  Depending on the platform alignment, it could
** legally be larger.
*/

/* Ethernet packet definitions */

#define ETHER_ADRSIZ	6	/* # bytes in ethernet address */
#define ETHER_HDRSIZ	14	/* # bytes in header (2 addrs plus type) */
#define ETHER_MTU	1500	/* Max # data bytes in ethernet pkt */
#define ETHER_MIN	(60-ETHER_HDRSIZ)	/* Minimum # data bytes */
#define ETHER_CRCSIZ	4	/* # bytes in trailing CRC */

	/* Ethernet packet offset values */
#define ETHER_PX_DST	0	/* Dest address */
#define ETHER_PX_SRC	6	/* Source address */
#define ETHER_PX_TYP	12	/* Type (high byte first) */
#define ETHER_PX_DAT 	14	/* Data bytes */
	/* CRC comes after data, which is variable-length */

/* Ethernet address.  Use ETHER_ADRSIZ for actual size. */
struct eth_addr {
    unsigned char ea_octets[ETHER_ADRSIZ];
};

/* Ethernet header.  Use ETHER_HDRSIZ for actual size. */
struct eth_header {
    unsigned char eh_octets[ETHER_HDRSIZ];
};

#define ea_ptr(var) (&(var[0]))
#define ea_set(ea, from) memcpy((void *)(ea), (void *)(from), ETHER_ADRSIZ)
#define ea_clr(ea)       memset((void *)(ea),      0,         ETHER_ADRSIZ)
#define ea_cmp(ea, ea2)  memcmp((void *)(ea), (void *)(ea2),  ETHER_ADRSIZ)
#define ea_isclr(ea) (0==memcmp((void *)(ea), "\0\0\0\0\0\0", ETHER_ADRSIZ))

#define eh_dptr(ehp) (((unsigned char *)(ehp))+ETHER_PX_DST)
#define eh_sptr(ehp) (((unsigned char *)(ehp))+ETHER_PX_SRC)
#define eh_tptr(ehp) (((unsigned char *)(ehp))+ETHER_PX_TYP)

#define eh_dset(ehp, eap) ea_set(eh_dptr(ehp), (eap))
#define eh_sset(ehp, eap) ea_set(eh_sptr(ehp), (eap))
#define eh_tset(ehp, typ) ((eh_tptr(ehp)[0] = ((typ)>>8)&0377), \
			   (eh_tptr(ehp)[1] = (typ)&0377))

#define eh_dget(ehp, eap) ea_set((eap), eh_dptr(ehp))
#define eh_sget(ehp, eap) ea_set((eap), eh_sptr(ehp))
#define eh_tget(ehp)      ((eh_tptr(ehp)[0] << 8) | (eh_tptr(ehp)[1]))


/* Internet Protocol definitions */

#define IP_ADRSIZ 4		/* # bytes in IP address */

union ipaddr {
    unsigned char ia_octet[IP_ADRSIZ];
    struct in_addr ia_addr;
};

struct pfdata;
struct osnpf;

typedef ssize_t (*osn_pfread_f)(struct pfdata *pfdata, void *buf, size_t nbytes);
typedef ssize_t (*osn_pfwrite_f)(struct pfdata *pfdata, const void *buf, size_t nbytes);
typedef void (*osn_pfdeinit_f)(struct pfdata *, struct osnpf *);

/*
 * A structure that aggregates information about the packet filter variant
 * which is in use.
 */
struct pfdata {
    int		 pf_fd;		/* most but not all have a file descriptor */
    int		 pf_meth;	/* which packet "filter" is in use */
    void 	*pf_handle;	/* pcap has a handle */
    int 	 pf_can_filter;	/* has a packet filter built-in and enabled */
    int		 pf_ip4_only;	/* set TRUE for IP i/f; FALSE for ethernet i/f */
    osn_pfread_f pf_read;	/* indirection to packet reading function */
    osn_pfwrite_f pf_write;	/* indirection to packet writing function */
    osn_pfdeinit_f pf_deinit;	/* indirection to closing function */
};

#define PF_METH_NONE		0
#define PF_METH_PCAP		1
#define PF_METH_TUN		2
#define PF_METH_TAP		3
#define PF_METH_VDE		4
#define PF_METH_LNX		5

int osn_iftab_init(void);
int osn_nifents(void);		/* # of entries cached by osn_iftab_init */

int osn_ifsock(char *ifnam, ossock_t *);
int osn_ifclose(ossock_t);
void osn_iftab_show(FILE *f, struct ifent *ife, int nents);
void osn_ifctab_show(FILE *f, struct ifconf *ifc);
int osn_ifipget(int s, char *ifnam, unsigned char *ipa);
int osn_ifnmget(int s, char *ifnam, unsigned char *ipa);
int osn_pfeaget(struct pfdata *, char *ifnam, unsigned char *eap);
int osn_ifeaget2(char *ifnam, unsigned char *eap);
#if !OSN_USE_IPONLY
int osn_ifeaset(struct pfdata *pfdata, int s, char *ifnam, unsigned char *newpa);
int osn_ifmcset(struct pfdata *pfdata, int s, char *ifc, int delf, unsigned char *pa);
#endif

struct ifent *osn_ipdefault(void);
struct ifent *osn_iftab_arp(struct in_addr ia);
int osn_iftab_arpget(struct in_addr ia, unsigned char *eap);

struct ifent *osn_ifcreate(char *ifnam);
int osn_ifealookup(char *ifnam, unsigned char *eap);
int osn_ifiplookup(char *ifnam, unsigned char *ipa);
int osn_ifnmlookup(char *ifnam, unsigned char *ipa);

#define OSN_EASTRSIZ sizeof("xx:xx:xx:xx:xx:xxZZ")
char *eth_adrsprint(char *cp, unsigned char *ea);

#define OSN_IPSTRSIZ sizeof("ddd.ddd.ddd.dddZZZZ")
char *ip_adrsprint(char *cp, unsigned char *ip);

int osn_arp_stuff(char *ifname, unsigned char *ipa, unsigned char *eap, int pubf);
int osn_arp_look(struct in_addr *ipa, unsigned char *eap);

struct osnpf {	/* Arg struct for common initialization params */
	char *osnpf_ifnam;	/* Interface name */
	char *osnpf_ifmeth;	/* Which connection method to use (pcap, tun, tap, etc */
	int osnpf_dedic;	/* TRUE if dedicated ifc, else shared */
	int osnpf_rdtmo;	/* Read timeout, if any */
	int osnpf_backlog;	/* Allow # backlogged packets, if any */
	union ipaddr osnpf_ip;	/* IP address to use */
	union ipaddr osnpf_tun;	/* INOUT: IP address host side of tunnel */
	struct ether_addr osnpf_ea;	/* OUT: ether address of ifc */
};


/* the void * is an argument to pass on to pfbuild() */
void osn_pfinit(struct pfdata *, struct osnpf *, void *);
void osn_pfdeinit(struct pfdata *, struct osnpf *);

ssize_t osn_pfread(struct pfdata *pfdata, void *buf, size_t nbytes);
int osn_pfwrite(struct pfdata *pfdata, const void *buf, size_t nbytes);

extern char osn_networking[];

#endif /* ifndef OSDNET_INCLUDED */
