/* UDLCONV.C - Utility to convert DIR.LIST files into ITSDUMP tapedirs
*/
/* $Id: udlconv.c,v 2.3 2002/04/26 05:19:06 klh Exp $
*/
/*  Copyright � 1992, 2001 Kenneth L. Harrenstien
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
 * $Log: udlconv.c,v $
 * Revision 2.3  2002/04/26 05:19:06  klh
 * Was missing include of <stdlib.h>
 *
 * Revision 2.2  2001/11/10 21:28:59  klh
 * Final 2.0 distribution checkin
 *
 */

/* Originally called "dlmunch".
 * Acts as a filter:
 *  Input is a DIR.LIST file from Alan Bawden's ITS archives.
 *  Output is a DIR.tdr file suitable for mounting as a virtual tape,
 *	provided ITSDUMP format is supported.
 */

/*
	Format of DIR.LIST list:

    (("system-name" "dir-name")
	("fn1" "fn2" <length> <bytesize> "linkto" <date1> <date2> "author")
		...
    )

"fn1" and "fn2" appear to have no quote chars.  Every char within
	the quotemarks is valid (including spaces!)

<length> is a decimal number of # bytes, format <digits><'.'>
	or NIL if entry is a link.
<bytesize> is either "7." or "36."  I suppose others may be possible.
	or NIL if entry is a link.
"linkto" is NIL for an ordinary file, else an ITS filespec of the name
	pointed to.  String format is:
		"<dirname><';'><' '><fn1><' '><fn2>"
	It's still unclear whether anything is quoted or not.
<date1> is the creation date.  See below.
<date2> is the reference date.
	Both dates are huge decimal numbers, i.e. <digits><'.'>
	which represent the CommonLisp/LispM convention of # seconds
	since 1 Jan 1900 00:00:00 GMT.
	This will fit within 32 bits, esp if unsigned.
"author" is the sname of the file's author, if known, and NIL otherwise.
	
	Suggest using sscanf's "%li" to read in the numeric formats.


Transformed into:
    ITSFILE:	dir fn1 fn2 {} <type> <filename>
			    {} -> xdir xfn1 xfn2

where each word is all nonspace chars.  Spaces are replaced by '~' within
a word.

{} is optional.  If present, it contains:
	{<crdate> <refdate> <bsize> <wlen> <auth>}
where the first 4 are numeric and the last is a word.  All are optional
but must be in this order; use 0 to default any of the first 4, and don't
specify the <auth> at all to default it.

There is currently no way to transform an author name into an author index
without some master table matching names to indices.  Someday DUMP may have
its format extended to include this info, so it's retained for now.


*/
/*
	From Alan:
The following structure describes the format of each entry:

  (defstruct (entry (:type list))
    pathname
    fn1
    fn2
    length-in-bytes
    byte-size
    link-to
    creation-date
    reference-date
    author
    )

Except the first slot (`pathname') isn't stored in the DIR.LIST file, only
the part of the list starting with the `fn1'.  

The `link-to' is `NIL' for an ordinary file, and contains the name of the
file linked to (as a string) if the entry is a link.  I no longer remember
if that string is properly quoted for an ITS filename parser.  (I may never
have known, all this information was actually generated by calling Lisp
Machine directory hacking routines, so we're actually at the mercy of
Symbolics here.)

Also, if the entry is a link, the `length-in-bytes' and `byte-size' are
both `NIL'.

I think the `creation-date' and `reference-date' are in the standard Common
Lisp / Lisp Machine date format as a number of seconds since some known
instant (perhaps 1 Jan 1901 00:00:00 GMT?).

The first element in the list stored in the DIR.LIST file is not the
description of a file.  It is a two element list: (<machine-name> <sname>).


   Date: Mon, 7 Dec 1992 23:35:37 GMT
   From: Ken Harrenstien <klh@us.oracle.com>

       length-in-bytes
       byte-size

   This information needs to be munched somehow to get it into (1)
   length-in-words and (2) bytecnt+bytesize.  The latter is some 6-bit
   magic field, part of value 5 of a FILBLK.  I don't at the moment know
   what the magic values are, but they must be in ITS someplace.

Well the byte-size is always either 7 or 36, so the transformation isn't
that hard.  Also, even the ITS DUMP program fails to restore this
information properly.  The description of the format of value 5 of a FILBLK
can be found as a comment near the end of SYSTEM;FSDEFS >.

       I think the `creation-date' and `reference-date' are in the standard
       Common Lisp / Lisp Machine date format as a number of seconds since
       some known instant (perhaps 1 Jan 1901 00:00:00 GMT?).

   Erg.  I was hoping they were the decimal values of the 4th and 5th
   FILBLK words.  Now this is going to take a little more conversion than I
   expected.  If you could find out...

I looked it up.  These times are the number of seconds since 
1 Jan 1900 00:00:00 GMT (I was a year wrong above).  This is the same
format as described in RFC 738 (written by someone named "K. Harrenstien").
The ITS DATIME library has routines that convert values in the format into
ITS dates...

You can sanity check any conversion routines you write by checking that all
of the `reference-dates' translate back into times at midnight (eastern
standard or daylight as appropriate).

   Incidentally, the method doesn't have to involve DUMP format, although
   that is simplest to reload.  For example, to create most of the links,
   I parsed the DIR.LIST link data into a bunch of :XFILE files, FTPed
   them over, and executed them.  Hack.

That's pretty funny.  You know, since the DIR.LIST files are written in
Lisp format, the -right- thing to do is to do this all from Maclisp!

*/

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>	/* For malloc */

/*#include "lread.h" */
#ifndef LREAD_INCLUDED
#define LREAD_INCLUDED 1
/* LREAD.H - originally a separate file, but now incorporated directly
 * for simplicity.
 */

#define NIL ((struct lnode *)0)
#define LTRUE (&ltruenode)

enum {
	LT_NIL=0,	/* Null list */
	LT_ATOM,	/* Untyped atom (lvs points to string) */
	LT_LIST,	/* List (lvl points to it) */
	LT_STR,		/* Atom with "string" syntax (lvs points to string) */
	LT_NUM		/* Atom converted to numerical value (lvi) */
};

struct lnode {
	struct lnode *lnxt;
	int ltyp;
	union {
		long lvi;
		struct { int ls_cnt; char *ls_ptr; } lvstr;
		struct lnode *lvl;
	} lval;
};

extern struct lnode ltruenode;		/* Constant TRUE */

extern struct lnode *lread(FILE *);
extern struct lnode *lnget(void);
extern void lprint(FILE *, struct lnode *);


#endif /* ifndef LREAD_INCLUDED */


struct filent {
	/* Raw parsed strings */
	char *ffn1, *ffn2;
	char *fslen, *fsbsz, *flink;
	char *fscreat, *fsref, *fsauth;

	/* Derived data */
	char *fpathname;		/* Local pathname */
	char *fldir, *flfn1, *flfn2;	/* Link specs */
	long fcreat, fref;
	long flen, fbsz;
};

struct lnode *dlist, *syslist, *lcur;
char *sysname = NULL;
char *mdrname = NULL;
#if 0	/* "dirname" is used by DECOSF string.h?!! */
char *dirname = NULL;
#endif

char usage[] = "\
Usage: %s [switches] < DIR.LIST > DIR.tdr\n\
	-p <prefixpath>  - Prefix this path to all host filenames\n\
";
char *swprefix = NULL;
int swfiles = 1;
int swxlinks = 0;
int swlinks = 0;
int swlist = 0;

int fesetup(struct filent *fe, struct lnode *l);
char *its2unixfn(char *cp, char *itsfn);
char *fn6quot(char *fn);
void outlink(struct filent *fe);
void outfile(struct filent *fe);


main(int argc, char *argv[])
{
    register int i;
    char *err = NULL;

    /* Handle switches */
    for (i = 0; ++i < argc; ) {
	if (argv[i][0] == '-') switch (argv[i][1]) {
	    case 'p':
		if (i+1 < argc) {
		    swprefix = argv[++i];
		    continue;
		}
		err = "No arg for";
		break;
	    default:
		err = "Unknown switch";
		break;
	} else
	    err = "Unknown arg";

	fprintf(stderr, "%s: %s \"%s\"\n", argv[0], err, argv[i]);
	break;
    }
    if (err) {
	fprintf(stderr, usage, argv[0]);
	exit(1);
    }

    /* Now gobble up input list */
    dlist = lread(stdin);

    if (dlist == NIL || dlist->ltyp != LT_LIST) {
	printf("; No list read\n");
	exit(1);
    }
    if (dlist->lnxt) {
	printf("; More than one thing read?\n");
	exit(1);
    }
    if (swlist)
	lprint(stdout, dlist);

    dlist = dlist->lval.lvl;	/* Get 1st thing on list */

    syslist = (dlist->ltyp == LT_LIST) ? dlist->lval.lvl : NIL;

    if (syslist) {
	sysname = (syslist->ltyp == LT_STR)
			? syslist->lval.lvstr.ls_ptr : NULL;
	mdrname = (syslist->lnxt && syslist->lnxt->ltyp == LT_STR)
			? syslist->lnxt->lval.lvstr.ls_ptr : NULL;
    }
    if (!swxlinks)
	printf(";;; System \"%s\", Directory \"%s\"\n",
			sysname ? sysname : "",
			mdrname ? mdrname : "");

    /* Loop thru list of files */
    lcur = dlist->lnxt;
    for (lcur = dlist->lnxt; lcur; lcur = lcur->lnxt) {
	register struct lnode *l;
	struct filent fe;

	l = (lcur->ltyp == LT_LIST) ? lcur->lval.lvl : NIL;
	if (!l) {
	    printf("; Error - non-list element in directory list\n");
	    continue;
	}
	if (!fesetup(&fe, l))	/* Set up filent from list spec */
	    continue;

	/* Now munch results.  For now, we just output a list of links. */
	if (swlinks) {
	    outlink(&fe);
	} else
	    outfile(&fe);
    }
}


int
fesetup(register struct filent *fe,
	register struct lnode *l)
{
    fe->ffn1 = (l && l->ltyp == LT_STR) ? l->lval.lvstr.ls_ptr : NULL;
    if (l) l = l->lnxt;
    fe->ffn2 = (l && l->ltyp == LT_STR) ? l->lval.lvstr.ls_ptr : NULL;
    if (l) l = l->lnxt;
    fe->fslen = (l && l->ltyp == LT_ATOM) ? l->lval.lvstr.ls_ptr : NULL;
    if (l) l = l->lnxt;
    fe->fsbsz = (l && l->ltyp == LT_ATOM) ? l->lval.lvstr.ls_ptr : NULL;
    if (l) l = l->lnxt;
    fe->flink = (l && l->ltyp == LT_STR) ? l->lval.lvstr.ls_ptr : NULL;
    if (l) l = l->lnxt;
    fe->fscreat = (l && l->ltyp == LT_ATOM) ? l->lval.lvstr.ls_ptr : NULL;
    if (l) l = l->lnxt;
    fe->fsref = (l && l->ltyp == LT_ATOM) ? l->lval.lvstr.ls_ptr : NULL;
    if (l) l = l->lnxt;
    fe->fsauth = (l && l->ltyp == LT_STR) ? l->lval.lvstr.ls_ptr : NULL;

    /* Now derive other elements and/or authenticate numbers */
    fe->fldir = fe->flfn1 = fe->flfn2 =
		fe->fpathname = NULL;
    fe->flen = fe->fbsz = fe->fcreat = fe->fref = 0;

    if (fe->fslen) {
	if (!sscanf(fe->fslen, "%li%*[.]", &fe->flen)) {
	    printf("; Bad length syntax: \"%s\"\n", fe->fslen);
	    return 0;
	}
    }
    if (fe->fsbsz) {
	if (!sscanf(fe->fsbsz, "%li%*[.]", &fe->fbsz)) {
	    printf("; Bad bytesize syntax: \"%s\"\n", fe->fsbsz);
	    return 0;
	}
    }
    if (fe->fscreat) {
	if (!sscanf(fe->fscreat, "%li%*[.]", &fe->fcreat)) {
	    printf("; Bad creation-date syntax: \"%s\"\n", fe->fscreat);
	    return 0;
	}
    }
    if (fe->fsref) {
	if (!sscanf(fe->fsref, "%li%*[.]", &fe->fref)) {
	    printf("; Bad reference-date syntax: \"%s\"\n", fe->fsref);
	    return 0;
	}
    }

    if (fe->flink) {
	char *ldir, *lfn1, *lfn2;
	static char lbuf[30];

	if (strlen(fe->flink) >= sizeof(lbuf)-1) {
	    printf("; Target of link too long: \"%s\"\n", fe->flink);
	    return 0;
	}
	strcpy(lbuf, fe->flink);
	ldir = lbuf;
	lfn1 = strchr(lbuf, ';');
	if (lfn1) {
	    *lfn1++ = '\0';
	    while (isspace(*lfn1)) ++lfn1;
	    lfn2 = lfn1;
	    while (!isspace(*lfn2)) ++lfn2;
	    *lfn2++ = '\0';
	    while (isspace(*lfn2)) ++lfn2;
	}
	if (!lfn1 || !*ldir || !*lfn1 || !*lfn2) {
	    printf("; Bad target syntax: \"%s\"\n", fe->flink);
	    return 0;
	}
	fe->fldir = ldir;
	fe->flfn1 = lfn1;
	fe->flfn2 = lfn2;
    }

    /* Construct local pathname. */
    if (!fe->flink) {
	static char pbuf[6+1+6+1];
	register char *cp;

	if (!fe->ffn1 || !fe->ffn2) {
	    printf("; No FN1 or FN2 for filespec, skipping \"%s\" \"%s\"\n",
			(fe->ffn1 ? fe->ffn1 : ""),
			(fe->ffn2 ? fe->ffn2 : "") );
	    return 0;
	}

	if ((strlen(fe->ffn1) + strlen(fe->ffn1) + 2) > sizeof(pbuf)) {
	    printf("; FN1+FN2 too large, skipping \"%s\" \"%s\"\n",
			(fe->ffn1 ? fe->ffn1 : ""),
			(fe->ffn2 ? fe->ffn2 : "") );
	    return 0;
	}

	cp = its2unixfn(pbuf, fe->ffn1);
	*cp++ = '.';
	cp = its2unixfn(cp, fe->ffn2);
	*cp = '\0';
	fe->fpathname = pbuf;
    }

    /* Translate author if possible?? */

    return 1;
}

/* Translate ITS filename to Unix version, using mapping of Alan Bawden,
** to wit:
**	ITS	   Unix
**	/      =>  {
**	Space  =>  ~
**	A - Z  =>  a - z
**	.      =>  _
**	_      =>  }
** All other chars are passed on unchanged.
*/
char *
its2unixfn(register char *cp,
	   register char *itsfn)
{
    register int ch;

    while (ch = *itsfn++) {
	switch (ch) {
	case '/':	ch = '{';	break;
	case ' ':	ch = '~';	break;
	case '.':	ch = '_';	break;
	case '_':	ch = '}';	break;
	default:
	    if (isupper(ch))
		ch = tolower(ch);
	    break;
	}
	*cp++ = ch;
    }
    return cp;
}

char *
fn6quot(register char *fn)
{
    static char cbuf[20];
    register char *fnp = fn;
    register char *cp = cbuf;
    register int c;

    while (c = *fnp++) {
	switch (c) {
	case ' ':	c = '~';	break;
#if 0
	case '\\':
	    *cp++ = '\\';
	    break;
#endif
	default:
	    if (!isprint(c)) {
		printf("; Bad char in filename component: \"%s\"\n", fn);
		c = 0;
		break;
	    }
	    break;
	}
	if (!c) break;
	*cp++ = c;
	if (cp >= &cbuf[sizeof(cbuf)-1]) {
	    printf("; Filename component too large: \"%s\"\n", fn);
	    break;
	}
    }
    *cp = '\0';
    return cbuf;
}

void
outlink(register struct filent *fe)
{
    if (! fe->flink)
	return;
    if (!mdrname || !fe->ffn1 || !fe->ffn2) {
	printf("; Null source dir, fn1 or fn2, skipping link to \"%s\".\n",
	       fe->flink);
	return;
    }
    if (!fe->fldir || !fe->flfn1 || !fe->flfn2) {
	printf("; Null target dir, fn1 or fn2, skipping link to \"%s\".\n",
	       fe->flink);
	return;
    }

    if (swxlinks)
	printf(":link %s;%s %s, %s;%s %s\n",
		mdrname, fe->ffn1, fe->ffn2,
		fe->fldir, fe->flfn1, fe->flfn2);
    else
	printf("ITSFILE: %s %-6s %-6s -> %s %s %s\n",
		mdrname, fe->ffn1, fe->ffn2,
		fe->fldir, fe->flfn1, fe->flfn2);
}

void
outfile(register struct filent *fe)
{
    if (!fe->flink) {
	/* Verify that file actually exists? */
    }

    printf("ITSFILE: %s", fn6quot(mdrname));
    printf(" %-6s", fn6quot(fe->ffn1));
    printf(" %-6s", fn6quot(fe->ffn2));

    printf(" { %lu %lu %2lu %4lu",
		fe->fcreat, fe->fref, fe->fbsz, fe->flen);
    if (fe->fsauth)
	printf(" %s", fn6quot(fe->fsauth));
    printf(" }");

    if (fe->flink) {
	printf(" -> %s", fn6quot(fe->fldir));
	printf(" %s", fn6quot(fe->flfn1));
	printf(" %s\n", fn6quot(fe->flfn2));
    } else {
	printf(" u36 %s%s\n",
		(swprefix ? swprefix : ""), fe->fpathname);
    }
}

/* LREAD.C - originally a separate file, but now incorporated directly
 * for simplicity.
 */
/* Stuff for feeble-minded list processor */

#if 0
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>	/* For malloc */
#include "lread.h"
#endif

#define MAXLINE 300

static int llstch = -1;
static int leofflg;
#define unlrch(c) llstch = c

static int lineno = 0;
static char linebuf[MAXLINE];
static char *linecp = linebuf;
static int linecnt = 0;

static struct lnode *lrstr(FILE *, int);
static void wspfls(FILE *);
static int lrch(FILE *);
static int islword(int);
static int ustrcmp(char *, char *);


struct lnode *
lread(register FILE *f)
{
    register int c;
    register struct lnode *lp, *lp2;
    struct lnode *head;

    wspfls(f);
    if ((c = lrch(f))== EOF)
	return NIL;
    if (c == ')')	/* End of a list? */
	return NIL;
    if (c == '(') {	/* Start of a list? */
	head = lp = lnget();
	lp->ltyp = LT_LIST;
	if ((head->lval.lvl = lp = lread(f)) == NIL)
	    return head;	/* Return empty list */
	while(lp2 = lread(f)) {
	    lp->lnxt = lp2;
	    lp = lp2;
	}
	return head;
    }

    /* Atom of some kind */
    if (c=='"')
	return lrstr(f, LT_STR);
    unlrch(c);
    lp = lrstr(f, LT_ATOM);

    /* Special check */
    if (lp && lp->lval.lvstr.ls_cnt == 3
	&&  ustrcmp(lp->lval.lvstr.ls_ptr, "NIL")==0) {
	free(lp->lval.lvstr.ls_ptr);
	lp->lval.lvstr.ls_ptr = NULL;
	lp->ltyp = LT_NIL;
    }
    return lp;
}



#define LSMAX 300	/* Max # chars in atom string */
static struct lnode *
lrstr(register FILE *f, int type)
{
    register char *cp;
    register int c, i;
    struct lnode *lp;
    char cbuf[LSMAX];

    cp = cbuf;
    i = 0;

    while((c = lrch(f)) != EOF)
	if (type == LT_STR) switch(c) {
	case '"':
	    if ((c = lrch(f)) == EOF)
		return NIL;
	    if (c != '"') {
		unlrch(c);
		goto out;
	    }
	default:
	ok:
	    if (++i > LSMAX)
		break;
	    *cp++ = c;
	    continue;
	}
	else {
	    if (islword(c)) goto ok;
	    unlrch(c);
	    break;
	}
 out:
    *cp = 0;
    lp = lnget();
    lp->ltyp = type;
    lp->lval.lvstr.ls_cnt = i;
    lp->lval.lvstr.ls_ptr = cp = (char *)malloc(i+1);
    memcpy(lp->lval.lvstr.ls_ptr, cbuf, i);
    cp[i] = '\0';
    return lp;
}

static void
wspfls(register FILE *f)
{
    register int c;

    for (;;) {
	c = lrch(f);
	if (isspace(c)) continue;
	if (c == ';')
	    while ((c = lrch(f)) != '\n')
		if (c == EOF) return;		
	break;
    }		
    if (c != EOF) unlrch(c);
}

static int
lrch(register FILE *f)
{
    register int c;

    if ((c = llstch) >= 0) {
	if (c == 0 && leofflg)
	    return EOF;
	llstch = -1;
	return c;
    }
    if ((c = getc(f)) == EOF) {
	leofflg = 1;
	llstch = 0;
	*linecp = 0;
	linecp = linebuf;
	linecnt = 0;
	return c;
    }
    if (c == '\n') {
	lineno++;
	linecp = linebuf;
	linecnt = 0;
    } else {
	if (linecnt >= MAXLINE-1) {
	    linecp = linebuf;
	    linecnt = 0;
	}
	++linecnt;
	*linecp++ = c;
    }
    return c;
}

static int
islword(int c)
{
    return (isgraph(c)
	   && c != '(' && c !=')' && c != ';'
	   && c != '"' && c != '\\');
}

struct lnode *
lnget(void)
{
    return (struct lnode *)calloc(1,sizeof(struct lnode));
}

/* Returns s1 - s2 (case-independent)
*/
static int
ustrcmp(register char *s1, register char *s2)
{
    register int res;

    for (; *s1; ++s1, ++s2) {
	if (*s1 != *s2) {
	    if (res = (islower(*s1) ? toupper(*s1) : *s1)
			- (islower(*s2) ? toupper(*s2) : *s2))
		return res;		/* Failed */
	}
    }
    return 0;
}

void
lprint(FILE *f, struct lnode *alp)
{
    register struct lnode *lp;

    if (!alp) {
	fprintf(f, "nil");
	return;
    }
    for (lp = alp; lp; lp = lp->lnxt) {
	if (lp != alp)
	    fputc(' ', f);
	switch (lp->ltyp) {
	case LT_ATOM:
	    fprintf(f, "%s", lp->lval.lvstr.ls_ptr);
	    break;
	case LT_STR:
	    fprintf(f, "\"%s\"", lp->lval.lvstr.ls_ptr);
	    break;
	case LT_NIL:
	    fprintf(f, "NIL");
	    break;
	case LT_LIST:
	    fputc('(', f);
	    lprint(f, lp->lval.lvl);
	    fputc(')', f);
	    break;

	case LT_NUM:
	default:
	    fprintf(f, "\n;; Unknown node type %d\n", lp->ltyp);
	}
    }
}
