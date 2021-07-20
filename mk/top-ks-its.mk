# Makefile fragment for building ks-its

####################################################################
##	Specific KLH10 configuration
##

# Standard setup for KS ITS
#
CONFFLAGS = -DKLH10_CPU_KS=1	\
	    -DKLH10_SYS_ITS=1	\
	    -DKLH10_EVHS_INT=1	\
		    -DKLH10_DEV_DPTM03=1 \
		    -DKLH10_DEV_DPRPXX=1 \
		    -DKLH10_DEV_DPIMP=1 \
	    -DKLH10_SIMP=0 \
	    -DKLH10_MEM_SHARED=1 \
	    $(TINTFLAGS) \
	    $(DINTFLAGS) \
	    -DKLH10_APRID_SERIALNO=4097 \
	    -DKLH10_CLIENT=\"MyITS\" \
	    -DVMTAPE_ITSDUMP=1

all base-ks-its:	kn10-ks-its DPROCS_KSITS ALL_UTILS

####################################################################
##
##	Basic KN10 configurations
##

# Modules needed for KS10 version.

OFILES_KS = klh10.o prmstr.o fecmd.o feload.o wfio.o osdsup.o \
	kn10cpu.o kn10pag.o kn10clk.o opdata.o kn10ops.o \
	inmove.o inhalf.o inblsh.o intest.o \
	infix.o  inflt.o  inbyte.o injrst.o \
	inexts.o inio.o   kn10dev.o dvuba.o  \
	dvcty.o  			\
	vdisk.o  dvrpxx.o dvrh11.o	\
	vmtape.o dvtm03.o	\
	dvlhdh.o dvdz11.o dvch11.o \
	dpsup.o \
	dvhost.o dvlites.o

kn10-ks-its: $(OFILES_KS)
	$(LINKER) $(LDFLAGS) $(LDOUTF) kn10-ks-its $(OFILES_KS) $(LIBS) $(CPULIBS)

base-ks:
	@echo "base-ks is not built in this directory."

base-kl:
	@echo "base-kl is not built in this directory."

####################################################################
##	Lintish versions to see how many compiler warnings we can generate
##

lint-ks-its:
	$(MAKER) kn10-ks-its $(DPROCS_KSITS) $(BASE_UTILS) udlconv \
	    "SRC = $(SRC)" \
	    "CC = $(CC)" \
	    "CFLAGS = $(CFLAGS) $(CFLAGS_AUX) $(CFLAGS_LINT)" \
	    "CPPFLAGS = $(CPPFLAGS)" \
	    "LDFLAGS = $(LDFLAGS)" \
	    "LIBS = $(LIBS)" \
	    "CPULIBS = $(CPULIBS)" \
	    "NETLIBS = $(NETLIBS)" \
	    "CENVFLAGS = $(CENVFLAGS)" \
	    "CONFFLAGS = $(CONFFLAGS) $(CONFFLAGS_AUX) $(CONFFLAGS_USR)"

#---
