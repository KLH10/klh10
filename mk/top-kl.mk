# Makefile fragment for building kl

####################################################################
##	Specific KLH10 configuration
##

# Standard setup for KL (TOPS-10 and TOPS-20)
#
CONFFLAGS = -DKLH10_CPU_KLX=1	\
	    -DKLH10_SYS_T20=1	\
	    -DKLH10_EVHS_INT=1	\
		    -DKLH10_DEV_DPNI20=1 \
		    -DKLH10_DEV_DPTM03=1 \
		    -DKLH10_DEV_DPRPXX=1 \
	    -DKLH10_MEM_SHARED=1	\
	    -DKLH10_RTIME_OSGET=1	\
	    -DKLH10_ITIME_INTRP=1	\
	    -DKLH10_CTYIO_INT=1	\
	    -DKLH10_APRID_SERIALNO=3600 \
	    -DKLH10_CLIENT=\"MyKL\"

all base-kl:	kn10-kl DPROCS_KL ALL_UTILS

####################################################################
##
##	Basic KN10 configurations
##

# Modules needed for KL10 version.

OFILES_KL = klh10.o prmstr.o fecmd.o feload.o wfio.o osdsup.o \
	kn10cpu.o kn10pag.o kn10clk.o opdata.o kn10ops.o \
	inmove.o inhalf.o inblsh.o intest.o \
	infix.o  inflt.o  inbyte.o injrst.o \
	inexts.o inio.o   kn10dev.o 	\
	dvcty.o  dvdte.o	\
	vdisk.o  dvrpxx.o dvrh20.o	\
	vmtape.o dvtm03.o	\
	dvni20.o dpsup.o	\
	dvhost.o dvlites.o

kn10-kl: $(OFILES_KL)
	$(LINKER) $(LDFLAGS) $(LDOUTF) kn10-kl $(OFILES_KL) $(LIBS) $(CPULIBS)

base-ks:
	@echo "base-ks is not built in this directory."

base-ks-its:
	@echo "base-ks-its is not built in this directory."

####################################################################
##	Lintish versions to see how many compiler warnings we can generate
##

lint-kl:
	$(MAKER) kn10-kl $(DPROCS_KL) $(BASE_UTILS) uexbconv \
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
