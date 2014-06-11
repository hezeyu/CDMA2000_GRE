#
# PF_RING
#
#PFRINGDIR  = /usr/local/src/PF_RING-6.0.1/userland/lib
PFRINGDIR = /usr/lib
LIBPFRING  = ${PFRINGDIR}/libpfring.a

#
# PF_RING aware libpcap
#
#PCAPDIR    = /usr/local/src/PF_RING-6.0.1/userland/libpcap-1.1.1-ring
OFLAGS = -g -DHAVE_PF_RING #-O1
PCAPDIR = /usr/lib
LIBPCAP    = ${PCAPDIR}/libpcap.a

# Search directories
#
PFRING_KERNEL=/usr/local/src/PF_RING-6.0.1/kernel
INCLUDE    = -I${PFRING_KERNEL} -I${PFRING_KERNEL}/plugins -I${PFRINGDIR} -I${PCAPDIR} -Ithird-party

LIBS = ${LIBPCAP} ${LIBPFRING}  -lpthread ${LIBPCAP} -lnuma -lrt -lmysqlclient

objects = cdma.o file.o panaly.o capture.o pf_ring.o
CFLAGS = ${OFLAGS} ${INCLUDE} -D HAVE_LIBNUMA -D_FILE_OFFSET_BITS=64

edit:$(objects)
	gcc ${CFLAGS} $(objects) ${LIBS} -o cdma

main.o:structure.h file.h panaly.h capture.h pf_ring.h
	gcc $(CFLAGS) -c cdma.c
file.o:structure.h file.h
	gcc $(CFLAGS) -c file.c
panaly.o:structure.h panaly.h sql.c
	gcc $(CFLAGS) -c panaly.c
capture.o:structure.h capture.h
	gcc $(CFLAGS) -c capture.c
pf_ring.o:structure.h pf_ring.h
	gcc $(CFLAGS) -c pf_ring.c

.PHONY:clean
clean:
	rm -rf cdma $(objects) core
