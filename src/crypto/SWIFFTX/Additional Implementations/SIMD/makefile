CC=gcc
#under cygwin use
#CC=gcc-4

OPT=-funroll-loops
#
#  use the following when compiling under gcc 4.3.2
#OPT=-funroll-loops -flax-vector-conversions

sha3: Tester.c SHA3.c SWIFFTX.c SWIFFTX.h SHA3.h
	${CC} -g  -O4 -DSYS_STDINT ${OPT} -msse2 -march=i686 -mfpmath=sse SWIFFTX.c SHA3.c Tester.c -o sha3

clean: 
	rm *.o *.s *~ sha3 sha3.exe
