CC=gcc
OPT=-funroll-loops

sha3: Tester.c SHA3.c SWIFFTX.c SWIFFTX.h SHA3.h
	${CC} -O4 -DSYS_STDINT ${OPT} -msse2 SHA3.c SWIFFTX.c Tester.c -o sha3
produceiv: ProduceRandomIV.c SHA3.c SWIFFTX.c SWIFFTX.h SHA3.h
	${CC} -O4 -DSYS_STDINT ${OPT} -msse2 SHA3.c SWIFFTX.c ProduceRandomIV.c -o produceiv

clean: 
	rm *.o *.s *~ sha3 sha3.exe
