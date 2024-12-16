This directory contains additional implementations, in addition to what specified 
by NIST.
	- README_Additional_Implementations.txt 	This file
	/SIMD							The directory that contains SIMD implementation.
		- SHA3.h					The exact copy of the reference version of this file.
		- SHA3.c					The exact copy of the reference version of this file.
		- SWIFFTX.h					The exact copy of the reference version of this file.	
		- SWIFFTX.c					The SIMD implementation of SWIFFTX compression function.
		- makefile					The makefile for gcc compiler. 
		- Tester.c					The exact copy of the reference version of this file.
_______________________________________________________________________		

To build the SIMD version: just make.

The makefile here works for gcc 4.2.1 and so is the source.

If you have a more up to date gcc 4.3.2 (like latest cygwin version)
then use the commented option in the makefile and uncomment the relevant
#ifdef in SWIFFTX.c

Play around with the Tester.c source to get various tests timing.

		
