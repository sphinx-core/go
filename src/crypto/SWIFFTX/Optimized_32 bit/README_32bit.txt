This directory contains the optimized implementation for 32bit processors.

	- README_32bit.txt 				This file
	- SHA3.h						The exact copy of the reference version of this file.
	- SHA3.c						The exact copy of the reference version of this file.
	- SWIFFTX.h						The exact copy of the reference version of this file.
	- SWIFFTX.c						The optimized implementation of SWIFFTX compression function.
	- Tester.c						The exact copy of the reference version of this file.
	- stdint.h						The exact copy of the reference version of this file.
	- inttypes.h					The exact copy of the reference version of this file.
	- stdbool.h						The exact copy of the reference version of this file.
	- makefile						The makefile that enables to compile the optimized implementation easily in gcc.
	- Optimized32.sln				The solution file in VS2005 format.
	- Optimized32.vcproj			The project file in VS2005 format. Note that in the RELEASE all the compilation
									flags are set to produce the fastest code possible.

