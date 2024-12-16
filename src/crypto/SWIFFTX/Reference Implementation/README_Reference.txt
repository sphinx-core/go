This directory contains the official reference implementation.
	- README_Reference.txt			This file
	- SHA3.h						The header file that defines the NIST API.
	- SHA3.c						The implementation of NIST API using HAIFA mode of operation
									and SWIFFTX compression function.
	- SWIFFTX.h						The API for a single SWIFFTX compression function.
	- SWIFFTX.c						The implementation of SWIFFTX compression function.
	- ProduceRandomIV.c				The code we used to produce the random IVs used in SWIFFTX.
	- ProduceRandomSBox.c			The code we used to produce the random S-Box used in SWIFFTX.
	- Tester.c						The simple tests we wrote for initial stages of development.
	- stdint.h						The header file we used for sized integral types in VS2005.
	- inttypes.h					The header file we used for sized integral types in VS2005.
	- stdbool.h						The header file we used for boolean type in VS2005.
	- makefile						The makefile that enables to compile the reference implementation easily in gcc.
	- Reference.sln					The solution file in VS2005 format.
	- Reference.vcproj				The project file in VS2005 format.
