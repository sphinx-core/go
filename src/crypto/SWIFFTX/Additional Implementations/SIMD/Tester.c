#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include "stdbool.h"
#include <string.h>
#include <time.h>
#include "SHA3.h"

void PrintDigestInHexa(BitSequence *digest, char* result, unsigned short lengthInBytes, 
                       bool toIdent)
{
	unsigned short i;
    int numOfWrittenChars = 0;
	const unsigned short spaceCond = 16;
	const unsigned short newLineCond = 32;

	numOfWrittenChars = sprintf(result, "%02X", digest[0]);

	for (i = 1; i < lengthInBytes; ++i)
	{
		if (toIdent)
			if ((i % newLineCond) == 0)
				numOfWrittenChars += sprintf(result + numOfWrittenChars, "\n");
			else if ((i % spaceCond) == 0)
				numOfWrittenChars += sprintf(result + numOfWrittenChars, " ");

		numOfWrittenChars += sprintf(result + numOfWrittenChars, "%02X", digest[i]);
	}
}


// Tests small input message for all the digest sizes.
int SanityCheck1()
{
	BitSequence resultingDigest[SWIFFTX_OUTPUT_BLOCK_SIZE] = {0};
    char resultInHexa[(SWIFFTX_OUTPUT_BLOCK_SIZE * 2) + 4] = {0}; // size 132
	BitSequence inputMessage[] = "Hello, world!"; // 14 including '\0'
	HashReturn exitCode;
	
	printf("The input message is:\n%s\n\n", inputMessage);

	exitCode = Hash(512, inputMessage, (DataLength) (sizeof(inputMessage) * 8), resultingDigest); 
	if (exitCode != SUCCESS)
	{
		printf("Failure occured.\n");
		return -1;
	}
	printf("The resulting digest of size 512bit of the input message is:\n");
    PrintDigestInHexa(resultingDigest, resultInHexa, 64, true);
    printf("%s", resultInHexa);
	printf("\n");

	////

	exitCode = Hash(384, inputMessage, (DataLength) (sizeof(inputMessage) * 8), resultingDigest); 
	if (exitCode != SUCCESS)
	{
		printf("Failure occured.\n");
		return -1;
	}
	printf("\nThe resulting digest of size 384bit of the input message is:\n");
	PrintDigestInHexa(resultingDigest, resultInHexa, 48, true);
    printf("%s", resultInHexa);
	printf("\n");

	////

	exitCode = Hash(256, inputMessage, (DataLength) (sizeof(inputMessage) * 8), resultingDigest); 
	if (exitCode != SUCCESS)
	{
		printf("Failure occured.\n");
		return -1;
	}
	printf("\nThe resulting digest of size 256bit of the input message is:\n");
	PrintDigestInHexa(resultingDigest, resultInHexa, 32, true);
    printf("%s", resultInHexa);
	printf("\n");

	////

	exitCode = Hash(224, inputMessage, (DataLength) (sizeof(inputMessage) * 8), resultingDigest); 
	if (exitCode != SUCCESS)
	{
		printf("Failure occured.\n");
		return -1;
	}
	printf("\nThe resulting digest of size 224bit of the input message is:\n");
	PrintDigestInHexa(resultingDigest, resultInHexa, 28, true);
    printf("%s", resultInHexa);
	printf("\n");

	return 0;
}

void PrintTimeAsReadableString(double value)
{
	double secs = .0;
	double mins = .0;
	double hours = .0;

	secs = value / 1000.;

	if (secs < 60.)
	{
		printf("%f seconds.", secs);
		return;
	}
	else
	{
		mins = floor(secs / 60.);
		secs -= mins * 60;
	}

	if (mins < 60.)
	{
		printf("%f minutes and %f seconds.", mins, secs);
		return;
	}
	else
	{
		hours = floor(mins / 60.);
		mins -= hours * 60.;
		printf("%f hours, %f minutes and %f seconds.", hours, mins, secs);
	}
}

// Basic time test. Tests a very short string many times (the slowest version - every time we 
// have the padding etc.).
// 
// Timing results (SIMD on E4500 @ 2.2 Mhz)
//
// with SIMD IFFT (not chosen - output is not random)
// Runs 5.5 secs
//
// with SIMD Smoothing (the  function chosen to have a smooth output distribution)
// Runs 11.5 secs
//
int TimeTest1()
{
	BitSequence resultingDigest[SWIFFTX_OUTPUT_BLOCK_SIZE] = {0};
    char resultInHexa[132] = {0}; 
	BitSequence inputMessage[] = "Hello, world!"; // 14 including '\0'
	HashReturn exitCode;
	// unsigned long numOfTrials = (unsigned long) 1e6;
	unsigned long numOfTrials = (unsigned long) 1e6; // for debug only
	unsigned long i;

	clock_t startTime, endTime;
	startTime = clock();

	for (i = 0; i < numOfTrials; ++i)
		exitCode = Hash(512, inputMessage, (DataLength) (sizeof(inputMessage) * 8), resultingDigest); 
		
	endTime = clock();

	printf("\nElapsed time was: ");
	PrintTimeAsReadableString(endTime - startTime);
	printf("\n\n");

	if (exitCode != SUCCESS)
	{
		printf("Failure occured.\n");
		return -1;
	}
	printf("The resulting digest of size 512bit of the input message is:\n");
    PrintDigestInHexa(resultingDigest, resultInHexa, 64, true);
    printf("%s", resultInHexa);
	printf("\n");

	return 0;
}

// Another timing test. Hashes a 1MB message 1e2 times.
// 
// Timing results (SIMD with gcc-4 on core 2 E4500 @ 2.2 Mhz)
// Without S-Box: 2.65 s
// With    S-Box: 2.78 s
int TimeTest2()
{
	BitSequence resultingDigest[SWIFFTX_OUTPUT_BLOCK_SIZE] = {0};
        char resultInHexa[132] = {0}; 
	BitSequence *inputMessage;
	HashReturn exitCode;
	unsigned long numOfTrials = (unsigned long) 1e2;
	unsigned long i;
	BitSequence inputPattern[] = "`1234567890-={}[];',./<>?:Pooky and Moockey WENT to walk. Then if the story ENDS:::!!?~!@#$%^&*()_+";
	int inputPatternLength = sizeof(inputPattern);
	clock_t startTime, endTime;
	const unsigned long memorySize1MB = 1048576;

	inputMessage = (BitSequence *) malloc(memorySize1MB * sizeof(BitSequence));
	if (!inputMessage)
	{
		printf("\nMemory allocation problem\n");
		return -2;
	}

	for (i = 0; i < 10485; ++i)
		memcpy(inputMessage + (i * inputPatternLength), inputPattern, inputPatternLength);

	for (i = 1048500; i < memorySize1MB; ++i)
		inputMessage[i] = 255; // All bits 1.

	startTime = clock();

	for (i = 0; i < numOfTrials; ++i)
		exitCode = Hash(512, inputMessage, (DataLength) (memorySize1MB * 8), resultingDigest); 
		
	endTime = clock();

	printf("\nElapsed time was: ");
	PrintTimeAsReadableString(endTime - startTime);
	printf("\n\n");

	if (exitCode != SUCCESS)
	{
		printf("Failure occured.\n");
		return -1;
	}
	printf("The resulting digest of size 512bit of the input message is:\n");
    PrintDigestInHexa(resultingDigest, resultInHexa, 64, true);
    printf("%s", resultInHexa);
    printf("\n");

	return 0;
}

// Checks that no matter how the division to blocks is, get the same result.
int SanityCheck2()
{
	BitSequence resultingDigest[SWIFFTX_OUTPUT_BLOCK_SIZE] = {0};
    char resultInHexa1[132] = {0}; 
    char resultInHexa2[132] = {0}; 
	BitSequence *inputMessage;
	HashReturn exitCode;
	unsigned long i;
	BitSequence inputPattern[] = "`1234567890-={}[];',./<>?:Pooky and Moockey WENT to walk. Then if the story ENDS:::!!?~!@#$%^&*()_+";
	int inputPatternLength = sizeof(inputPattern);
	const unsigned long memorySize1MB = 1048576;
	const unsigned long NUM_OF_RUNS = 100;
   	DataLength numOfBlocks, j, k;
   	// The pointer to the current place in the input we take into the compression function.
	DataLength currInputIndex = 0;
    bool wasFailure = false;
	hashState state;

	inputMessage = (BitSequence *) malloc(memorySize1MB * sizeof(BitSequence));
	if (!inputMessage)
	{
		printf("\nMemory allocation problem\n");
		return -2;
	}

	for (i = 0; i < 10485; ++i)
		memcpy(inputMessage + (i * inputPatternLength), inputPattern, inputPatternLength);

	for (i = 1048500; i < memorySize1MB; ++i)
		inputMessage[i] = 255; // All bits 1.

	exitCode = Hash(512, inputMessage, (DataLength) (memorySize1MB * 8), resultingDigest); 
		
	if (exitCode != SUCCESS)
	{
		printf("Failure occured.\n");
		return -1;
	}

    printf("The resulting digest after 'Hash()' is:\n");
    PrintDigestInHexa(resultingDigest, resultInHexa1, 64, true);
    printf("%s", resultInHexa1);
    printf("\n");

    for (k = 1; k <= memorySize1MB; k += (memorySize1MB / NUM_OF_RUNS))
    {
        exitCode = Init(&state, 512);

	    if (exitCode != SUCCESS)
		    wasFailure = true;

        numOfBlocks = (DataLength) ceil((double) memorySize1MB / k);

	    for (j = 0, currInputIndex = 0; j < (numOfBlocks - 1); ++j, currInputIndex += k)
	    {
		    exitCode = Update(&state, inputMessage + currInputIndex, k * 8); 
		    if (exitCode != SUCCESS)
			    wasFailure = true;
	    }

        // The length of the last block may be shorter than (HAIFA_INPUT_BLOCK_SIZE * 8)
        exitCode = Update(&state, inputMessage + currInputIndex, 
						  (memorySize1MB * 8) - ((numOfBlocks - 1) * (k * 8))); 
	    if (exitCode != SUCCESS)
		    wasFailure = true;
        
        exitCode = Final(&state, resultingDigest);
	    if (exitCode != SUCCESS)
		    wasFailure = true;

        if (!wasFailure)
        {
            PrintDigestInHexa(resultingDigest, resultInHexa2, 64, true);
            if (strcmp(resultInHexa1, resultInHexa2))
            {
                printf("\nComparison failed.\n");
                return -2;
            }
        }
        else
        {
            printf("\nFailure occured, couldn't even compare.\n");
            return -1;
        }
    }

    if (!wasFailure)
        printf("\nSucceeded!!!\n");

	return 0;
}

int main()
{
	SanityCheck1();
	TimeTest1();
	return 0;
}

