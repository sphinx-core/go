#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SHA3.h"
#include "SWIFFTX.h"

// Calculates out IV out of the decimal expansion of e.
void PrintOurIV()
{
	// Starts after 8281828459045235360, which we used for our random salt.
	// We need 65 * 3 = 195 decimal digits, so we put here 400 (50 on each line)
	// to be on the safe side.
	const char eDecimalExpansion[] = 
{"28747135266249775724709369995957496696762772407663\
03535475945713821785251664274274663919320030599218\
17413596629043572900334295260595630738132328627943\
49076323382988075319525101901157383418793070215408\
91499348841675092447614606680822648001684774118537\
42345442437107539077744992069551702761838606261331\
38458300075204493382656029760673711320070932870912\
74437470472306969772093101416928368190255151086574"};

	BitSequence resultingIV[SWIFFTX_OUTPUT_BLOCK_SIZE] = {0};
	int i;
	int currIndex = 0;

	for (i = 0; i < SWIFFTX_OUTPUT_BLOCK_SIZE; )
	{
		char ch0[2] = {0};
		char ch1[2] = {0};
		char ch2[2] = {0};
		int currNumber = 0;

		ch0[0] = eDecimalExpansion[currIndex];
		ch1[0] = eDecimalExpansion[currIndex + 1];
		ch2[0] = eDecimalExpansion[currIndex + 2];

		currNumber = (atoi(ch0) * 100)
				   + (atoi(ch1) * 10)
				   + (atoi(ch2));

		if (currNumber < (256 * 3))
		{
			resultingIV[i++] = currNumber % 256;
		}

		currIndex += 3;
	}

	for (i = 0; i < SWIFFTX_OUTPUT_BLOCK_SIZE; ++i)
		printf("%4d,", resultingIV[i]);
}

// Produces the IV_m for each digest size.
void ProduceIVs()
{
	int i;

	const BitSequence IV[SWIFFTX_OUTPUT_BLOCK_SIZE] =
	{31, 215,  96, 150, 241, 245, 247,  93, 187,  62, 115, 212,  76, 118,  97,  35,
	 82,  59, 126, 178,  13, 166, 171, 171, 210, 135,   3,  59, 157,  84, 117,  43,
     60,  78,  39,   4,  83, 118, 226, 132,  72, 115, 234, 251, 233, 241, 195, 251,
     19,  11,  61, 187, 190, 154,  89, 149, 167, 253, 244, 249, 204, 156,  82,   8,
     168};

	unsigned char digestSizeLSB = 0;
	unsigned char digestSizeMSB = 0;

	BitSequence IV_224[SWIFFTX_OUTPUT_BLOCK_SIZE] = {0};
	BitSequence IV_256[SWIFFTX_OUTPUT_BLOCK_SIZE] = {0};
	BitSequence IV_384[SWIFFTX_OUTPUT_BLOCK_SIZE] = {0};
	BitSequence IV_512[SWIFFTX_OUTPUT_BLOCK_SIZE] = {0};

	BitSequence currInput[SWIFFTX_INPUT_BLOCK_SIZE] = {0};

	InitializeSWIFFTX();

	memcpy(currInput, IV, SWIFFTX_OUTPUT_BLOCK_SIZE);
	digestSizeLSB = 224;
	digestSizeMSB = 0;
	currInput[SWIFFTX_OUTPUT_BLOCK_SIZE] = digestSizeMSB;
	currInput[SWIFFTX_OUTPUT_BLOCK_SIZE + 1] = digestSizeLSB;

	ComputeSingleSWIFFTX(currInput, IV_224, false);

	digestSizeLSB = 0;
	digestSizeMSB = 1;
	currInput[SWIFFTX_OUTPUT_BLOCK_SIZE] = digestSizeMSB;
	currInput[SWIFFTX_OUTPUT_BLOCK_SIZE + 1] = digestSizeLSB;

	ComputeSingleSWIFFTX(currInput, IV_256, false);

	digestSizeLSB = 384 % 256;
	digestSizeMSB = 1;
	currInput[SWIFFTX_OUTPUT_BLOCK_SIZE] = digestSizeMSB;
	currInput[SWIFFTX_OUTPUT_BLOCK_SIZE + 1] = digestSizeLSB;

	ComputeSingleSWIFFTX(currInput, IV_384, false);

	digestSizeLSB = 0;
	digestSizeMSB = 2;
	currInput[SWIFFTX_OUTPUT_BLOCK_SIZE] = digestSizeMSB;
	currInput[SWIFFTX_OUTPUT_BLOCK_SIZE + 1] = digestSizeLSB;

	ComputeSingleSWIFFTX(currInput, IV_512, false);

	// Print the output:

	printf("IV_224:\n");
	for (i = 0; i < SWIFFTX_OUTPUT_BLOCK_SIZE; ++i)
		printf("%4d,", IV_224[i]);

	printf("\n\nIV_256:\n");
	for (i = 0; i < SWIFFTX_OUTPUT_BLOCK_SIZE; ++i)
		printf("%4d,", IV_256[i]);

	printf("\n\nIV_384:\n");
	for (i = 0; i < SWIFFTX_OUTPUT_BLOCK_SIZE; ++i)
		printf("%4d,", IV_384[i]);

		printf("\n\nIV_512:\n");
	for (i = 0; i < SWIFFTX_OUTPUT_BLOCK_SIZE; ++i)
		printf("%4d,", IV_512[i]);

	printf("\n\n");
}

int main111()
{
	ProduceIVs();

	return 0;
}