This README file accompanies the SWIFFTX submission package for the NIST SHA-3 competition.
In what follows we explain the directory structure and each of the files there.

/                                   Root directory
    - README.txt                    This file
    
/Reference Implementation           The directory that contains the official reference 
                                    implementation.
                                    
    - SHA3.h                        The header file that defines the NIST API.
    - SHA3.c                        The implementation of NIST API using HAIFA mode of operation
                                    and SWIFFTX compression function.
    - SWIFFTX.h                     The API for a single SWIFFTX compression function.
    - SWIFFTX.c                     The implementation of SWIFFTX compression function.
    - ProduceRandomIV.c             The code we used to produce the random IVs used in SWIFFTX.
    - ProduceRandomSBox.c           The code we used to produce the random S-Box used in SWIFFTX.
    - Tester.c                      The simple tests we wrote for initial stages of development.
    - stdint.h                      The header file we used for sized integral types in VS2005.
    - inttypes.h                    The header file we used for sized integral types in VS2005.
    - stdbool.h                     The header file we used for boolean type in VS2005.
    - makefile                      The makefile that enables to compile the reference 
                                    implementation easily in gcc.
    - Reference.sln                 The solution file in VS2005 format.
    - Reference.vcproj              The project file in VS2005 format.
     
/Optimized_32 bit                   This directory contains the optimized implementation for 
                                    32bit processors.
    - SHA3.h                        The exact copy of the reference version of this file.
    - SHA3.c                        The exact copy of the reference version of this file.
    - SWIFFTX.h                     The exact copy of the reference version of this file.
    - SWIFFTX.c                     The optimized implementation of SWIFFTX compression 
                                    function.
    - Tester.c                      The exact copy of the reference version of this file.
    - stdint.h                      The exact copy of the reference version of this file.
    - inttypes.h                    The exact copy of the reference version of this file.
    - stdbool.h                     The exact copy of the reference version of this file.
    - makefile                      The makefile that enables to compile the optimized 
                                    implementation easily in gcc.
    - Optimized32.sln               The solution file in VS2005 format.
    - Optimized32.vcproj            The project file in VS2005 format. Note that in the RELEASE
                                    all the compilation
                                    flags are set to produce the fastest code possible.

/Optimized_64 bit                   This directory contains the optimized implementation for
                                    64bit processors. Unfortunately due to time constraints 
                                    this is the exact copy of the 32bit optimized version.
    - SHA3.h                        The exact copy of the optimized 32bit version of this file.
    - SHA3.c                        The exact copy of the optimized 32bit version of this file.
    - SWIFFTX.h                     The exact copy of the optimized 32bit version of this file.
    - SWIFFTX.c                     The exact copy of the optimized 32bit version of this file.
    - Tester.c                      The exact copy of the optimized 32bit version of this file.
    - stdint.h                      The exact copy of the optimized 32bit version of this file.
    - inttypes.h                    The exact copy of the optimized 32bit version of this file.
    - stdbool.h                     The exact copy of the optimized 32bit version of this file.
    - makefile                      The exact copy of the optimized 32bit version of this file.
    - Optimized64.sln               The solution file in VS2005 format.
    - Optimized64.vcproj            The project file in VS2005 format. Note that in the RELEASE
                                    all the compilation flags are set to produce the fastest 
                                    code possible.

/Additional Implementations         The directory that contain additional implementations, in 
                                    addition to what specified by NIST.
    /SIMD                           The directory that contains SIMD implementation.
        - SHA3.h                    The exact copy of the reference version of this file.
        - SHA3.c                    The exact copy of the reference version of this file.
        - SWIFFTX.h                 The exact copy of the reference version of this file.    
        - SWIFFTX.c                 The SIMD implementation of SWIFFTX compression function.
        - makefile                  The makefile for gcc compiler. 
        - Tester.c                  The exact copy of the reference version of this file.
        
/KAT_MCT                            The directory that contains the input files for KATs and
                                    MCT specified by NIST and the results obtained from SWIFFTX
                                    for the required digest sizes.
    - ShortMsgKAT.txt               The input file for short messages KAT as specified by NIST.
    - ShortMsgKAT_224.txt           The results for short message KAT for SWIFFTX with 224bit 
                                    digest.
    - ShortMsgKAT_256.txt           The results for short message KAT for SWIFFTX with 256bit 
                                    digest.
    - ShortMsgKAT_384.txt           The results for short message KAT for SWIFFTX with 384bit 
                                    digest.
    - ShortMsgKAT_512.txt           The results for short message KAT for SWIFFTX with 512bit 
                                    digest.
    - LongMsgKAT.txt                The input file for long messages KAT as specified by NIST.
    - LongMsgKAT_224.txt            The results for long message KAT for SWIFFTX with 224bit
                                    digest.
    - LongMsgKAT_256.txt            The results for long message KAT for SWIFFTX with 256bit
                                    digest.
    - LongMsgKAT_384.txt            The results for long message KAT for SWIFFTX with 384bit
                                    digest.
    - LongMsgKAT_512.txt            The results for long message KAT for SWIFFTX with 512bit
                                    digest.
    - ExtremelyLongMsgKAT.txt       The input file for extremely long messages KAT as specified
                                    by NIST.
    - ExtremelyLongMsgKAT_224.txt   The results for extremely long message KAT for SWIFFTX with
                                    224bit digest.
    - ExtremelyLongMsgKAT_256.txt   The results for extremely long message KAT for SWIFFTX with 
                                    256bit digest.
    - ExtremelyLongMsgKAT_384.txt   The results for extremely long message KAT for SWIFFTX with 
                                    384bit digest.
    - ExtremelyLongMsgKAT_512.txt   The results for extremely long message KAT for SWIFFTX with 
                                    512bit digest.
    - MonteCarlo.txt                The input file for MonteCarlo test as specified by NIST.
    - MonteCarlo_224.txt            The results for MonteCarlo test for SWIFFTX with 224bit 
                                    digest.
    - MonteCarlo_256.txt            The results for MonteCarlo test for SWIFFTX with 256bit 
                                    digest.
    - MonteCarlo_384.txt            The results for MonteCarlo test for SWIFFTX with 384bit 
                                    digest.
    - MonteCarlo_512.txt            The results for MonteCarlo test for SWIFFTX with 512bit 
                                    digest.
                                
/Supporting Documentation                   This directory contains supplemental information.
    - Cyclic_CRH_TCC2006.pdf                The paper "Efficient Collision-Resistant Hashing 
                                            from Worst-Case Assumptions on Cyclic Lattices"
                                            by Peikert and Rosen, TCC 2006.
    - Generalized_Knapsacks_ICALP2006.pdf   The paper "Generalized compact knapsacks are 
                                            collision resistant" by Lyubashevsky and 
                                            Micciancio, ICALP 2006. 
    - Ideal_Lattices_STOC2007.pdf           The paper "Lattices that Admit Logarithmic Worst-
                                            Case to Average-Case Connection Factors" by Peikert
                                            and Rosen, STOC 2007.
    - SWIFFT_FSE2008.pdf                    The SWIFFT paper appeared in FSE 2008.
    - SWIFFT_FSE2008.ppt                    The SWIFFT presentation.
    - SWIFFTX_Report.pdf                    The main submission report on SWIFFTX in pdf.
    - SWIFFTX_Report.ps                     The main submission report on SWIFFTX in ps.
