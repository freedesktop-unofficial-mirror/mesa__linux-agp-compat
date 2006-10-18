/*
 * Copyright (C) 2003 Tungsten Graphics
 * Copyright (C) 2003 Jeff Hartmann
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * JEFF HARTMANN, OR ANY OTHER CONTRIBUTORS BE LIABLE FOR ANY CLAIM, 
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE 
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * testagp: Test program for /dev/agpgart under Linux, slightly based off old
 * testgart program which had the following copyright notice.
 *
 * Copyright (C) 1999 Jeff Hartmann, 
 * Precision Insight, Inc., Xi Graphics, Inc.
 *
 * Currently it works on ia32 compatible archs only, however it should be 
 * trivial to convert it for use on other archs.
 *
 * Changelog:
 * Dec 2002: Initial conversion of testgart program to something more useful.
 * Jan 2003: Add AGP 3.0 tests for new ioctl's that are exported.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <linux/types.h>
#include "agpgart.h"
#include <asm/mtrr.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>

#ifndef AGP_RESERVED_KEY
#define AGP_RESERVED_KEY	(-2)
#endif

/* These should probably be variables, since the agp version 3.0
 * capable /dev/agpgart will provide this information.
 */
#define AGP_PAGE_SHIFT		12
#define AGP_PAGE_SIZE		(1 << AGP_PAGE_SHIFT)
#define PTR_TO_PAGE(x, y)	((char *)(x) + ((y) << AGP_PAGE_SHIFT))
#define CONST_PATTERN_1 	0xdeadbeaf
#define CONST_PATTERN_2 	0xaef3456a
/* Number of bytes to dump of an error condition by default */
#define HEXDUMP_BYTES		128
/* Number of hex digits to print out for the index in a hex dump */
#define NUMBER_IDX_PLACES	4
#define TEST_GET_MAP_SUPPORT	2

/* Global information about the reserved block of memory */
int agpgartSupportsGetMap = TEST_GET_MAP_SUPPORT;
agp_map reserved_map;

/* Global pointer to gart and the gart file descriptor. */
unsigned char *gart;
int gartfd;

/* General Utility Functions */

/* Call xchg and cpuid asm instructions to flush the write combining cache.
 * Could be replaced with sfence on some cpus or perhaps just the code
 * for mb() from the kernel
 */
void flushWriteCombining(void) 
{
   int xchangeDummy;
   __asm__ volatile(" push %%eax ; "
		    " xchg %%eax, %0 ;"
		    " pop %%eax" : : "m" (xchangeDummy));
   __asm__ volatile(" push %%eax ; "
		    " push %%ebx ; "
		    " push %%ecx ; "
		    " push %%edx ; "
		    " movl $0,%%eax ; "
		    " cpuid ; "
		    " pop %%edx ; "
		    " pop %%ecx ; "
		    " pop %%ebx ; "
		    " pop %%eax" : /* no outputs */ :  /* no inputs */ );
}

int usec(void)
{
  struct timeval tv;
  struct timezone tz;
  
  gettimeofday( &tv, &tz );
  return (tv.tv_sec & 2047) * 1000000 + tv.tv_usec;
}

int coverRangeWithMTRR(int base, int range, int type)
{
   int count;   
   int mtrr;

   if ((mtrr = open("/proc/mtrr", O_WRONLY, 0)) == -1) {
      if (errno == ENOENT) {
	 perror("/proc/mtrr not found: MTRR not enabled\n");
      }  else {
	 perror("Error opening /proc/mtrr:");
	 perror("MTRR not enabled\n");
      }
      mtrr = -1;
   }

   /* set it if we aren't just checking the number */
   if (mtrr != -1 && type != -1 ) {
      struct mtrr_sentry sentry;
      
      sentry.base = base;
      sentry.size = range;
      sentry.type = type;
      
      if(ioctl(mtrr, MTRRIOC_ADD_ENTRY, &sentry) == -1 ) {
	 perror("Error during ioctl MTRR_ADD_ENTRY\n");
	 exit(1);
      }
   }
}

/* size is in bytes */
void fillBufConstPattern(unsigned int pattern, char *bufPtr,
			 int size)
{
   unsigned int *buf = (unsigned int *)bufPtr;
   int i;

   for(i = 0; i < size / sizeof(unsigned int); i++) {
      buf[i] = pattern;
   }
}

/* Returns the failed index on the error, -1 on success */
int checkBufConstPattern(unsigned int pattern, char *bufPtr,
			 int size)
{
   unsigned int *buf = (unsigned int *)bufPtr;
   int i;

   for(i = 0; i < size / sizeof(unsigned int); i++) {
      if(buf[i] != pattern) return i;
   }
   return -1;
}

void createRandomBuffer(char *bufPtr,
			int size)
{
   unsigned int *buf = (unsigned int *)bufPtr;
   int i;

   for(i = 0; i < size / sizeof(unsigned int); i++) {
      buf[i] = rand();
   }
}

static inline char *valueToHex(int digit)
{
   switch(digit & 0xf) {
    case 0: return "0";
    case 1: return "1";
    case 2: return "2";
    case 3: return "3";
    case 4: return "4";
    case 5: return "5";
    case 6: return "6";
    case 7: return "7";
    case 8: return "8";
    case 9: return "9";
    case 10: return "a";
    case 11: return "b";
    case 12: return "c";
    case 13: return "d";
    case 14: return "e";
    case 15: return "f";
   }
}

/* Only used to print upto 16 bytes at a time so 80 is safe */
void printBytes(char *data, int numBytes)
{
   char temp[80];
   int i;

   temp[0] = '\0';
   for(i = 0; i < numBytes; i++) {
      strcat(temp, valueToHex(data[i] >> 4));
      strcat(temp, valueToHex(data[i]));
      strcat(temp, " ");
   }
   printf("%s\n", temp);
}


void printIdx(int index, int places)
{
   char temp[80];
   int i;

   temp[0] = '\0';
   --places;
   for(i = places; i >= 0; i--) {
      strcat(temp, valueToHex(index >> (i * 4)));
   }
   printf("%s : ", temp);
}

void printHexDump(char *data, int outputBytes)
{
   int loop16 = outputBytes / 16;
   int remainBytes = outputBytes % 16;
   int i;
   
   for(i = 0; i < loop16; i++, data += 16) {
      printIdx(i * 16, NUMBER_IDX_PLACES);
      printBytes(data, 16);
   }
   if(remainBytes) {
      printIdx(i * 16, NUMBER_IDX_PLACES);
      printBytes(data, remainBytes);
   }
}

int memoryBenchmark(void *buffer, int dwords) 
{
   int i;
   int start, end;
   int mb;
   int *base;
  
   base = (int *)buffer;
   start = usec();
   for ( i = 0 ; i < dwords ; i += 8 ) {
      base[i] =
	base[i+1] =
	base[i+2] =
	base[i+3] =
	base[i+4] =
	base[i+5] =
	base[i+6] =
	base[i+7] = 0xdeadbeef;
   }
   end = usec();
   mb = ( (float)dwords / 0x40000 ) * 1000000 / (end - start);
   printf("MemoryBenchmark: %i mb/s\n", mb );
   return mb;
}

/* Functions to perform /dev/agpgart ioctls and general agp setup */

int unbindMemory(int key)
{
   agp_unbind unbind;
   
   unbind.key = key;
#ifdef DEBUG
   printf("Using AGPIOC_UNBIND\n");
#endif
   if(ioctl(gartfd, AGPIOC_UNBIND, &unbind) != 0) {
      perror("ioctl(AGPIOC_UNBIND)");
      exit(1);
   }

   return 0;
}

int bindMemory(int key, int page)
{
   agp_bind bind;
   
   bind.key = key;
   bind.pg_start = page;
#ifdef DEBUG
   printf("Using AGPIOC_BIND\n");
#endif
   if(ioctl(gartfd, AGPIOC_BIND, &bind) != 0) {
      perror("ioctl(AGPIOC_BIND)");
      exit(1);
   }

   return 0;
}

int allocMemory(int size)
{
   agp_allocate entry;

   entry.type = 0;
   entry.pg_count = size;
#ifdef DEBUG
   printf("Using AGPIOC_ALLOCATE\n");
#endif
   if(ioctl(gartfd, AGPIOC_ALLOCATE, &entry) != 0) {
      perror("ioctl(AGPIOC_ALLOCATE)");
      exit(1);
   }
   return entry.key;
}

int allocAndBind(int page, int size)
{
   int key = allocMemory(size);

   bindMemory(key, page);   
   return key;
}

int freeMemory(int key)
{
#ifdef DEBUG
   printf("Using AGPIOC_DEALLOCATE\n");
#endif
   if(ioctl(gartfd, AGPIOC_DEALLOCATE, key) != 0) {
      perror("ioctl(AGPIOCREMOVE)");
      exit(1);
   }

   return 0;
}

void getAgpInfo(agp_info *info)
{
#ifdef DEBUG
   printf("Using AGPIOC_INFO\n");
#endif
   if(ioctl(gartfd, AGPIOC_INFO, info) != 0) {
      perror("ioctl(AGPIOC_INFO)");
      exit(1);
   }
}

int getCurrentPages(void)
{
   agp_info info;
   
   getAgpInfo(&info);
   return info.pg_used;
}

void openAgpDevice(int flags)
{
   gartfd = open("/dev/agpgart", flags);
   if (gartfd == -1) {	
      perror("Open of /dev/agpgart failed!");
      exit(1);
   }
}

size_t getApertureSize(void)
{
   agp_info info;
   
   getAgpInfo(&info);
   return info.aper_size;
}

void unmapAgpAperture(size_t aper_size)
{
   if(gartfd != -1) {
      munmap(gart, aper_size);
      gart = (char *)0xffffffff;
      close(gartfd);
      gartfd = -1;
   }
}

void mapAgpAperture(size_t aper_size, int prot)
{
   gart = mmap(NULL, aper_size * 0x100000,
	       prot, MAP_SHARED, gartfd, 0);
#ifdef DEBUG
   if(gart == (unsigned char *)0xffffffff) {
      perror("mmap failed with ");
   }
#endif
}

int supportsGetMap(void)
{   
   if(agpgartSupportsGetMap == TEST_GET_MAP_SUPPORT) {
      memset(&reserved_map, 0, sizeof(reserved_map));
      reserved_map.key = AGP_RESERVED_KEY;

      if(ioctl(gartfd, AGPIOC_GETMAP, &reserved_map) == -1 && 
	 errno == ENOTTY) {
	 agpgartSupportsGetMap = FALSE;
      } else {
	 agpgartSupportsGetMap = TRUE;
      }
   }

   return agpgartSupportsGetMap;
}

/* Only call if supportsGetMap returns TRUE */
int printReserved(void)
{
   printf("Reserved agp memory block: \n");
   printf("bound: %s, ", reserved_map.is_bound ? "yes" : "no");
   printf("offset: 0x%08x, ", reserved_map.pg_start * AGP_PAGE_SIZE);
   printf("size: 0x%08x\n", reserved_map.page_count * AGP_PAGE_SIZE);
}

int checkPageAvailable(int page)
{
   agp_map map;
   off_t pg_start;
   off_t pg_end;

   /* If we don't support get map, the page is available */
   if(supportsGetMap() == FALSE) return TRUE;

   /* Reserved map is of zero size or reserved region not bound, so page 
    * is available */
   if(reserved_map.page_count == 0 ||
      reserved_map.is_bound == FALSE) return TRUE;

   /* If we are equal to or greater than the first page but
    * less then the first page + page count then we are within the
    * reserved region.  This page isn't available.  Otherwise it
    * is available for use.
    */
   pg_start = reserved_map.pg_start;
   pg_end = reserved_map.pg_start + reserved_map.page_count - 1;
   if(pg_start <= page && 
      page <= pg_end) return FALSE;

   return TRUE;
}

int getNumberOfPages(void)
{
   unsigned long apertureSize = getApertureSize() * 0x100000;
   int numberPages = apertureSize / AGP_PAGE_SIZE;

   return numberPages;
}

/* Very stupid brute force approach to finding a slot of size,
 * if we want this to be fast we need to make a memory allocator of some
 * kind.  This test code doesn't have to be terribly efficent so we
 * don't care.
 * This function only handles the reserved memory, nothing else at the
 * moment.  Its all we need so don't worry.
 * 
 * returns -1 if we can't find such a region.
 */

int findFirstRegionOfSize(int numberPages)
{
   
   int pagesTotal = getNumberOfPages();
   int i, k;
   
   for(i = 0; i < pagesTotal; i++) {
      if(checkPageAvailable(i) == TRUE) {
	 /* We already know the first page is available */
	 for(k = 1; k < numberPages; k++) {
	    if(checkPageAvailable(i + k) == FALSE) break;
	 }
	 /* Full region is available, return i as the index */
	 if(k == numberPages) return i;
	 /* Okay we didn't get the full region and i + k is not available,
	  * so we continue testing at i + k + 1
	  */
	 i = i + k + 1;
      }
   }
   return -1;
}

/* Returns the size of the aperture in megabytes */
int initializeAgp(void)
{
   agp_info info;
   agp_setup setup;

#ifdef DEBUG
   printf("Using AGPIOC_ACQUIRE\n");
#endif
   if(ioctl(gartfd, AGPIOC_ACQUIRE) != 0) {
      perror("ioctl(AGPIOC_ACQUIRE)");
      exit(1);
   }
   getAgpInfo(&info);
   
   printf("Basic information extracted from /dev/agpgart:\n");
   printf("Agpgart Interface Version: %i.%i\n", 
	  info.version.major, 
	  info.version.minor);
   printf("Bridge pci id: 0x%lx\n", info.bridge_id);
   printf("Agp mode: 0x%lx\n", info.agp_mode);
   printf("Aperture base: 0x%lx\n", info.aper_base);
   printf("Aperture size: %iMB\n", info.aper_size);
   printf("Pages allowed total: %i\n", info.pg_total);
   printf("Pages allowed from memory: %i\n", info.pg_system);
   printf("Pages currently used: %i\n", info.pg_used);

   coverRangeWithMTRR(info.aper_base, info.aper_size * 0x100000, 
		      MTRR_TYPE_WRCOMB);
   
   mapAgpAperture(info.aper_size, PROT_READ | PROT_WRITE);

   gart = mmap(NULL, info.aper_size * 0x100000, 
	       PROT_READ | PROT_WRITE, MAP_SHARED, gartfd, 0);

   if(gart == (unsigned char *) 0xffffffff) {
      close(gartfd);
      exit(1);
   }

   setup.agp_mode = info.agp_mode;
#ifdef DEBUG
   printf("Using AGPIOC_SETUP\n");
#endif
   if(ioctl(gartfd, AGPIOC_SETUP, &setup) != 0) {
      perror("ioctl(AGPIOC_SETUP)");
      exit(1);
   }

   if(supportsGetMap() == TRUE) {
      printReserved();
   }
   return info.aper_size;
}

/* Test functions start in earnest */
void simpleBenchMark(unsigned char *regionPtr)
{
   int i;
   unsigned long *tempPtr;

   /* Make sure we are paged in, then do the performance test */
   tempPtr = (unsigned long *)regionPtr;
   for(i = 0; i < (4 * 1024 * 1024) / sizeof(unsigned long); i++) {
      tempPtr[i] = 0;
   }
   printf("Benchmarking writes:\n");
   
   i = memoryBenchmark(regionPtr, (1024 * 1024 * 4) / 4) +
     memoryBenchmark(regionPtr, (1024 * 1024 * 4) / 4) +
     memoryBenchmark(regionPtr, (1024 * 1024 * 4) / 4);
  
   printf("Average speed: %i mb/s\n", i / 3);
}

int oldIntegrity(int firstPage, int key1, int key2,
		 unsigned char *regionPtrStageOne,
		 unsigned char *regionPtrStageTwo,
		 int do_rebind)
{
   int i, worked1 = 1, worked2 = 1;

   printf("Testing data integrity (1st pass): ");
   fflush(stdout);
   
   flushWriteCombining();
  
   for(i=0; i < 8 * 0x100000; i++) {
      regionPtrStageOne[i] = i % 256;
   }

   flushWriteCombining();

   for(i=0; i < 8 * 0x100000; i++) {
      if(!(regionPtrStageOne[i] == i % 256)) {
#ifdef DEBUG
	 printf("failed on %i, gart[i] = %i\n", i, regionPtr[i]);
#endif
	 worked1 = 0;
	 break;
      }
   }

   if (!worked1) printf("failed on first pass!\n");
   else printf("passed on first pass.\n");

   if(do_rebind == TRUE) {
      if(key1 >= 0 && key2 >= 0) {
	 unbindMemory(key1);
	 unbindMemory(key2);
	 bindMemory(key1, firstPage);
	 bindMemory(key2, firstPage + 1024);
      } else if(key1 >= 0) {
	 /* Special test case where we know we are unbound. */
	 bindMemory(key1, firstPage);
      }
   }

   printf("Testing data integrity (2nd pass): ");
   fflush(stdout);

   for(i=0; i < 8 * 0x100000; i++) {
      if(!(regionPtrStageTwo[i] == i % 256)) {
#ifdef DEBUG
	 printf("failed on %i, gart[i] = %i\n", i, regionPtr[i]);
#endif
	 worked2 = 0;
      }
   }

   if(!worked2) printf("failed on second pass!\n");
   else printf("passed on second pass.\n");

   return worked1 & worked2;
}

/* Quick benchmark and very simple data integrity test */
void legacyTests()
{
   int key1, key2;
   int firstPage = 0;
   int worked;
   int totalStart = getCurrentPages();

   printf("\nNow performing legacy testgart functionality.\n");
   firstPage = findFirstRegionOfSize(2048);
   if(firstPage == -1) {
      printf("There are no 8MB regions, so we can't perform the legecy "
	     "tests.\n");
      return;
   }

   printf("Testing from offset into gart : 0x%08x\n", 
	  (unsigned int)(firstPage * AGP_PAGE_SIZE));
   key1 = allocAndBind(firstPage, 1024);
   key2 = allocAndBind(firstPage + 1024, 1024);

   if(key1 >= 0 && key2 >= 0 && getCurrentPages() - totalStart == 2048) {
      printf("Successfully allocated 8 megs of memory from /dev/agpgart\n");
   } else {
      printf("Couldn't successfully allocate 8 megs of GART memory\n");
      printf("Legacy tests failed!\n");
      return;
   }

   simpleBenchMark(PTR_TO_PAGE(gart, firstPage));

   worked = oldIntegrity(firstPage, key1, key2, PTR_TO_PAGE(gart, firstPage),
			 PTR_TO_PAGE(gart, firstPage), TRUE);

   freeMemory(key1);
   freeMemory(key2);   
   if(getCurrentPages() - totalStart == 0) {
      printf("Successfully deallocated memory from /dev/agpgart.\n");
   } else {
      printf("Memory was not successfully deallocated\n");
      printf("Start total : %d, Current total: %d\n",
	     totalStart, getCurrentPages());
      printf("Legacy tests failed!\n");
      return;
   }
   if(worked) printf("Legacy tests passed.\n");
   else printf("Legacy tests failed!\n");
}

/* Takes aperture size in megabytes,
 * Plugs in pages around any reserved area we know about.
 */
void apertureIntegrityTests(int aper_size)
{
   unsigned long apertureSize = aper_size * 0x100000;
   int numberPages = apertureSize / AGP_PAGE_SIZE;
   int firstPage = 0;
   char *pagePtr;
   char *patternBuf = malloc(2 * AGP_PAGE_SIZE);
   int sectionKey;
   int i;
   int test;
   
   if(!patternBuf) {
      printf("Failed allocating pattern buffer!");
      exit(1);
   }
   
   /* Test with one page first, fill it with a constant pattern
    * then move it around the whole aperture and test for the correct value
    * at that location.
    */
   printf("\nAperture Integrity Tests:\n"
	  "Now performing various integrity tests on the agp aperture.\n");
   printf("These are useful to see if an agpgart driver for a specific "
	  "chipset\n");
   printf("is functioning correctly\n\n");
   printf("Simple Constant Pattern Test 1:\n");
   printf("\tThis test allocates a single page of agp memory and fills it\n");
   printf("with a constant pattern.  It then binds it into each available\n");
   printf("page location in the aperture and tests to make sure it "
	  "matches.\n");
   printf("Performing Simple Constant Pattern Test 1: ");
   fflush(stdout);

   firstPage = findFirstRegionOfSize(1);
   if(firstPage == -1) {
      printf("Fatal error, can't find any size 1 regions.\n");
      printf("Exiting.\n");
      exit(1);
   }
#if 0
   printf("First Page (%d)\n", firstPage);
#endif
   sectionKey = allocAndBind(firstPage, 1);
   /* Start at the beginning of the aperture */
   
   pagePtr = PTR_TO_PAGE(gart, firstPage);
   fillBufConstPattern(CONST_PATTERN_1, pagePtr, AGP_PAGE_SIZE);
   flushWriteCombining();
   unbindMemory(sectionKey);
   for(i = firstPage; i < numberPages; i++) {
      if(checkPageAvailable(i) == FALSE) continue;
      bindMemory(sectionKey, i);
      pagePtr = PTR_TO_PAGE(gart, i);
      test = checkBufConstPattern(CONST_PATTERN_1, pagePtr, AGP_PAGE_SIZE);
      if(test != -1) {
	 printf("failed!\n");
	 printf("Simple constant pattern test has failed at page %d\n",
		i);
	 printf("The Dword at offset %d from the start of that page was "
		"incorrect.\n", test);
	 printf("Expected : [0x%lx], Got : [0x%lx]\n", CONST_PATTERN_1,
		((unsigned int *)pagePtr) + test);
	 printf("Integrity tests failed\n");
	 unbindMemory(sectionKey);
	 freeMemory(sectionKey);
	 return;
      }
      unbindMemory(sectionKey);
   }
   printf("passed.\n");
   fflush(stdout);
   freeMemory(sectionKey);
   
   /* Do the same test as above but do it with two pages */
   firstPage = findFirstRegionOfSize(2);
   if(firstPage == -1) {
      printf("Fatal error, can't find any size 2 regions.\n");
      printf("Exiting.\n");
      exit(1);
   }
   sectionKey = allocAndBind(firstPage, 2);
   printf("\nSimple Constant Pattern Test 2:\n");
   printf("\tThis test allocates two pages of agp memory and fills them\n");
   printf("with two seperate constant patterns.  It then binds it into"
	  " each\n");
   printf("available page pair in the aperture and tests to make sure it "
	  "matches.\n");
   printf("Performing Simple Constant Pattern Test 2: ");
   fflush(stdout);

   pagePtr = PTR_TO_PAGE(gart, firstPage);
   fillBufConstPattern(CONST_PATTERN_1, pagePtr, AGP_PAGE_SIZE);
   fillBufConstPattern(CONST_PATTERN_2, pagePtr + AGP_PAGE_SIZE, 
		       AGP_PAGE_SIZE);
   flushWriteCombining();
   unbindMemory(sectionKey);
   
   for(i = firstPage; i < numberPages; i += 2) {
      if(checkPageAvailable(i) == FALSE ||
	 checkPageAvailable(i + 1) == FALSE) continue;
      if(numberPages - i < 2) continue;
      bindMemory(sectionKey, i);
      pagePtr = PTR_TO_PAGE(gart, i);
      test = checkBufConstPattern(CONST_PATTERN_1, pagePtr, AGP_PAGE_SIZE);
      if(test != -1) {
	 printf("failed!\n");
	 printf("Simple constant pattern test has failed at page %d\n",
		i);
	 printf("The Dword at offset %d from the start of that page was "
		"incorrect.\n", test);
	 printf("Expected : [0x%lx], Got : [0x%lx]\n", CONST_PATTERN_1,
		((unsigned int *)pagePtr) + test);
	 printf("Integrity test failed\n");
	 unbindMemory(sectionKey);
	 freeMemory(sectionKey);
	 return;
      }
      test = checkBufConstPattern(CONST_PATTERN_2, pagePtr + AGP_PAGE_SIZE, 
				  AGP_PAGE_SIZE);
      if(test != -1) {
	 printf("failed!\n");
	 printf("Simple constant pattern test has failed at page %d\n",
		i + 1);
	 printf("The Dword at offset %d from the start of that page was "
		"incorrect.\n", test);
	 printf("Expected : [0x%lx], Got : [0x%lx]\n", CONST_PATTERN_2,
		((unsigned int *)(pagePtr + AGP_PAGE_SIZE)) + test);
	 printf("Integrity test failed\n");
	 unbindMemory(sectionKey);
	 freeMemory(sectionKey);
	 return;
      }
      unbindMemory(sectionKey);
   }
   printf("passed.\n");
   fflush(stdout);

   pagePtr = PTR_TO_PAGE(gart, firstPage);
   bindMemory(sectionKey, firstPage);
   createRandomBuffer(patternBuf, 2 * AGP_PAGE_SIZE);
   memcpy(pagePtr, patternBuf, 2 * AGP_PAGE_SIZE);
   flushWriteCombining();
   unbindMemory(sectionKey);

   printf("\nRandom Pattern Test:\n");
   printf("\tThis test allocates two pages of agp memory and fills them\n");
   printf("with a random pattern.  It then binds it into each available\n");
   printf("page pair in the aperture and tests to make sure it matches.\n");
   printf("Performing Random Pattern Test: ");
   fflush(stdout);

   for(i = firstPage; i < numberPages; i += 2) {
      if(checkPageAvailable(i) == FALSE ||
	 checkPageAvailable(i + 1) == FALSE) continue;
      if(numberPages - i < 2) continue;

      bindMemory(sectionKey, i);
      pagePtr = PTR_TO_PAGE(gart, i);
      test = memcmp((void *)pagePtr, (void *)patternBuf, 2 * AGP_PAGE_SIZE);

      if(test != 0) {
	 printf("failed!\n");
	 printf("Random pattern test has failed at page %d\n",
		i);
	 printf("Hex dump of first %d bytes of expected data:\n",
		HEXDUMP_BYTES);
	 printHexDump(patternBuf, HEXDUMP_BYTES);
	 printf("\nHex dump of first %d bytes of actual data:\n",
		HEXDUMP_BYTES);
	 printHexDump(pagePtr, HEXDUMP_BYTES);
	 printf("\nIntegrity test failed\n");
	 unbindMemory(sectionKey);
	 freeMemory(sectionKey);
	 return;
      }
      unbindMemory(sectionKey);
   }
   printf("passed.\n");
   fflush(stdout);

   freeMemory(sectionKey);
   
   printf("\nAperture Integrity Tests Complete\n");
}

#define RECYCLE_KEYS_TO_TEST 10
/* Test key recycling mechanism to make sure its working correctly. */
void keyRecycleTest()
{
   int keys[RECYCLE_KEYS_TO_TEST];
   int newKeys[3];
   int midpt, start, end;
   int i;

   printf("\nKey Recycle Test:\n");
   printf("This test insures that the key recycling is functioning "
	  "properly.\n");
   printf("This is needed to insure that an Xserver can continue to "
	  "recycle\n");
   printf("and not leak keys, since there are only a finite amount.\n");
   printf("\nNow peforming key recycle test: ");

   for(i = 0; i < RECYCLE_KEYS_TO_TEST; i++) {
      int key = allocMemory(1);
      if(key < 0) {
	 printf("failed!\n");
	 printf("Failed to allocate key to test with.\n");
	 return;
      }
      keys[i] = key;
   }
   /* Hold onto the keys values */
   midpt = keys[RECYCLE_KEYS_TO_TEST / 2];
   start = keys[0];
   end = keys[RECYCLE_KEYS_TO_TEST - 1];

   freeMemory(midpt);
   freeMemory(start);
   freeMemory(end);
   
   for(i = 0; i < 3; i++) {
      int key = allocMemory(1);
      if(key < 0) {
	 printf("failed!\n");
	 printf("Failed to allocate key to test with.\n");
	 return;
      }
      newKeys[i] = key;
   }
   if(start != newKeys[0] ||
      midpt != newKeys[1] ||
      end != newKeys[2]) {
      printf("failed!\n");
   } else {
      printf("passed.\n");
   }
   
   keys[RECYCLE_KEYS_TO_TEST / 2] = newKeys[1];
   keys[0] = newKeys[0];
   keys[RECYCLE_KEYS_TO_TEST - 1] = newKeys[2];

   for(i = 0; i < RECYCLE_KEYS_TO_TEST; i++) {
      freeMemory(keys[i]);
   }
   printf("\n");
}

#define CLIENTS_TO_TEST 	2
#define CLIENT_SLEEP_PERIOD	3

int initializeClient(agp_region *region)
{
#ifdef DEBUG
   printf("Using AGPIOC_RESERVE\n");
#endif
   if(ioctl(gartfd, AGPIOC_RESERVE, region) != 0) {
      perror("ioctl(AGPIOC_RESERVE)");
      exit(1);
   }

   return 0;
}

void clientTestOne(int aper_size, int create_segments)
{
   unsigned long apertureSize = aper_size * 0x100000;
   int numberPages = apertureSize / AGP_PAGE_SIZE;
   pid_t clients[CLIENTS_TO_TEST];
   struct passwd *userNobody;
   agp_region region;
   agp_segment segment;
   int passed = 1;
   int i;
   
   region.seg_count = 1;
   region.seg_list = &segment;
   segment.pg_start = 0;
   segment.pg_count = numberPages;
   segment.prot = PROT_READ;

   userNobody = getpwnam("nobody");
   if(!userNobody) {
      printf("failed!\n");
      printf("Can not perform client test since user nobody can't be found\n");
      return;
   }
   for(i = 0; i < CLIENTS_TO_TEST; i++) {
      pid_t cPid = fork();
      
      if(cPid == 0) {
	 /* Client path */
	 /* Just test to see if the client could map the aperture */
	 unmapAgpAperture(aper_size);
	 setuid(userNobody->pw_uid);
	 sleep(CLIENT_SLEEP_PERIOD);
	 openAgpDevice(O_RDONLY);
	 mapAgpAperture(aper_size, PROT_READ);

	 if(gart == (unsigned char *)0xffffffff) {
	    exit(1);
	 } else {
	    exit(0);
	 }	 
      } else if(cPid == -1) {
	 /* Error path */
	 int k;
	 for(k = 0; k < i; k++) {
	    kill(clients[k], SIGKILL);
	 }
	 printf("failed!\n");
	 printf("Couldn't create enough clients\n");
	 return;
      } else {
	 /* Normal Path */
	 clients[i] = cPid;
      }
   }
   /* Let the clients do their thing */
   sleep(1);
   if(create_segments == 1) {
      /* Setup the segments with the proper pids */
      for(i = 0; i < CLIENTS_TO_TEST; i++) {
	 region.pid = clients[i];
	 initializeClient(&region);
      }
   }
   for(i = 0; i < CLIENTS_TO_TEST; i++) {
      int status;
      waitpid(clients[i], &status, 0);
      if(WIFEXITED(status) && WEXITSTATUS(status) != 0) {
	 /* Failure */
	 if(create_segments && passed) {
	    printf("failed!\n");
	    printf("%d failed to map the agp aperture\n", clients[i]);
	 }
	 passed = 0;
      }
   }

   if(passed && create_segments) printf("passed.\n");
   if(!passed && !create_segments) printf("passed.\n");
   if(passed && !create_segments) printf("failed.\n");
}

void clientTest(int aper_size)
{
   printf("\nClient Permissions Test:\n");
   printf("\tThis test tests the ability of /dev/agpgart to mmap the "
	  "aperture\n");
   printf("into a clients process space.\n");
   printf("\tThis test will fail if the user nobody can't read the\n");
   printf("/dev/agpgart device.  This test only tests read mappings\n");
   printf("since most installations have set permissions as to only allow "
	  "reads.\n");
   printf("The first test checks to see if permission setting works. "
	  " While\n");
   printf("the second test checks to see if the mmap is blocked properly.\n");
   printf("\nNow peforming client permissions test: ");
   fflush(stdout);
   clientTestOne(aper_size, 1);
   printf("\nNow testing permission failure case: ");
   fflush(stdout);
   clientTestOne(aper_size, 0);
}

void testMemoryFailures(int aper_size)
{
   unsigned long apertureSize = aper_size * 0x100000;
   int numberPages = apertureSize / AGP_PAGE_SIZE;
   int allocKey1, allocKey2, allocKey3;
   int firstPage = 0;
   agp_bind bind;

   /* This test set check for some bad things are handled properly. */
   allocKey1 = allocMemory(1);
   allocKey2 = allocMemory(2);
   allocKey3 = allocMemory(3);

   printf("\nMemory Ioctl Sanity Test:\n");
   printf("\tThis set of tests checks that the proper error values are "
	  "returned\n");
   printf("from /dev/agpgart when several incorrect requests are performed.\n");
   
   /* Testing double freeing */
   printf("\nNow testing double freeing a block of agp memory: ");
   fflush(stdout);
   freeMemory(allocKey3);
   if(ioctl(gartfd, AGPIOC_DEALLOCATE, allocKey3) != -1 &&
      errno != EINVAL) {
      printf("failed!\n");
      printf("Deallocate ioctl didn't return expected error value.\n");
   } else {
      printf("passed.\n");
   }
   
   /* Testing inserting memory past the aperture end */
   bind.key = allocKey1;
   bind.pg_start = numberPages;
   printf("Now testing binding a single page past the agp aperture end: ");
   fflush(stdout);
   if(ioctl(gartfd, AGPIOC_BIND, &bind) != -1 &&
      errno != EINVAL) {
      printf("failed!\n");
      printf("Bind ioctl didn't return expected error value.\n");
      printf("Inserting past the end of the agp aperture didn't fail\n");
      printf("properly.\n");
   } else {
      printf("passed.\n");
   }
   bind.key = allocKey2;
   bind.pg_start = numberPages - 1;
   printf("Now testing bind with a block lying inside and outside: ");
   fflush(stdout);
   if(ioctl(gartfd, AGPIOC_BIND, &bind) != -1 &&
      errno != EINVAL) {
      printf("failed!\n");
      printf("Bind ioctl didn't return expected error value.\n");
      printf("Inserting past the end of the agp aperture didn't fail\n");
      printf("properly for two pages.\n");
   } else {
      printf("passed.\n");
   }

   /* Test several busy conditions */
   firstPage = findFirstRegionOfSize(2);
   if(firstPage == -1) {
      printf("Fatal error, no regions of 2 pages inside aperture, exiting\n");
      exit(1);
   }
   
   bind.key = allocKey1;
   bind.pg_start = firstPage;
   
   bindMemory(allocKey1, firstPage);
   printf("Now testing double binding of the same block of memory: ");
   fflush(stdout);
   if(ioctl(gartfd, AGPIOC_BIND, &bind) != -1 &&
      errno != EINVAL) {
      printf("failed!\n");
      printf("Bind ioctl didn't return the expected error value.\n");
   } else {
      printf("passed.\n");
   }

   bind.key = allocKey2;
   bind.pg_start = firstPage;
   printf("Now testing binding another block of memory to the same place: ");
   fflush(stdout);
   if(ioctl(gartfd, AGPIOC_BIND, &bind) != -1 &&
      errno != EBUSY) {
      printf("failed!\n");
      printf("Bind ioctl didn't return a busy condition as expected.\n");
   } else {
      printf("passed\n");
   }
   unbindMemory(allocKey1);
   bindMemory(allocKey1, firstPage + 1);
   printf("Now testing binding a block of memory within anothers bounds: ");
   fflush(stdout);
   if(ioctl(gartfd, AGPIOC_BIND, &bind) != -1 &&
      errno != EBUSY) {
      printf("failed!\n");
      printf("Bind ioctl didn't return a busy condition as expected.\n");
   } else {
      printf("passed\n");
   }
   freeMemory(allocKey1);
   printf("Now testing if free automatically unbound a bound page: ");
   if(ioctl(gartfd, AGPIOC_BIND, &bind) != 0) {
      printf("failed!\n");
      perror("Bind shouldn't have failed.  Reason");
   } else {
      printf("passed\n");
   }
   freeMemory(allocKey2);
}


/* A set of tests of the agp 3.0 functionality if it is available
 * from this /dev/agpgart.
 */
agp_driver_info *agp_alloc_driver_info(int ctx)
{
   agp_query_request rq;
   agp_driver_info *drv;

   rq.ctx = ctx;

   if(ioctl(gartfd, AGPIOC_QUERY_SIZE, &rq) != 0) {
      perror("query_size");
      return NULL;
   }
   drv = malloc(rq.size);
   return drv;
}

int agp_copy_driver_info(int ctx, agp_driver_info *buffer)
{
   agp_query_request rq;
   
   rq.ctx = ctx;
   rq.buffer = (void *)buffer;
   if(ioctl(gartfd, AGPIOC_QUERY_CTX, &rq) != 0) {
      perror("query ctx");
      return errno;
   }
   return 0;
}

void agp_print_one_master(agp_master *info)
{
   printf("\nAgp Master Information:\n");
   printf("Agp version %d.%d\n", info->agp_major_version, 
	  info->agp_minor_version);
   printf("Request Depth : %d\n", info->num_requests_enqueue);
   printf("Pci Vender ID : 0x%04x\n", info->master_pci_id >> 16);
   printf("Pci Device ID : 0x%04x\n", info->master_pci_id & 0xffff);
   if(info->agp_major_version >= 3) {
      printf("Calibration cycle : %d ms\n", info->calibration_cycle_ms);
      if(info->flags & AGP_SUPPORTS_AGP_3_0_ENABLED) {
	 printf("Agp Modes Supported : %s%s\n",
		(info->flags & AGP_SUPPORTS_SPEED_4X) ? "4X " : "",
		(info->flags & AGP_SUPPORTS_SPEED_8X) ? "8X " : "");
      } else {
	 printf("Agp Modes Supported : %s%s%s\n",
		(info->flags & AGP_SUPPORTS_SPEED_1X) ? "1X " : "",
		(info->flags & AGP_SUPPORTS_SPEED_2X) ? "2X " : "",
		(info->flags & AGP_SUPPORTS_SPEED_4X) ? "4X " : "");
      }
      printf("Supports isochronous operation mode : %s\n",
	     (info->flags & AGP_SUPPORTS_ISOCHRONOUS) ? "true" : "false");
      printf("Supports Sideband addressing : %s\n",
	     (info->flags & AGP_SUPPORTS_SBA) ? "true" : "false");
      printf("Supports Fast write : %s\n",
	     (info->flags & AGP_SUPPORTS_FAST_WRITE) ? "true" : "false");
      printf("Supports over 4G addressing : %s\n",
	     (info->flags & AGP_SUPPORTS_OVER4G_ADDR) ? "true" : "false");
   } else {
      printf("Agp Modes Supported : %s%s%s\n",
	     (info->flags & AGP_SUPPORTS_SPEED_1X) ? "1X " : "",
	     (info->flags & AGP_SUPPORTS_SPEED_2X) ? "2X " : "",
	     (info->flags & AGP_SUPPORTS_SPEED_4X) ? "4X " : "");
      printf("Supports Sideband addressing : %s\n",
	     (info->flags & AGP_SUPPORTS_SBA) ? "true" : "false");
      printf("Supports Fast write : %s\n",
	     (info->flags & AGP_SUPPORTS_FAST_WRITE) ? "true" : "false");
      printf("Supports over 4G addressing : %s\n",
	     (info->flags & AGP_SUPPORTS_OVER4G_ADDR) ? "true" : "false");
   }
}

void agp_output_driver_info(agp_driver_info *info)
{
   agp_master *masters = info->masters;
   int i, num_masters = info->num_masters;
   
   printf("Agp Driver Name : %s\n", info->driver_name);
   printf("Agp context id : %d\n", info->context_id);
   printf("Agp page size : %d\n", 1 << info->agp_page_shift);
   printf("Alloc page size : %d\n", 1 << info->alloc_page_shift);
   printf("Agp page mask : 0x%lx\n", info->agp_page_mask);
   printf("Alloc page mask : 0x%lx\n", info->alloc_page_mask);
   printf("Maximum system pages for Agp : %d\n", info->max_system_pages);
   printf("Current system pages used by Agp : %d\n", info->current_memory);
   printf("\nAgp Target Information:\n");
   printf("Agp version %d.%d\n", info->agp_major_version, 
	  info->agp_minor_version);
   printf("Pci Vender ID : 0x%04x\n", info->target_pci_id >> 16);
   printf("Pci Device ID : 0x%04x\n", info->target_pci_id & 0xffff);
   printf("Agp aperture base : 0x%lx\n", info->aper_base);
   printf("Agp aperture size (MB) : %d\n", info->aper_size);
   printf("Request Depth : %d\n", info->num_requests_enqueue);
   if(info->agp_major_version >= 3) {
      printf("Optimum agp request size : %d\n", info->optimum_request_size);
      printf("Calibration cycle : %d ms\n", info->calibration_cycle_ms);
      if(info->target_flags & AGP_SUPPORTS_AGP_3_0_ENABLED) {
	 printf("Agp Modes Supported : %s%s\n",
		(info->target_flags & AGP_SUPPORTS_SPEED_4X) ? "4X " : "",
		(info->target_flags & AGP_SUPPORTS_SPEED_8X) ? "8X " : "");
      } else {
	 printf("Agp Modes Supported : %s%s%s\n",
		(info->target_flags & AGP_SUPPORTS_SPEED_1X) ? "1X " : "",
		(info->target_flags & AGP_SUPPORTS_SPEED_2X) ? "2X " : "",
		(info->target_flags & AGP_SUPPORTS_SPEED_4X) ? "4X " : "");
      }
      printf("Supports isochronous operation mode : %s\n",
	     (info->target_flags & AGP_SUPPORTS_ISOCHRONOUS) ? 
	     "true" : "false");
      printf("Supports cached memory accesses : %s\n",
	     (info->target_flags & AGP_SUPPORTS_CACHED_MEMORY) ? 
	     "true" : "false");
      printf("Supports Sideband addressing : %s\n",
	     (info->target_flags & AGP_SUPPORTS_SBA) ? "true" : "false");
      printf("Supports Fast write : %s\n",
	     (info->target_flags & AGP_SUPPORTS_FAST_WRITE) ? 
	     "true" : "false");
      printf("Supports over 4G addressing : %s\n",
	     (info->target_flags & AGP_SUPPORTS_OVER4G_ADDR) ? 
	     "true" : "false");
      printf("Supports directly mapping the agp aperture : %s\n",
	     (info->target_flags & AGP_SUPPORTS_APER_MMAP) ?
	     "true" : "false");	     
   } else {
      printf("Agp Modes Supported : %s%s%s\n",
	     (info->target_flags & AGP_SUPPORTS_SPEED_1X) ? "1X " : "",
	     (info->target_flags & AGP_SUPPORTS_SPEED_2X) ? "2X " : "",
	     (info->target_flags & AGP_SUPPORTS_SPEED_4X) ? "4X " : "");
      printf("Supports Sideband addressing : %s\n",
	     (info->target_flags & AGP_SUPPORTS_SBA) ? "true" : "false");
      printf("Supports Fast write : %s\n",
	     (info->target_flags & AGP_SUPPORTS_FAST_WRITE) ? 
	     "true" : "false");
      printf("Supports over 4G addressing : %s\n",
	     (info->target_flags & AGP_SUPPORTS_OVER4G_ADDR) ? 
	     "true" : "false");
      printf("Supports directly mapping the agp aperture : %s\n",
	     (info->target_flags & AGP_SUPPORTS_APER_MMAP) ? 
	     "true" : "false");	     
   }
   printf("Number of detected agp masters : %d\n", num_masters);
   if(num_masters) {
      agp_print_one_master(masters);
      masters++;
   }
}

/* Just tests to make sure that we can completely copy and print out
 * an agp extended info structure properly.  Only tests context zero.
 */
void print_agp3_info(void)
{
   agp_driver_info *info;

   printf("\nNow testing agp 3.0 basic driver information copying ioctls: ");
   fflush(stderr);

   info = agp_alloc_driver_info(0);
   if(!info) {
      printf("failed!\n");
      printf("Error allocating buffer for driver info struct.\n");
      return;
   }
   if(agp_copy_driver_info(0, info) != 0) {
      printf("failed!\n");
      printf("Error copying information from kernel.\n");
      return;
   }
   printf("passed.\n");
   printf("Please insure that the following information matches what you "
	  "expect :\n");
   agp_output_driver_info(info);
}

void test_context(void)
{
   int num_contexts;

   printf("\nNow testing basic context support: ");
   fflush(stderr);
   
   num_contexts = ioctl(gartfd, AGPIOC_NUM_CTXS);
   if(num_contexts < 1) {
      printf("failed!\n");
      printf("Expected at least one context, got : %d\n", num_contexts);
      perror("");
      return;
   }
   /* Test that we get a valid return value for changing to context zero.
    * All others are expected to fail if we don't implement multiple agp
    * bridges per system.
    */
   if(ioctl(gartfd, AGPIOC_CHG_CTX, 0) != 0) {
      printf("failed!\n");
      printf("Expected success for change to context zero.\n");
      perror("");
      return;
   }
   /* Test a context just past our range for the failure, since this
    * agpgart might truely support more then one context.
    */
   if(ioctl(gartfd, AGPIOC_CHG_CTX, num_contexts) == 0) {
      printf("failed!\n");
      printf("Expected failure for a context outside the valid range.\n");
      perror("");
      return;
   }
   
   printf("passed.\n");
   printf("This agpgart implementation reports that it supports %d contexts.\n",
	  num_contexts);
}

unsigned char *agp_map_memory(int key, off_t pg_ofs, size_t pages, 
			      unsigned long prot, unsigned long flags)
{
   agp_map_request rq;
   rq.key = key;
   rq.pg_start = pg_ofs;
   rq.page_count = pages;
   rq.prot = prot;
   rq.flags = flags;
   if(ioctl(gartfd, AGPIOC_MAP, &rq) != 0) {
      perror("map ioctl");
      return NULL;
   }
   return (unsigned char *)rq.addr;
}

int agp_unmap_memory(int key, unsigned char *ptr)
{
   agp_map_request rq;
   rq.key = key;
   rq.addr = (unsigned long)ptr;
   if(ioctl(gartfd, AGPIOC_UNMAP, &rq) != 0) {
      perror("unmap ioctl");
      return errno;
   }
   return 0;
}

void test_usermap(void)
{
   unsigned char *userMap;
   int worked;
   int firstPage, key1;

   firstPage = findFirstRegionOfSize(2048);
   if(firstPage == -1) {
      printf("There are no 8MB regions, so we can't perform the "
	     "User map/unmap tests.\n");
      return;
   }

   key1 = allocAndBind(firstPage, 2048);

   printf("User map/unmap test:\n");
   printf("This set of tests checks to make sure that the ioctls for"
	  "mapping\na piece of agp memory are working correctly.  It "
	  "also attempts to\nmeasure the performance of these mappings.\n");
   
   printf("\nNow testing user map of 8 MB of bound agp memory: ");
   fflush(stderr);

   userMap = agp_map_memory(key1, 0, 2048, PROT_READ | PROT_WRITE, MAP_SHARED);

   if(!userMap) {
      printf("failed!\n");
      printf("User map testing failed\n");
      return;
   } else {
      printf("success.\n");
   }

   printf("\nNow attempting to use this mapping:\n");

   printf("Testing from offset into gart : 0x%08x\n", 
	  (unsigned int)(firstPage * AGP_PAGE_SIZE));

   printf("Testing basic memory performance:\n");
   simpleBenchMark(userMap);
   printf("Now testing memory visability through agp aperture:\n");
   worked = oldIntegrity(firstPage, key1, -1, userMap,
			 PTR_TO_PAGE(gart, firstPage), FALSE);

   if(!worked) {
      printf("\nThe mappings don't match, test failed!\n");
      return;
   }

   printf("\nNow testing user unmap of 8 MB of bound memory: ");
   fflush(stderr);
   worked = agp_unmap_memory(key1, userMap);
   if(worked != 0) {
      printf("failed!\n");
      printf("User map testing failed.\n");
      return;
   } else {
      printf("success.\n");
   }

   printf("\nNow testing user map of 8 MB of unbound memory: ");
   fflush(stderr);
   unbindMemory(key1);

   userMap = agp_map_memory(key1, 0, 2048, PROT_READ | PROT_WRITE, MAP_SHARED);
   if(!userMap) {
      printf("failed!\n");
      printf("User map testing failed.\n");
      return;
   } else {
      printf("success.\n");
   }

   printf("\nNow attempting to use this mapping:\n");

   printf("Testing from offset into gart : 0x%08x\n", 
	  (unsigned int)(firstPage * AGP_PAGE_SIZE));

   printf("Testing basic memory performance:\n");
   simpleBenchMark(userMap);
   printf("Now testing memory visability through agp aperture:\n");
   worked = oldIntegrity(firstPage, key1, -1, userMap,
			 PTR_TO_PAGE(gart, firstPage), TRUE);

   unbindMemory(key1);

   if(!worked) {
      printf("\nThe mappings don't match, test failed!\n");
      return;
   }

   printf("\nNow testing user unmap of 8 MB of unbound memory: ");
   fflush(stderr);
   worked = agp_unmap_memory(key1, userMap);
   if(worked != 0) {
      printf("failed!\n");
      printf("User map testing failed.\n");
      return;
   } else {
      printf("success.\n");
   }

   printf("\nAll user map tests completed successfully.\n");

   freeMemory(key1);   
}

void agp3_tests(void)
{
   printf("\nNow performing some tests to test the "
	  "agp 3.0 infrastructure\nprovided by /dev/agpgart.\n");
   print_agp3_info();
   test_context();
   test_usermap();
}

/* Some more tests that could be written */

/* A client test that checks to see if clients writes to the aperture
 * are correctly placed in the reads from the test program.  Requires
 * that /dev/agpgart be r/w by nobody.
 * Could chmod /dev/agpgart for the test and then put it back how it was.
 */

/* A set of tests of the ioctl permissions when the /dev/agpgart isn't
 * acquired.
 */

/* A set of tests of the ioctl permissions for a client, everything should
 * fail.
 */

int main(void)
{
   int aperSize;

   gart = (char *)0xffffffff;

   openAgpDevice(O_RDWR);

   aperSize = initializeAgp();

   apertureIntegrityTests(aperSize);
#ifdef DEBUG
   printf("Current number of pages : %d\n", getCurrentPages());
#endif
   keyRecycleTest();
#ifdef DEBUG
   printf("Current number of pages : %d\n", getCurrentPages());
#endif
   clientTest(aperSize);

   testMemoryFailures(aperSize);
#ifdef DEBUG
   printf("Current number of pages : %d\n", getCurrentPages());
#endif
   legacyTests();
#ifdef DEBUG   
   printf("Using AGPIOC_RELEASE\n");
#endif

   if(agpgartSupportsGetMap == TRUE) {
      printf("Detected AGP 3.0 capable /dev/agpgart.\n");
      agp3_tests();
   }

   if(ioctl(gartfd, AGPIOC_RELEASE) != 0) {
      perror("ioctl(AGPIOC_RELEASE)");
      exit(1);
   }

   close(gartfd);
}
