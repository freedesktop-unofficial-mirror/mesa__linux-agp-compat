/* 
 * 
 * Test program for AGPGART module under Linux
 * 
 * Copyright (C) 1999 Jeff Hartmann, 
 * Precision Insight, Inc., Xi Graphics, Inc.
 *
 */ 



#define DEBUG


/*
 * Set the offset (in KB) past the stolen memory.
 */

#if 0
#define OFFSET (32 * 1024 - 132)
#else
#define OFFSET (16 * 1024 - 132)
#endif

#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <linux/types.h>
#include <linux/agpgart.h>
#include <asm/mtrr.h>
#include <errno.h>
#include <stdlib.h>


unsigned char *gart;
int gartfd;
int mtrr;
int offset;

int usec( void ) {
  struct timeval tv;
  struct timezone tz;
  
  gettimeofday( &tv, &tz );
  return (tv.tv_sec & 2047) * 1000000 + tv.tv_usec;
}

int init_agp(void)
{
   agp_info info;
   agp_setup setup;

#ifdef DEBUG
   printf("Using AGPIOC_ACQUIRE\n");
#endif
   if(ioctl(gartfd, AGPIOC_ACQUIRE) != 0)
     {
	perror("ioctl(AGPIOC_ACQUIRE)");
	exit(1);
     }
#ifdef DEBUG
   printf("Using AGPIOC_INFO\n");
#endif
   if(ioctl(gartfd, AGPIOC_INFO, &info) != 0)
     {
	perror("ioctl(AGPIOC_INFO)");
	exit(1);
     }
   
#ifdef DEBUG
   printf("version: %i.%i\n", info.version.major, info.version.minor);
   printf("bridge id: 0x%lx\n", info.bridge_id);
   printf("agp_mode: 0x%lx\n", info.agp_mode);
   printf("aper_base: 0x%lx\n", info.aper_base);
   printf("aper_size: %i\n", info.aper_size);
   printf("pg_total: %i\n", info.pg_total);
   printf("pg_system: %i\n", info.pg_system);
   printf("pg_used: %i\n", info.pg_used);
#endif

   gart = mmap(NULL, info.aper_size * 0x100000, PROT_READ | PROT_WRITE, MAP_SHARED, gartfd, 0);

   if(gart == (unsigned char *) 0xffffffff)
     {
	perror("mmap");
	close(gartfd);
	exit(1);
     }	
   
   gart += offset * 4096;

   setup.agp_mode = info.agp_mode;
#ifdef DEBUG
   printf("Using AGPIOC_SETUP\n");
#endif
   if(ioctl(gartfd, AGPIOC_SETUP, &setup) != 0)
     {
	perror("ioctl(AGPIOC_SETUP)");
	exit(1);
     }
   
   return(0);
}

int xchangeDummy;

#ifndef __x86_64__
void FlushWriteCombining( void ) {
	__asm__ volatile( " push %%eax ; xchg %%eax, %0 ; pop %%eax" : : "m" (xchangeDummy));
	__asm__ volatile( " push %%eax ; push %%ebx ; push %%ecx ; push %%edx ; movl $0,%%eax ; cpuid ; pop %%edx ; pop %%ecx ; pop %%ebx ; pop %%eax" : /* no outputs */ :  /* no inputs */ );
}
#else
void FlushWriteCombining( void ) {

  __asm__ volatile("\t"
		   "xchg %%eax, %0\n\t"
		   :
		   : "m" (xchangeDummy)
		   : "eax");

  __asm__ volatile ("\t"
		    "push %%rbx\n\t"
		    "cpuid\n\t"
		    "pop %%rbx\n\t"
		    :
		    :
		    :"ecx", "edx", "cc");
}
#endif

int main(int argc, char *argv[])
{
   int i;
   int key;
   int key2;
   agp_info info;
  
   if (argc > 1)
      offset = atoi(argv[0]);
   else
      offset = OFFSET;

   offset /= 4;

   gartfd = open("/dev/agpgart", O_RDWR);
   if (gartfd == -1)
     {	
	perror("open");
	exit(1);
     }
   
   init_agp();
   
   close(gartfd);
}

