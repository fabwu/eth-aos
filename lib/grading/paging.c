#include <aos/systime.h>
#include <aos/aos.h>

#include "paging.h"

static void test_malloc_simple(void) {
    systime_t start = systime_now();
    char *pointer = (char *)malloc(1024*1024*64);
    systime_t stop = systime_now();

    DEBUG_PRINTF("%p\n", pointer);
    DEBUG_PRINTF("%d microseconds spent allocating 64MB\n", systime_to_us(stop - start));

    free(pointer);
}

#define NUM_THREADS 10
#define NUM_RUNS 100

struct alloc_options {
    int num_runs;
};

static int alloc(void *args) {
    int i;
    for(i = 0; i < NUM_RUNS; ++i) {
        int *pointer = (int *)malloc(BASE_PAGE_SIZE + 43);
        assert(pointer != NULL);
        *pointer = i;
        thread_yield();
    }
    DEBUG_PRINTF("I'm done after %d runs\n", i);
    return 0;
}

static void test_malloc_threads(void) {
    //FIXME This test fails at the moment
    for(int i = 0; i < NUM_THREADS; ++i) {
        thread_create(alloc, NULL);
        thread_yield();
    }

    /*while(true) {
        DEBUG_PRINTF("ALIVE\n");
        thread_yield();
    }*/
}

static void test_null_pointer(void) {
    char *null_pointer = NULL;
    DEBUG_PRINTF("%p\n", *null_pointer);
}

#define TEST_MALLOC 1
#define TEST_NULL_POINTER 0

void grading_test_demand_paging(void) {
    if(TEST_MALLOC) {
        test_malloc_simple();
        test_malloc_threads();
    }

    if(TEST_NULL_POINTER) {
        test_null_pointer();
    }
}
