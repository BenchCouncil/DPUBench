#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <thread>
#include <mutex>

using namespace std;

#define NUM_TBL24 1 << 23 
#define NUM_VALID_TBL24 3000
#define NUM_INVALID_TBLE24 2700
#define NUM_VALID_TBL8 20
#define NUM_TBL8_ENTRY 253
#define MAX_THREAD 100

struct Entry {
    int* next;
    int valid;
} tbl24[1 << 24];

struct tbl_8 {
    struct Entry entry[256];
};

struct tbl_8 *tbl8[NUM_VALID_TBL8];

struct thread_data {
    int niter, tid;
};

mutex mtx[256 * NUM_VALID_TBL8];

void thread_worker(void* inp_data) {
    int niter = ((struct thread_data*)inp_data)->niter;
    int tid = ((struct thread_data*)inp_data)->tid;
    for (int i = 0; i < niter; i++) {
        int idx = rand() % NUM_TBL24;

        int* next = tbl24[idx].next;

        int valid = rand() % NUM_VALID_TBL24;

        if (valid > NUM_INVALID_TBLE24) {
            int idx0 = rand() % NUM_VALID_TBL8;
            int idx1 = rand() % NUM_TBL8_ENTRY;
            int* nex = tbl8[idx0]->entry[idx1].next;
            mtx[idx0 * idx1].lock();
            tbl8[idx0]->entry[idx1].valid = 1;
            mtx[idx0 * idx1].unlock();
        }
    }
}

int main(int argc, char** argv) {
    thread threads[MAX_THREAD];
    int num_thread;
    int niters, len;
    if (argc == 1) {
        len = 1500, num_thread = 1;
        niters = 100;
    }
    else if (argc == 2) {
        len = atoi(argv[1]);
        niters = 100, num_thread = 1;
    }
    else if (argc == 3) {
        len = atoi(argv[1]);
        niters = atoi(argv[2]);
        num_thread = 1;
    }
    else {
        len = atoi(argv[1]);
        niters = atoi(argv[2]);
        num_thread = atoi(argv[3]);
    }

    struct thread_data* thread_inp = (struct thread_data*)malloc(sizeof(struct thread_data) * num_thread);

    for (int i = 0; i < NUM_VALID_TBL8; i++)
        tbl8[i] = (tbl_8*)malloc(sizeof(tbl_8));

    // initialize per thread data
    for (int i = 0; i < num_thread; i++) {
        thread_inp[i].niter = niters;
        thread_inp[i].tid = i;
    }

    struct timeval start, end;

    gettimeofday(&start, NULL);

    for (int i = 0; i < num_thread; i++) {
        threads[i] = thread(thread_worker, (void*)&thread_inp[i]);
    }

    // thread_worker((void *)&thread_inp[0]);

    int* ret = NULL;

    for (int i = 0; i < num_thread; i++)
        threads[i].join();

    gettimeofday(&end, NULL);

    double time_taken = double(1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)) / double(1e6);

    printf("spend %fs\n", time_taken);
    printf("LPM : %lld MB per second\n", (long long)((float)(niters * num_thread * len) / (float)(time_taken * 1024 * 1024)));

    free(thread_inp);
    for (int i = 0; i < NUM_VALID_TBL8; i++)
        free(tbl8[i]);

    return 0;
}
