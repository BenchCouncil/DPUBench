#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <thread>


using namespace std;

#define HEAD_SIZE 20

#define MAX_LEN 1004
#define MEM_POOL_SIZE 2000
#define MAX_THREAD 100

unsigned char payload[MAX_LEN * MEM_POOL_SIZE + 10];

struct Mbuf {
    int head[5];
    unsigned char* data;
    int len;
} mbuf[MEM_POOL_SIZE];

void do_IpSeg(Mbuf * src, Mbuf * dst) {
    memcpy(dst->head, src->head, HEAD_SIZE);
    dst->len = src->len;
    dst->data = src->data;
}

struct thread_data {
    Mbuf* src, *dst;
    int niter, tid;
};

void thread_worker(void* inp_data) {
    Mbuf* src = ((struct thread_data*)inp_data)->src;
    Mbuf* dst = ((struct thread_data*)inp_data)->dst;
    int niter = ((struct thread_data*)inp_data)->niter;
    int tid = ((struct thread_data*)inp_data)->tid;
    for (int i = 0; i < niter; i++) {
        do_IpSeg(src, dst);
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

    for (int i = 0; i < MEM_POOL_SIZE; i++) {
        mbuf[i].data = &payload[i * (len - HEAD_SIZE)];
        mbuf[i].len = len - HEAD_SIZE;
    }

    // initialize per thread data
    for (int i = 0; i < num_thread; i++) {
        thread_inp[i].src = &mbuf[i];
        thread_inp[i].dst = &mbuf[i + MEM_POOL_SIZE / 2];
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
    printf("IPSeg : %lld MB per second\n", (long long)(((long long)niters * num_thread * len) / (float)(time_taken * 1024 * 1024)));

    free(thread_inp);

    return 0;
}
