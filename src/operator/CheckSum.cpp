#include <stdint.h>
#include <sys/time.h>
#include <thread>
#include <stdio.h>
#include <stdlib.h>

using namespace std;

#define MAX_LEN 1500
#define MAX_THREAD 100

unsigned short inp[MAX_THREAD * MAX_LEN + 10];

const uint16_t crc_ta_4[16] = { /* CRC °ë×Ö½ÚÓàÊ½±í */
    0x0000,0x1021,0x2042,0x3063,0x4084,0x50a5,0x60c6,0x70e7,
    0x8108,0x9129,0xa14a,0xb16b,0xc18c,0xd1ad,0xe1ce,0xf1ef,
};

static inline unsigned short check_sum(const unsigned short* buf, int size)
{
    unsigned long chksum = 0;

    while (size > 1)
    {
        chksum += *buf++;
        size -= sizeof(unsigned short);
    }

    if (size)
    {
        chksum += *((unsigned char*)buf);
    }

    while (chksum >> 16)
    {
        chksum = (chksum >> 16) + (chksum & 0xffff);
    }

    return (unsigned short)(~chksum);
}

struct thread_data {
    int niter, tid;
    unsigned short* src;
    int len;
};

void thread_worker(void* inp_data) {
    int niter = ((struct thread_data*)inp_data)->niter;
    int tid = ((struct thread_data*)inp_data)->tid;
    unsigned short* src = ((struct thread_data*)inp_data)->src;
    int len = ((struct thread_data*)inp_data)->len;
    for (int i = 0; i < niter; i++) {
        check_sum(src, len);
    }
}

void generate_data(unsigned short* buffer, int len) {
    for (int i = 0; i < len; i++)
        buffer[i] = rand() % 256;
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

    for (int i = 0; i < num_thread; i++)
        generate_data(&inp[i * len], len);

    struct thread_data* thread_inp = (struct thread_data*)malloc(sizeof(struct thread_data) * num_thread);

    // initialize per thread data
    for (int i = 0; i < num_thread; i++) {
        thread_inp[i].len = len;
        thread_inp[i].niter = niters;
        thread_inp[i].src = &inp[i * len];
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
    printf("CheckSum16 : %lld MB per second\n", (long long)((float)(niters * num_thread * len) / (float)(time_taken * 1024 * 1024)));

    free(thread_inp);

    return 0;
}

