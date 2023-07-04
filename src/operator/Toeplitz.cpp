// #include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <thread>
#include <sys/time.h>

using namespace std;

#define uint unsigned int
#define NUM_THREADS 1

#define MAX_LEN 1500
#define MAX_THREAD 100

unsigned char inp[MAX_THREAD * MAX_LEN + 10];
char thread_buffer[MAX_THREAD * MAX_LEN * 4 + 10];

struct thread_data{
    unsigned char* str;
    int length;
    int niter;
    int tid;
};

void toeplize(unsigned char* data, int len) { 
    uint result = 0;
    for (int i = 0; i < len; i++) {
        for (int j = 0; j < 8; j++) {
            if (((data[i] >> j) ^ 1) == 0) 
                continue;
            if (i == 0 && j == 0)
                result = ((uint)data[3] << 24) 
                    ^ ((uint)data[2] << 16) ^ ((uint)data[1] << 8) ^ data[0];
            else 
                result = (result >> 1) ^ ((data[i + 3] >> 7) & 1); 
        }
    }
}

void thread_worker(void* inp_data) {
    unsigned char* str = ((struct thread_data *) inp_data)->str;
    int len = ((struct thread_data *) inp_data)->length;
    int niter = ((struct thread_data *) inp_data)->niter;
    for (int i = 0; i < niter; i++) {
        toeplize(str, len);
    }
}

void generate_data(unsigned char* buffer, int len) {
    for (int i = 0; i < len; i++)
        buffer[i] = rand() % 255;
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
        thread_inp[i].length = len;
        thread_inp[i].niter = niters;
        thread_inp[i].str = &inp[i * len];
        thread_inp[i].tid = i;
    }

    struct timeval start, end;

    gettimeofday(&start, NULL);

    for (int i = 0; i < num_thread; i++) {
        threads[i] = thread(thread_worker, (void *)&thread_inp[i]);
    }

    // thread_worker((void *)&thread_inp[0]);

    int* ret = NULL;

    for (int i = 0; i < num_thread; i++)
        threads[i].join();

    gettimeofday(&end, NULL);

    double time_taken = double(1000000*(end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)) / double(1e6);
    
    printf("spend %fs\n", time_taken);
    printf("Toeplitz : %lld MB per second\n", (long long)((float)(niters * num_thread * len) / (float)(time_taken * 1024 * 1024)));

    free(thread_inp);

    return 0;
}

