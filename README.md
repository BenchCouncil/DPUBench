# Discription

____________________________________________________________________________________________________________________________________________________________

This is the source code for DPUBench mark, the first application driven benchmarrk suit for DPU. The source code contains two part, the code in the operator folder correspond to
the micro-benchmark, and code in the end2end folder correspond to the end-to-end benchmark.

# Installation
_____________________________________________________________________________________________________________________________________________________________

To build the micro-benchmark, simply run the following command on linux:

**g++ path_to_your_operator/operator_name.cpp -o optput**

All the micro-benchmark programs make use of the std::thread library, which is C++11 feature, make sure your compiler support it.

To build the end-to-end benchmark, you shoud first install a NVIDIA's BlueField DPU on your host, then you can setup the host environment following the link: 
[DOCA Install Guid](https://docs.nvidia.com/doca/sdk/installation-guide-for-linux/index.html)

After host environment has been set up and DOCA has been installed, you can ssh to your device through ssh:

**ssh ubuntu@192.168.100.2**

Then in the device, cd to the folder of benchmark you want to build and run:

**meson build**

**ninja -C build**

Then the binary of the benchmark will be built on the build folder.

To see more about environment build up and DOCA programe compilation, see the link: 
[doca_doc](https://docs.nvidia.com/doca/sdk)

# Test
_____________________________________________________________________________________________________________________________________________________________

For micro-benchmark, the command line interface is:

**bench_name nthread niters input_data_size**

Where nthread correspond to the number of threads in the benchmark, iters is the number of iteration per thread run, and input_data_size is the data size for the operator's input. The result throughput will be output to the standard output.

For end to end benchmark, run the benchmark binary using following command:

**/path/to/your/benchmark/bin/bench_name -a auxiliary:mlx5_core.sf.4,sft_en=1 -a auxiliary:mlx5_core.sf.5,sft_en=1 -c3 -- -p -a 03:00.0**

Then you can send packet to the server in whitch your benchmark run, eg. pktgen or DPDK-pktgen. For example, if you use pktgen in the linux kernel, run following command: 

**sudo echo "add_device eno2" > /proc/net/pktgen/kpktgend_0**

**sudo echo "pkt_size 64" > /proc/net/pktgen/eno2**

**sudo echo "count 50000" > /proc/net/pktgen/eno2**

**sudo echo "dst_mac 08:c0:eb:8e:dc:32" > /proc/net/pktgen/eno2**

**sudo echo "dst 172.18.254.49" > /proc/net/pktgen/eno2**

**sudo echo "delay 1000" > /proc/net/pktgen/eno2**

**sudo echo start > /proc/net/pktgen/pgctrl**

The result thoughput will be printed on the terminal.

