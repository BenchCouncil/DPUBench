# Discription

____________________________________________________________________________________________________________________________________________________________

This is the source code for DPUBench mark, the first application driven benchmarrk suit for DPU. The source code contains two part, the code in the operator folder correspond to
the micro-benchmark, and code in the end2end folder correspond to the end-to-end benchmark.

# installation
_____________________________________________________________________________________________________________________________________________________________

To build the micro-benchmark, simply run the following command on linux:
**g++ path_to_your_operator/operator_name.cpp -o optput**

All the micro-benchmark programs make use of the std::thread library, which is C++11 feature, make sure your compiler support it.

To build the end-to-end benchmark, you shoud first install a NVIDIA's BlueField DPU on your host, then you can setup the host environment following the link below:
[DOCA Install Guid](https://docs.nvidia.com/doca/sdk/installation-guide-for-linux/index.html)

After host environment has been set up and DOCA has been installed, you can ssh to your device through ssh:
** **


