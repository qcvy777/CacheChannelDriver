# CacheChannel
proof of concept implementation demonstrating cache based covert communication channels between usermode applications and  kernelmode.

## **Overview**

This Driver demonstrates a complete cache side-channel communication that enables covert data exchange between usermode kernelmode without traditional IPC mechanisms. It uses Prime+Probe cache timing attacks to establish a communication channel.

### **Some Key Features**

- No direct IOCTL calls or traditional driver communication
- Memory read/write, process base address, PEB extraction
- Adaptive timing threshold calculation


### **How it Communicates**

1. **Prime Phase**: Fill cache sets with known data patterns
2. **Request Transmission**: Encode operation via cache access patterns  
3. **Kernel Processing**: Driver executes requested memory operations
4. **Probe Phase**: Measure cache access times to detect evictions
5. **Response Decoding**: Extract data from timing variations
