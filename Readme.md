# Sentinel Engine (v0.1-Alpha)

A network analyzer designed for real-time detection of network anomalies and scanners (L3 Network Layer).


## Key Features

1. **Real-time L3 Analysis:** Immediate packet inspection using WinDivert's network layer.

2. **High-Speed Binary Logging:**
	* **Memory-Mapped Files (FileMapping):** Instead of standard I/O, the logger uses `FileMapping` for direct memory access, minimizing CPU overhead.
    * **Circular Buffer Logic:** Implements a lock-free circular buffer to handle high-velocity traffic data without losing packets or blocking the main processing thread.
    * **Compact Storage:** Data is stored in a raw binary format, significantly reducing disk space compared to text logs.


## Build

Prerequisites

* WinDivert (dll and sys files).


## Standard Build Instructions 

```
mkdir build && cd build
cmake ..
cmake --build .
```


## License

This project is licensed under the **MIT License**.	

