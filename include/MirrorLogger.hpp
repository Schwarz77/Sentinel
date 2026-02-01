#include <iostream>
#include <atomic>
#include <cstring>
#include <cstdint>
#include <filesystem>
#include <string>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/mman.h>
    #include <unistd.h>
    #include <fcntl.h>
#endif

namespace fs = std::filesystem;

fs::path getExecutableDirectory() {
#ifdef _WIN32
    wchar_t buffer[MAX_PATH];
    if (GetModuleFileNameW(NULL, buffer, MAX_PATH) == 0) {
        return "";
    }
    return fs::path(buffer).parent_path();
#else
    char buffer[PATH_MAX];
    ssize_t count = readlink("/proc/self/exe", buffer, PATH_MAX);
    if (count == -1) return "";
    buffer[count] = '\0';
    return fs::path(buffer).parent_path();
#endif
}


class MirrorLogger 
{
    size_t buffer_size;
    uint8_t* base_ptr = nullptr;
    std::atomic<size_t> tail{0};
    std::string path;

#ifdef _WIN32
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMap = NULL;
#else
    int fd = -1;
#endif

public:
    MirrorLogger(size_t requested_size) 
	{
        fs::path exePath = getExecutableDirectory();
        fs::path logDir = exePath / "logs";

        if (!fs::exists(logDir)) {
            fs::create_directories(logDir);
        }

        fs::path out = logDir / "sentinel.bin";

        path = out.string();


        // Rounded to 64 KB (allocation granularity in Windows)
        size_t granularity = 64 * 1024;
        buffer_size = (requested_size + granularity - 1) & ~(granularity - 1);

#ifdef _WIN32
        hFile = CreateFileA(path.data(), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        
        hMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, (DWORD)buffer_size, NULL);

        // for Win: search for free space in 2 * buffer_size
        for (int i = 0; i < 10; ++i) 
		{
            base_ptr = (uint8_t*)VirtualAlloc(NULL, 2 * buffer_size, MEM_RESERVE, PAGE_NOACCESS);
            if (!base_ptr) 
				continue;
			
            VirtualFree(base_ptr, 0, MEM_RELEASE); // We're releasing, but we've memorized address

            // We are trying to map two copies one after the other
            auto p1 = MapViewOfFileEx(hMap, FILE_MAP_ALL_ACCESS, 0, 0, buffer_size, base_ptr);
            auto p2 = MapViewOfFileEx(hMap, FILE_MAP_ALL_ACCESS, 0, 0, buffer_size, base_ptr + buffer_size);

            if (p1 && p2) 
				break; // Success

            if (p1) 
				UnmapViewOfFile(p1);
			
            if (p2) 
				UnmapViewOfFile(p2);
        }
#else
        fd = open(path.data(), O_RDWR | O_CREAT | O_TRUNC, 0666);
        ftruncate(fd, buffer_size);

        base_ptr = (uint8_t*)mmap(NULL, 2 * buffer_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        mmap(base_ptr, buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
        mmap(base_ptr + buffer_size, buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
#endif
    }

    ~MirrorLogger() 
	{
#ifdef _WIN32
        UnmapViewOfFile(base_ptr);
        UnmapViewOfFile(base_ptr + buffer_size);
        CloseHandle(hMap);
        CloseHandle(hFile);
#else
        munmap(base_ptr, 2 * buffer_size);
        close(fd);
#endif
    }

    template<typename T>
    void write_binary(const T& data) 
	{
        size_t pos = tail.fetch_add(sizeof(T), std::memory_order_relaxed) % buffer_size;
        // Thanks to the mirror, memcpy simply “spills” to the beginning if it reaches the end
        std::memcpy(base_ptr + pos, &data, sizeof(T));
    }


};