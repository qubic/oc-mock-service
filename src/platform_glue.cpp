// Minimal host-side definitions for the platform memory primitives that the
// vendored crypto headers declare under NO_UEFI (normally provided by the
// node's test/stdlib_impl.cpp). Only the two symbols the crypto path uses.

#include <cstring>

void setMem(void* buffer, unsigned long long size, unsigned char value)
{
    std::memset(buffer, value, (size_t)size);
}

void copyMem(void* destination, const void* source, unsigned long long length)
{
    std::memcpy(destination, source, (size_t)length);
}
