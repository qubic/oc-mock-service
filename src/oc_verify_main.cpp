// oc_verify — standalone verifier for OC authorization bundles.
//
// Reads a raw OcMachineInvocation frame (exactly the bytes a Qubic Core node
// emits over the private OC-machine channel) on stdin, plus the 676 computor
// public keys for the bundle's epoch from a file, and decides whether the
// bundle carries >= QUORUM (451) valid computor signatures.
//
// This is the trust anchor of the mock OC interface service: because the
// service's ingest endpoint is public (any operator's OC machine may POST to
// the single service, so it cannot be IP-whitelisted), authenticity rests
// entirely on re-verifying the signatures here. A forged bundle cannot produce
// 451 valid SchnorrQ signatures over the correct authMessage.
//
// Usage:
//     oc_verify --keys <computors.bin>  < bundle.bin
//
//   <computors.bin> : NUMBER_OF_COMPUTORS * 32 bytes = 676 * 32 = 21632 bytes,
//                     the m256i publicKeys[] array from a BroadcastComputors
//                     message for the bundle's epoch (see network_messages/
//                     computors.h). The caller is responsible for having
//                     validated that computor list against the epoch (the list
//                     is itself signed and self-authenticating).
//
// Output (stdout): one JSON line describing the verdict, e.g.
//     {"valid":true,"verifiedCount":451,"invocationId":123,"epoch":150,"interfaceIndex":0,"tick":58,"requestSize":8}
// Exit code: 0 if valid (>= QUORUM good sigs), 1 if invalid, 2 on usage/IO error.

#define NO_UEFI 1

#include "four_q.h"
#include "kangaroo_twelve.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>

// ---- OC protocol constants (mirrors network_messages/common_def.h & oc_engine.h) ----
static constexpr int      NUMBER_OF_COMPUTORS = 676;
static constexpr int      QUORUM              = NUMBER_OF_COMPUTORS * 2 / 3 + 1; // 451
static constexpr int      SIGNATURE_SIZE      = 64;
static constexpr uint8_t  OC_MACHINE_INVOCATION_TYPE = 192; // NetworkMessageType::OC_MACHINE_INVOCATION
static constexpr char     OC_AUTH_DOMAIN_SEPARATOR[13] =
    { 'Q','U','B','I','C','_','O','C','_','A','U','T','H' };
static constexpr unsigned OC_AUTH_DOMAIN_SEPARATOR_SIZE = 13;

// ---- Wire structs (mirror oc_core/core_oc_network_messages.h, packed) ----
#pragma pack(push, 1)
struct OcMachineInvocationHeader
{
    long long      invocationId;   // 8
    unsigned short epoch;          // 2
    unsigned short interfaceIndex; // 2
    unsigned short requestSize;    // 2
    unsigned short signatureCount; // 2
    // followed by: requestSize bytes of pinned OcRequest payload
    // followed by: signatureCount x SignerEntry
};
static_assert(sizeof(OcMachineInvocationHeader) == 16, "header must be 16 bytes");

struct SignerEntry
{
    unsigned short computorIndex;            // 2
    unsigned char  signature[SIGNATURE_SIZE];// 64
};
static_assert(sizeof(SignerEntry) == 66, "SignerEntry must be 66 bytes");

// Canonical authMessage byte layout (mirrors OcAuthMessageBytes, oc_engine.h §2.3).
struct OcAuthMessageBytes
{
    unsigned char  domainSeparator[OC_AUTH_DOMAIN_SEPARATOR_SIZE]; // 13
    unsigned short epoch;          // 2
    unsigned short interfaceIndex; // 2
    long long      invocationId;   // 8
    unsigned char  paramsDigest[32]; // 32
};
static_assert(sizeof(OcAuthMessageBytes) == 57, "authMessage must be 57 bytes");
#pragma pack(pop)

static std::vector<unsigned char> readAll(FILE* f)
{
    std::vector<unsigned char> buf;
    unsigned char tmp[65536];
    size_t n;
    while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0)
        buf.insert(buf.end(), tmp, tmp + n);
    return buf;
}

static bool readFile(const char* path, std::vector<unsigned char>& out)
{
    FILE* f = fopen(path, "rb");
    if (!f)
        return false;
    out = readAll(f);
    fclose(f);
    return true;
}

static void fail(const char* reason)
{
    // Invalid but well-formed run: emit a verdict and exit 1.
    printf("{\"valid\":false,\"verifiedCount\":0,\"reason\":\"%s\"}\n", reason);
    exit(1);
}

int main(int argc, char** argv)
{
    const char* keysPath = nullptr;
    for (int i = 1; i < argc; ++i)
    {
        if (std::strcmp(argv[i], "--keys") == 0 && i + 1 < argc)
            keysPath = argv[++i];
    }
    if (!keysPath)
    {
        fprintf(stderr, "usage: oc_verify --keys <computors.bin> < bundle.bin\n");
        return 2;
    }

    // Load the epoch's computor public keys.
    std::vector<unsigned char> keys;
    if (!readFile(keysPath, keys))
    {
        fprintf(stderr, "oc_verify: cannot read keys file '%s'\n", keysPath);
        return 2;
    }
    if (keys.size() != (size_t)NUMBER_OF_COMPUTORS * 32)
    {
        fprintf(stderr, "oc_verify: keys file must be %d bytes (got %zu)\n",
                NUMBER_OF_COMPUTORS * 32, keys.size());
        return 2;
    }

    // Read the raw OcMachineInvocation frame from stdin.
    std::vector<unsigned char> bundle = readAll(stdin);
    if (bundle.size() < sizeof(OcMachineInvocationHeader))
        fail("bundle too small for header");

    OcMachineInvocationHeader hdr;
    std::memcpy(&hdr, bundle.data(), sizeof(hdr));

    // Structural checks before any expensive crypto.
    if (hdr.signatureCount < QUORUM)
        fail("signatureCount below quorum");

    const size_t expected = sizeof(OcMachineInvocationHeader)
                          + (size_t)hdr.requestSize
                          + (size_t)hdr.signatureCount * sizeof(SignerEntry);
    if (bundle.size() < expected)
        fail("bundle shorter than declared payload");

    const unsigned char* requestData = bundle.data() + sizeof(OcMachineInvocationHeader);
    const SignerEntry* signers = reinterpret_cast<const SignerEntry*>(
        bundle.data() + sizeof(OcMachineInvocationHeader) + hdr.requestSize);

    // Recompute paramsDigest = K12(pinned request bytes). This confirms the
    // transmitted request matches what the computors actually signed.
    unsigned char paramsDigest[32];
    KangarooTwelve(requestData, hdr.requestSize, paramsDigest, 32);

    // Build the canonical authMessage and its K12 hash (the signed message digest).
    OcAuthMessageBytes msg;
    std::memcpy(msg.domainSeparator, OC_AUTH_DOMAIN_SEPARATOR, OC_AUTH_DOMAIN_SEPARATOR_SIZE);
    msg.epoch          = hdr.epoch;
    msg.interfaceIndex = hdr.interfaceIndex;
    msg.invocationId   = hdr.invocationId;
    std::memcpy(msg.paramsDigest, paramsDigest, 32);

    unsigned char authHash[32];
    KangarooTwelve((const unsigned char*)&msg, sizeof(msg), authHash, 32);

    // Verify each signer entry. Count only DISTINCT computor indices with a
    // valid signature (a malicious relay might duplicate a good entry).
    std::vector<bool> counted(NUMBER_OF_COMPUTORS, false);
    unsigned int verifiedCount = 0;
    for (unsigned short i = 0; i < hdr.signatureCount; ++i)
    {
        const unsigned short c = signers[i].computorIndex;
        if (c >= NUMBER_OF_COMPUTORS)
            continue;              // out-of-range index
        if (counted[c])
            continue;              // duplicate signer
        const unsigned char* pubKey = keys.data() + (size_t)c * 32;
        if (!verify(pubKey, authHash, signers[i].signature))
            continue;             // bad signature
        counted[c] = true;
        ++verifiedCount;
    }

    const bool valid = verifiedCount >= (unsigned)QUORUM;
    const long long tick = hdr.invocationId >> 31; // invocationId = (tick<<31)|indexInTick

    printf("{\"valid\":%s,\"verifiedCount\":%u,\"invocationId\":%lld,"
           "\"epoch\":%u,\"interfaceIndex\":%u,\"tick\":%lld,\"requestSize\":%u}\n",
           valid ? "true" : "false", verifiedCount, hdr.invocationId,
           hdr.epoch, hdr.interfaceIndex, tick, hdr.requestSize);

    return valid ? 0 : 1;
}
