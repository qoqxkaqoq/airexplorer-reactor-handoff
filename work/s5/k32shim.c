/* k32shim.c - fake kernel32/mscoree for native mono tracing of AirExplorer.
   LoadLibrary -> fake handle; GetProcAddress -> pointer to generic stub (returns 1). */
#include <stdint.h>
#include <stddef.h>

static int generic_stub(void) { return 1; }
static int generic_stub1(void* a) { (void)a; return 1; }

uintptr_t LoadLibrary(const char* name) {
    (void)name;
    return 0x0000DEB0; /* fake non-null handle */
}
uintptr_t GetProcAddress(uintptr_t h, const char* name) {
    (void)h; (void)name;
    return (uintptr_t)(void*)&generic_stub;
}
int CloseHandle(uintptr_t h) { (void)h; return 1; }
uintptr_t GetCurrentProcess(void) { return (uintptr_t)-1; }
uintptr_t GetCurrentThread(void) { return (uintptr_t)-2; }
/* mscoree: BOOL StrongNameSignatureVerificationEx(LPCWSTR path, BOOL fForceVerification, BOOL* pfWasVerified) */
int StrongNameSignatureVerificationEx(const void* path, int force, int* wasVerified) {
    (void)path; (void)force;
    if (wasVerified) *wasVerified = 1;
    return 1;
}
