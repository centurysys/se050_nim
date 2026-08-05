# =============================================================================
# Best-effort secure memory clearing helpers
# =============================================================================
#
# These helpers are intended for short-lived buffers that may contain private
# key material or other secrets. A volatile C loop is used so the clearing
# write is not optimized away as an ordinary dead store.
#
# This does not erase copies owned by callers, OpenSSL, the kernel, or hardware.
# Callers must still keep secret-bearing buffers short-lived and avoid creating
# unnecessary copies.

{.emit: """
#include <stddef.h>

static void se050_secure_zero(void *data, size_t length)
{
    volatile unsigned char *p = (volatile unsigned char *)data;
    while (length-- > 0) {
        *p++ = 0;
    }
}
""".}

proc secureZeroRaw(data: pointer, length: csize_t) {.
  cdecl,
  importc: "se050_secure_zero",
  nodecl
.}

proc secureZero*(data: var seq[uint8]) =
  ## Clears the currently allocated bytes of a byte sequence in place.
  if data.len > 0:
    secureZeroRaw(addr data[0], csize_t(data.len))

proc secureZero*[N: static[int]](data: var array[N, uint8]) =
  ## Clears a fixed-size byte array in place.
  when N > 0:
    secureZeroRaw(addr data[0], csize_t(N))

proc secureZero*(data: var seq[char]) =
  ## Clears the currently allocated bytes of a character sequence in place.
  if data.len > 0:
    secureZeroRaw(addr data[0], csize_t(data.len))

proc secureZero*(data: var string) =
  ## Clears the bytes currently occupied by a mutable string in place.
  ##
  ## Nim string literals use copy-on-write storage. prepareMutation() must be
  ## called before taking an address that will be used for mutation so a
  ## literal-backed string is first moved to writable storage.
  ##
  ## This is useful for private-key material loaded through readFile(). The
  ## string length is preserved so callers can decide when to release it.
  if data.len > 0:
    prepareMutation(data)
    secureZeroRaw(addr data[0], csize_t(data.len))
