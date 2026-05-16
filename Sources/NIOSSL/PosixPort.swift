//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

// This file contains a version of the SwiftNIO Posix enum. This is necessary
// because SwiftNIO's version is internal. Our version exists for the same reason:
// to ensure errno is captured correctly when doing syscalls, and that no ARC traffic
// can happen inbetween that *could* change the errno value before we were able to
// read it.
//
// The code is an exact port from SwiftNIO, so if that version ever becomes public we
// can lift anything missing from there and move it over without change.
#if canImport(Darwin)
import Darwin.C
#elseif canImport(Musl)
import Musl
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Android)
import Android
#elseif canImport(WinSDK)
import WinSDK
// `WinSDK` re-exports the Universal CRT (ucrt) so `fopen`, `fclose`, `FILE`,
// `EINTR`, `EFAULT`, `EBADF`, and `strerror` are all available. Symbol shape differs
// from POSIX in five ways that this file papers over for Windows:
//   1. `stat` (function + struct) is named `_stat64` on Windows MSVC. We typealias it.
//   2. `lstat` doesn't exist on Windows. We alias it to `_stat64` so the caller's
//      symlink check correctly returns false on regular files. Real reparse-point
//      handling would require `GetFileAttributesExW`, but the only caller of
//      `Posix.lstat` in NIOSSL is OpenSSL-style CA bundle rehash detection, which
//      we gate out entirely on Windows below (no `/etc/ssl/certs`-style directories
//      exist on Windows; users go through certificate stores instead).
//   3. `mlock`/`munlock` are unimplemented; we map them to `VirtualLock`/`VirtualUnlock`,
//      which are the closest Win32 equivalent (page-granularity working-set locking).
//   4. `readlink` is referenced by `sysReadlink` but never actually called from NIOSSL
//      Swift code. We provide a stub that fails with ENOSYS so the linker is happy and
//      any future caller sees a clear error.
//   5. `errno` is a macro in Windows MSVC, expanding to `*_errno()`. Swift's `WinSDK`
//      overlay doesn't expose it as a global; we route through `_errno().pointee`.
//   6. `S_IFLNK` macro doesn't exist on Windows; we provide the POSIX value (0xA000)
//      as a Swift constant in the same module. Since `_stat64`'s st_mode never sets
//      this bit on Windows, the symlink check correctly returns false.
internal typealias stat = _stat64
internal let S_IFLNK: UInt16 = 0xA000

// Bridge for Swift code that wants to read/write the Windows CRT errno. Routes
// through `_errno()` which the CRT macro expands to.
@inline(__always)
internal var errno: CInt {
    get { _errno().pointee }
    set { _errno().pointee = newValue }
}

@inline(__always)
private func _winReadlink(
    _ path: UnsafePointer<CChar>,
    _ buf: UnsafeMutablePointer<CChar>,
    _ bufSize: Int
) -> Int {
    // No POSIX-style readlink on Windows; this stub returns -1 with errno=ENOSYS so
    // wrapSyscall throws an IOError. No code path in NIOSSL Swift actually invokes
    // Posix.readlink, so this is purely defensive.
    errno = ENOSYS
    return -1
}

@inline(__always)
private func _winMlock(_ addr: UnsafeRawPointer, _ len: size_t) -> CInt {
    // Page-granularity working-set lock via VirtualLock. Returns 0 on success, -1
    // with errno on failure (matching the POSIX contract that wrapSyscall expects).
    // Windows VirtualLock returns `Bool` (Swift overlay) where `true` == success.
    let ok = VirtualLock(UnsafeMutableRawPointer(mutating: addr), SIZE_T(len))
    if !ok {
        errno = EACCES
        return -1
    }
    return 0
}

@inline(__always)
private func _winMunlock(_ addr: UnsafeRawPointer, _ len: size_t) -> CInt {
    let ok = VirtualUnlock(UnsafeMutableRawPointer(mutating: addr), SIZE_T(len))
    if !ok {
        errno = EACCES
        return -1
    }
    return 0
}
#else
#error("unsupported os")
#endif

#if os(Android)
internal typealias FILEPointer = OpaquePointer
#else
internal typealias FILEPointer = UnsafeMutablePointer<FILE>
#endif

#if canImport(WinSDK)
// Windows MSVC: ucrt provides `fopen`/`fclose` directly. `stat()` is `_stat64()`.
// `lstat`/`readlink`/`mlock`/`munlock` are stubbed/remapped above.
private let sysFopen = fopen
private let sysMlock = _winMlock
private let sysMunlock = _winMunlock
private let sysFclose = fclose
private let sysStat = { @Sendable in _stat64($0, $1) }
private let sysLstat = { @Sendable in _stat64($0, $1) }
private let sysReadlink = _winReadlink
#else
private let sysFopen = fopen
private let sysMlock = mlock
private let sysMunlock = munlock
private let sysFclose = fclose
private let sysStat = { @Sendable in stat($0, $1) }
private let sysLstat = lstat
private let sysReadlink = readlink
#endif

// MARK:- Copied code from SwiftNIO
private func isUnacceptableErrno(_ code: CInt) -> Bool {
    switch code {
    case EFAULT, EBADF:
        return true
    default:
        return false
    }
}

// Sorry, we really try hard to not use underscored attributes. In this case however we seem to break the inlining threshold which makes a system call take twice the time, ie. we need this exception.
@inline(__always)
internal func wrapSyscall<T: FixedWidthInteger>(where function: String = #function, _ body: () throws -> T) throws -> T
{
    while true {
        let res = try body()
        if res == -1 {
            let err = errno
            if err == EINTR {
                continue
            }
            assert(!isUnacceptableErrno(err), "unacceptable errno \(err) \(strerror(err)!)")
            throw IOError(errnoCode: err, reason: function)
        }
        return res
    }
}

// Sorry, we really try hard to not use underscored attributes. In this case however we seem to break the inlining threshold which makes a system call take twice the time, ie. we need this exception.
@inline(__always)
internal func wrapErrorIsNullReturnCall<T>(
    errorReason: @autoclosure () -> String = #function,
    _ body: () throws -> T?
) throws -> T {
    while true {
        guard let res = try body() else {
            let err = errno
            if err == EINTR {
                continue
            }
            assert(!isUnacceptableErrno(err), "unacceptable errno \(err) \(strerror(err)!)")
            throw IOError(errnoCode: err, reason: errorReason())
        }
        return res
    }
}

// MARK:- Our functions
internal enum Posix {
    @inline(never)
    internal static func fopen(file: String, mode: String) throws -> FILEPointer {
        try file.withCString { fileCString in
            try wrapErrorIsNullReturnCall(errorReason: "fopen(file: \"\(file)\", mode: \"\(mode)\")") {
                sysFopen(fileCString, mode)
            }
        }
    }

    @inline(never)
    internal static func fclose(file: FILEPointer) throws -> CInt {
        try wrapSyscall {
            sysFclose(file)
        }
    }

    @inline(never)
    internal static func readlink(
        path: UnsafePointer<Int8>,
        buf: UnsafeMutablePointer<Int8>,
        bufSize: Int
    ) throws -> Int {
        try wrapSyscall {
            sysReadlink(path, buf, bufSize)
        }
    }

    @inline(never)
    @discardableResult
    internal static func stat(path: UnsafePointer<CChar>, buf: UnsafeMutablePointer<stat>) throws -> CInt {
        try wrapSyscall {
            sysStat(path, buf)
        }
    }

    @inline(never)
    @discardableResult
    internal static func lstat(path: UnsafePointer<Int8>, buf: UnsafeMutablePointer<stat>) throws -> Int32 {
        try wrapSyscall {
            sysLstat(path, buf)
        }
    }

    @inline(never)
    @discardableResult
    internal static func mlock(addr: UnsafeRawPointer, len: size_t) throws -> CInt {
        try wrapSyscall {
            sysMlock(addr, len)
        }
    }

    @inline(never)
    @discardableResult
    internal static func munlock(addr: UnsafeRawPointer, len: size_t) throws -> CInt {
        try wrapSyscall {
            sysMunlock(addr, len)
        }
    }
}
