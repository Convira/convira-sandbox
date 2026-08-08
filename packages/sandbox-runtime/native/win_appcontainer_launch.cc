// convira_sbx_launch — the AppContainer spawn wrapper for
// @convira/sandbox-runtime (HARDENING batch 5).
//
// SECURITY_CAPABILITIES must be present at CreateProcessW time, so
// AppContainer can never be applied to a Node-spawned child after the fact
// the way Job Objects are. This launcher is therefore used AS the wrapper
// command (argv-level, exactly like `sandbox-exec` on macOS and `bwrap` on
// Linux): Node spawns the launcher with inherited stdio/env/cwd, and the
// launcher creates the REAL command inside the AppContainer.
//
//   convira_sbx_launch <profileName> <grantsFile> [--allow-network]
//                      [--probe-report <file>] -- <command> <args...>
//
// Steps (each fails closed - any error before ResumeThread means the child
// never ran):
//   1. CreateAppContainerProfile (per-user, no admin; ERROR_ALREADY_EXISTS
//      resolves to the deterministic SID).
//   2. Apply the grants file (deny\t / read\t / write\t lines): inheritable
//      DENY then GRANT ACEs for the AC SID via SetEntriesInAclW +
//      SetNamedSecurityInfoW. No ACE for the AC SID = no access, so the
//      grants are the child's ENTIRE reachable filesystem.
//   3. Build SECURITY_CAPABILITIES: the AC SID plus, only with
//      --allow-network, INTERNET_CLIENT + PRIVATE_NETWORK_CLIENT_SERVER.
//      No SIDs = default-deny outbound INCLUDING loopback. Loopback is never
//      grantable here: the exemption is an admin-only CheckNetIsolation
//      registration a per-user install cannot perform.
//   4. CreateProcessW(CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT) with
//      the attribute list + inherited std handles.
//   5. Create a kill-on-close Job Object, AssignProcessToJobObject, and only
//      then ResumeThread: job caging holds from the child's FIRST
//      instruction (the race the post-spawn assignment path cannot close).
//      With --probe-report, the IsProcessInJob verdict and child pid are
//      written BEFORE the resume so the spawn-caging probe can verify it.
//   6. Wait, propagate the child's exit code, and in the cleanup path revoke
//      the granted ACEs (ephemeral SIDs would otherwise accumulate orphan
//      ACEs on user directories), delete the profile, and remove the grants
//      file. A hard kill of this launcher skips cleanup by design: the job's
//      kill-on-close still reaps the child tree instantly, and the boot
//      janitor (src/win-appcontainer.ts, ledger-driven) sweeps the profile
//      and ACEs at next start.
//
// Why not a restricted / low-integrity token instead: no outbound-network
// deny and only integrity-level write blocking (no read confinement) —
// enforcing strictly less than what the capability flags advertise would be
// dishonest, so AppContainer is the only shipped path and probe failures
// keep tools hidden.

#ifdef _WIN32

#define NOMINMAX
// winsock2.h MUST precede windows.h: windows.h pulls in the ancient winsock.h
// otherwise and the two define the same symbols. The `listen` / `connect`
// self-test verbs need the sockets API.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

#include "win_appcontainer_common.h"

namespace {

using convira_appcontainer::ApplySidAceOnPath;
using convira_appcontainer::BuildNetworkCapabilitySids;
using convira_appcontainer::CreateProfileOrDerive;
using convira_appcontainer::DeleteProfileIdempotent;
using convira_appcontainer::RemoveSidAcesFromPath;
using convira_appcontainer::Utf8ToWide;

struct GrantEntry {
  enum class Kind { kDeny, kRead, kWrite } kind;
  std::wstring path;
};

void PrintError(const wchar_t* stage, DWORD code) {
  fwprintf(stderr, L"[convira_sbx_launch] %ls failed (code %lu)\n", stage,
           static_cast<unsigned long>(code));
}

// Reports whether a variable is set WITHOUT printing its value: these names
// carry user paths and this text goes to public CI logs. The two-character
// probe buffer is deliberate rather than sloppy - a too-small buffer is not a
// failure for GetEnvironmentVariableW, which answers the REQUIRED size, so only
// a genuinely absent variable answers 0.
const wchar_t* EnvPresence(const wchar_t* name) {
  wchar_t probe[2];
  return GetEnvironmentVariableW(name, probe, ARRAYSIZE(probe)) > 0 ? L"present" : L"MISSING";
}

bool ReadFileBytes(const std::wstring& path, std::string* out) {
  HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  bool ok = true;
  for (;;) {
    char buffer[4096];
    DWORD read = 0;
    if (!ReadFile(file, buffer, sizeof(buffer), &read, nullptr)) {
      ok = false;
      break;
    }
    if (read == 0) break;
    out->append(buffer, read);
  }
  CloseHandle(file);
  return ok;
}

// Parse `deny|read|write<TAB>path` lines (UTF-8; tabs/newlines are illegal
// in Windows paths so no quoting layer exists).
bool ParseGrants(const std::string& raw, std::vector<GrantEntry>* out) {
  size_t start = 0;
  while (start < raw.size()) {
    size_t end = raw.find('\n', start);
    if (end == std::string::npos) end = raw.size();
    std::string line = raw.substr(start, end - start);
    start = end + 1;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;
    const size_t tab = line.find('\t');
    if (tab == std::string::npos || tab + 1 >= line.size()) return false;
    const std::string kind = line.substr(0, tab);
    GrantEntry entry;
    if (kind == "deny") {
      entry.kind = GrantEntry::Kind::kDeny;
    } else if (kind == "read") {
      entry.kind = GrantEntry::Kind::kRead;
    } else if (kind == "write") {
      entry.kind = GrantEntry::Kind::kWrite;
    } else {
      return false;
    }
    entry.path = Utf8ToWide(line.substr(tab + 1));
    if (entry.path.empty()) return false;
    out->push_back(std::move(entry));
  }
  return true;
}

// Standard Windows argv quoting (the CommandLineToArgvW inverse).
std::wstring QuoteArg(const std::wstring& arg) {
  if (!arg.empty() && arg.find_first_of(L" \t\n\v\"") == std::wstring::npos) return arg;
  std::wstring out = L"\"";
  size_t i = 0;
  while (i < arg.size()) {
    size_t backslashes = 0;
    while (i < arg.size() && arg[i] == L'\\') {
      ++backslashes;
      ++i;
    }
    if (i == arg.size()) {
      out.append(backslashes * 2, L'\\');
      break;
    }
    if (arg[i] == L'"') {
      out.append(backslashes * 2 + 1, L'\\');
      out.push_back(L'"');
    } else {
      out.append(backslashes, L'\\');
      out.push_back(arg[i]);
    }
    ++i;
  }
  out.push_back(L'"');
  return out;
}

void MakeStdHandleInheritable(DWORD which) {
  HANDLE handle = GetStdHandle(which);
  if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
    SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
  }
}

bool WriteProbeReport(const std::wstring& path, BOOL caged, DWORD pid) {
  HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  char buffer[64];
  const int length = snprintf(buffer, sizeof(buffer), "caged=%d\npid=%lu\n", caged ? 1 : 0,
                              static_cast<unsigned long>(pid));
  DWORD written = 0;
  const BOOL ok = WriteFile(file, buffer, static_cast<DWORD>(length), &written, nullptr);
  CloseHandle(file);
  return ok == TRUE;
}

// ─── self-test payload (`--selftest <verb>`) ────────────────────────────────
//
// Why this exists: every destructive capability probe needs a CHILD PROCESS
// that does one specific thing (fork and report a pid, commit N MiB, burn
// CPU, fill a directory, read a path, open a socket) so the probe can observe
// what the OS control did to it. Those children used to be
// `process.execPath -e "<script>"`. In a packaged Electron build that is the
// application binary, and the `runAsNode` fuse - deliberately disabled, so a
// signed Convira.exe can never be reused as a general-purpose Node
// interpreter - makes it ignore `-e` entirely. The child booted the app, lost
// the single-instance lock, exited 0, and every probe reported its control
// unavailable. Re-enabling the fuse to make a self-test pass would trade a
// real security control for a green check, so instead the probe subject
// becomes this: a CLOSED verb table in the one binary the Windows sandbox
// already requires, already ships, already gates at package time, and already
// signs.
//
// This is deliberately NOT an interpreter. Each verb is a fixed behavior with
// clamped numeric arguments; there is no path from argv to code execution, no
// format string derives from argv, and unknown verbs do nothing at all.
//
// `--selftest` is mutually exclusive with the launcher form by construction:
// it is dispatched from the first line of wmain, so it never reaches profile
// creation, the grants file, ApplySidAceOnPath, or SECURITY_CAPABILITIES.

// Every long-lived verb dies on its own after this, so a probe that is killed
// mid-flight can never leave a spinner behind on a developer's machine or a
// CI runner.
constexpr DWORD kSelfTestCeilingMs = 120000;
constexpr DWORD kSelfTestPollMs = 20;
constexpr DWORD kSelfTestWaitCapMs = 10000;
// A `fill` child must never be able to exhaust the disk if the probe's
// sampler dies: 64 MiB is 16x the 4 MiB breach budget the watchdog measures.
constexpr unsigned long kFillTotalCapMib = 64;
constexpr unsigned long kAllocCapMib = 4096;

const wchar_t* SelfTestFlag(int argc, wchar_t** argv, const wchar_t* name) {
  for (int i = 3; i + 1 < argc; ++i) {
    if (wcscmp(argv[i], name) == 0) return argv[i + 1];
  }
  return nullptr;
}

unsigned long SelfTestNumber(int argc, wchar_t** argv, const wchar_t* name, unsigned long cap) {
  const wchar_t* raw = SelfTestFlag(argc, argv, name);
  if (raw == nullptr) return 0;
  wchar_t* end = nullptr;
  const unsigned long parsed = wcstoul(raw, &end, 10);
  if (end == raw) return 0;
  return parsed > cap ? cap : parsed;
}

// Publish atomically: a probe polls these files, and a torn read would be
// indistinguishable from a verb that reported the wrong thing.
bool SelfTestPublish(const std::wstring& path, const char* text) {
  const std::wstring tmp = path + L".tmp";
  HANDLE file = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  DWORD written = 0;
  const BOOL ok =
      WriteFile(file, text, static_cast<DWORD>(strlen(text)), &written, nullptr);
  FlushFileBuffers(file);
  CloseHandle(file);
  if (ok != TRUE) return false;
  return MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING) == TRUE;
}

bool SelfTestFileExists(const std::wstring& path) {
  return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

std::wstring SelfTestSelfPath() {
  wchar_t buffer[MAX_PATH * 2];
  const DWORD length = GetModuleFileNameW(nullptr, buffer, ARRAYSIZE(buffer));
  return length == 0 ? std::wstring() : std::wstring(buffer, length);
}

// Spawn ourselves as an idle child. The command line is built from our own
// module path plus a constant - never from argv - so this cannot be steered.
bool SelfTestSpawnIdle(PROCESS_INFORMATION* out) {
  const std::wstring self = SelfTestSelfPath();
  if (self.empty()) return false;
  std::wstring commandLine = QuoteArg(self) + L" --selftest idle";
  std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
  mutableCommandLine.push_back(L'\0');
  STARTUPINFOW startupInfo{};
  startupInfo.cb = sizeof(startupInfo);
  return CreateProcessW(nullptr, mutableCommandLine.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &startupInfo, out) == TRUE;
}

void SelfTestIdle() { Sleep(kSelfTestCeilingMs); }

int SelfTestMain(int argc, wchar_t** argv) {
  if (argc < 3) {
    fwprintf(stderr, L"[convira_sbx_launch] --selftest requires a verb\n");
    return 2;
  }
  const std::wstring verb = argv[2];

  if (verb == L"idle") {
    SelfTestIdle();
    return 0;
  }

  // The handshake verb. Proves this binary ran THIS payload, which a child
  // that merely exits 0 cannot fake - and exiting 0 is exactly what the old
  // packaged probe child did.
  if (verb == L"echo") {
    const wchar_t* nonce = SelfTestFlag(argc, argv, L"--nonce");
    const wchar_t* out = SelfTestFlag(argc, argv, L"--out");
    if (nonce == nullptr || out == nullptr) return 2;
    std::string ascii;
    for (const wchar_t* p = nonce; *p != L'\0'; ++p) {
      const wchar_t c = *p;
      const bool hex = (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f');
      if (!hex || ascii.size() >= 64) return 2;
      ascii.push_back(static_cast<char>(c));
    }
    if (ascii.size() < 8) return 2;
    return SelfTestPublish(out, ascii.c_str()) ? 0 : 1;
  }

  // Fork a grandchild and report its pid, then stay alive so the caller can
  // terminate the job and require BOTH to disappear. `--wait-for` lets the
  // caller open the gate only after AssignProcessToJobObject has returned, so
  // the grandchild cannot be created in the pre-assignment window.
  if (verb == L"spawn-child") {
    const wchar_t* pidFile = SelfTestFlag(argc, argv, L"--pid-file");
    if (pidFile == nullptr) return 2;
    const wchar_t* waitFor = SelfTestFlag(argc, argv, L"--wait-for");
    if (waitFor != nullptr) {
      for (DWORD waited = 0; waited < kSelfTestWaitCapMs; waited += kSelfTestPollMs) {
        if (SelfTestFileExists(waitFor)) break;
        Sleep(kSelfTestPollMs);
      }
    }
    PROCESS_INFORMATION child{};
    if (!SelfTestSpawnIdle(&child)) return 1;
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%lu", static_cast<unsigned long>(child.dwProcessId));
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    if (!SelfTestPublish(pidFile, buffer)) return 1;
    SelfTestIdle();
    return 0;
  }

  // Report whether a spawn was PERMITTED. The pids probe needs both answers:
  // a control run that must say `spawned`, and a capped run that must say
  // `denied`. Without the control leg, any CreateProcessW failure - antivirus,
  // a bad self path - forges proof of a process-count limit that is not there.
  if (verb == L"try-spawn") {
    const wchar_t* out = SelfTestFlag(argc, argv, L"--out");
    if (out == nullptr) return 2;
    PROCESS_INFORMATION child{};
    if (SelfTestSpawnIdle(&child)) {
      TerminateProcess(child.hProcess, 0);
      CloseHandle(child.hThread);
      CloseHandle(child.hProcess);
      return SelfTestPublish(out, "spawned") ? 0 : 1;
    }
    return SelfTestPublish(out, "denied") ? 0 : 1;
  }

  // Commit real pages: a reservation the kernel never backs would not test a
  // commit-charge cap. memset forces the commit.
  if (verb == L"alloc") {
    const wchar_t* out = SelfTestFlag(argc, argv, L"--out");
    if (out == nullptr) return 2;
    const unsigned long mib = SelfTestNumber(argc, argv, L"--mib", kAllocCapMib);
    if (mib == 0) return 2;
    const SIZE_T bytes = static_cast<SIZE_T>(mib) << 20;
    void* block = VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (block == nullptr) return SelfTestPublish(out, "alloc-failed") ? 0 : 1;
    memset(block, 1, bytes);
    const bool ok = SelfTestPublish(out, "ok");
    VirtualFree(block, 0, MEM_RELEASE);
    return ok ? 0 : 1;
  }

  // Publish BEFORE spinning. The CPU probe's control leg requires this marker
  // plus a still-alive process: a child that quits on its own must fail it,
  // which is precisely the false positive the old probe could not see.
  if (verb == L"burn-cpu") {
    const wchar_t* marker = SelfTestFlag(argc, argv, L"--marker");
    if (marker == nullptr) return 2;
    if (!SelfTestPublish(marker, "spinning")) return 1;
    volatile unsigned long long spin = 0;
    for (;;) ++spin;
  }

  // Append 1 MiB chunks round-robin so the watchdog's directory sampler sees
  // growth. Hard-capped so a killed probe cannot fill the volume.
  if (verb == L"fill") {
    const wchar_t* dir = SelfTestFlag(argc, argv, L"--dir");
    const wchar_t* marker = SelfTestFlag(argc, argv, L"--marker");
    if (dir == nullptr || marker == nullptr) return 2;
    if (!SelfTestPublish(marker, "spinning")) return 1;
    std::vector<char> chunk(1u << 20, 1);
    for (unsigned long written = 0; written < kFillTotalCapMib; ++written) {
      wchar_t target[MAX_PATH * 2];
      _snwprintf_s(target, ARRAYSIZE(target), _TRUNCATE, L"%ls\\w%lu", dir, written % 4);
      HANDLE file = CreateFileW(target, FILE_APPEND_DATA, 0, nullptr, OPEN_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
      if (file != INVALID_HANDLE_VALUE) {
        DWORD wrote = 0;
        WriteFile(file, chunk.data(), static_cast<DWORD>(chunk.size()), &wrote, nullptr);
        CloseHandle(file);
      }
      Sleep(kSelfTestPollMs);
    }
    SelfTestIdle();
    return 0;
  }

  // Read one path that must be denied and read+write one that must be
  // allowed, then publish both verdicts together. The AppContainer leg and
  // the control leg run IDENTICAL argv; the only difference is the token, so
  // a divergence can only come from the confinement.
  if (verb == L"fs-check") {
    const wchar_t* outside = SelfTestFlag(argc, argv, L"--outside");
    const wchar_t* granted = SelfTestFlag(argc, argv, L"--granted");
    if (outside == nullptr || granted == nullptr) return 2;
    HANDLE probe = CreateFileW(outside, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
    const char* outsideVerdict = "denied";
    if (probe != INVALID_HANDLE_VALUE) {
      outsideVerdict = "read";
      CloseHandle(probe);
    }
    std::wstring inner = std::wstring(granted) + L"\\inner.txt";
    const char* insideVerdict = "failed";
    if (SelfTestPublish(inner, "x")) {
      HANDLE back = CreateFileW(inner.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (back != INVALID_HANDLE_VALUE) {
        char byte = 0;
        DWORD read = 0;
        if (ReadFile(back, &byte, 1, &read, nullptr) && read == 1 && byte == 'x') {
          insideVerdict = "ok";
        }
        CloseHandle(back);
      }
    }
    std::string verdict = std::string(outsideVerdict) + ":" + insideVerdict;
    return SelfTestPublish(std::wstring(granted) + L"\\result.txt", verdict.c_str()) ? 0 : 1;
  }

  if (verb == L"listen") {
    const wchar_t* portFile = SelfTestFlag(argc, argv, L"--port-file");
    if (portFile == nullptr) return 2;
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
    SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server == INVALID_SOCKET) return 1;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(server, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
        listen(server, 1) != 0) {
      closesocket(server);
      return 1;
    }
    int addressLength = sizeof(address);
    if (getsockname(server, reinterpret_cast<sockaddr*>(&address), &addressLength) != 0) {
      closesocket(server);
      return 1;
    }
    char buffer[16];
    snprintf(buffer, sizeof(buffer), "%u", static_cast<unsigned>(ntohs(address.sin_port)));
    if (!SelfTestPublish(portFile, buffer)) {
      closesocket(server);
      return 1;
    }
    SOCKET client = accept(server, nullptr, nullptr);
    if (client != INVALID_SOCKET) {
      send(client, "hi", 2, 0);
      closesocket(client);
    }
    closesocket(server);
    SelfTestIdle();
    return 0;
  }

  if (verb == L"connect") {
    const wchar_t* out = SelfTestFlag(argc, argv, L"--out");
    if (out == nullptr) return 2;
    const unsigned long port = SelfTestNumber(argc, argv, L"--port", 65535);
    if (port == 0) return 2;
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return SelfTestPublish(out, "denied") ? 0 : 1;
    u_long nonBlocking = 1;
    ioctlsocket(sock, FIONBIO, &nonBlocking);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(static_cast<unsigned short>(port));
    const char* verdict = "denied";
    if (connect(sock, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0) {
      verdict = "connected";
    } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
      fd_set writable;
      FD_ZERO(&writable);
      FD_SET(sock, &writable);
      timeval timeout{};
      timeout.tv_sec = 10;
      const int ready = select(0, nullptr, &writable, nullptr, &timeout);
      if (ready > 0) {
        int soError = 0;
        int soErrorLength = sizeof(soError);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soError),
                       &soErrorLength) == 0 &&
            soError == 0) {
          verdict = "connected";
        }
      } else if (ready == 0) {
        verdict = "timeout";
      }
    }
    closesocket(sock);
    return SelfTestPublish(out, verdict) ? 0 : 1;
  }

  fwprintf(stderr, L"[convira_sbx_launch] unknown --selftest verb\n");
  return 2;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  // The self-test payload is dispatched FIRST and returns unconditionally, so
  // it can never reach profile creation, the grants file, ApplySidAceOnPath or
  // SECURITY_CAPABILITIES. The two argv forms are mutually exclusive by
  // construction rather than by convention.
  if (argc >= 2 && wcscmp(argv[1], L"--selftest") == 0) return SelfTestMain(argc, argv);
  if (argc < 5) {
    fwprintf(stderr,
             L"usage: convira_sbx_launch <profileName> <grantsFile> [--allow-network] "
             L"[--probe-report <file>] -- <command> <args...>\n");
    return 1;
  }
  const std::wstring profileName = argv[1];
  const std::wstring grantsFile = argv[2];
  bool allowNetwork = false;
  std::wstring probeReportFile;
  int commandIndex = -1;
  for (int i = 3; i < argc; ++i) {
    if (wcscmp(argv[i], L"--") == 0) {
      commandIndex = i + 1;
      break;
    }
    if (wcscmp(argv[i], L"--allow-network") == 0) {
      allowNetwork = true;
    } else if (wcscmp(argv[i], L"--probe-report") == 0 && i + 1 < argc) {
      probeReportFile = argv[++i];
    } else {
      fwprintf(stderr, L"[convira_sbx_launch] unknown option: %ls\n", argv[i]);
      return 1;
    }
  }
  if (commandIndex < 0 || commandIndex >= argc) {
    fwprintf(stderr, L"[convira_sbx_launch] missing -- <command>\n");
    return 1;
  }

  std::string grantsRaw;
  if (!ReadFileBytes(grantsFile, &grantsRaw)) {
    PrintError(L"reading grants file", GetLastError());
    return 1;
  }
  std::vector<GrantEntry> grants;
  if (!ParseGrants(grantsRaw, &grants)) {
    fwprintf(stderr, L"[convira_sbx_launch] malformed grants file\n");
    return 1;
  }

  PSID sid = nullptr;
  const HRESULT profileResult = CreateProfileOrDerive(profileName, &sid);
  if (FAILED(profileResult) || sid == nullptr) {
    PrintError(L"CreateAppContainerProfile", static_cast<DWORD>(profileResult));
    return 1;
  }

  int exitCode = 1;
  std::vector<std::wstring> appliedPaths;
  HANDLE job = nullptr;
  PROCESS_INFORMATION processInfo = {};
  // Outlives the do-while: `attributes` aliases this buffer and is torn down
  // in the shared cleanup below.
  std::vector<BYTE> attributeBuffer;
  LPPROC_THREAD_ATTRIBUTE_LIST attributes = nullptr;
  bool spawned = false;
  bool waited = false;

  do {
    // Denies land first so a deny inside a broader grant always wins.
    bool grantsOk = true;
    for (const GrantEntry& entry : grants) {
      const DWORD status =
          ApplySidAceOnPath(entry.path, sid, entry.kind == GrantEntry::Kind::kWrite,
                            entry.kind == GrantEntry::Kind::kDeny);
      if (status != ERROR_SUCCESS) {
        PrintError(L"granting directory access", status);
        grantsOk = false;
        break;
      }
      appliedPaths.push_back(entry.path);
    }
    if (!grantsOk) break;

    std::vector<std::vector<BYTE>> capabilityStorage;
    std::vector<SID_AND_ATTRIBUTES> capabilities;
    if (allowNetwork && !BuildNetworkCapabilitySids(&capabilityStorage, &capabilities)) {
      PrintError(L"building network capability SIDs", GetLastError());
      break;
    }

    SECURITY_CAPABILITIES securityCapabilities = {};
    securityCapabilities.AppContainerSid = sid;
    securityCapabilities.Capabilities = capabilities.empty() ? nullptr : capabilities.data();
    securityCapabilities.CapabilityCount = static_cast<DWORD>(capabilities.size());

    SIZE_T attributeSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeSize);
    attributeBuffer.resize(attributeSize);
    attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributeBuffer.data());
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &attributeSize)) {
      PrintError(L"InitializeProcThreadAttributeList", GetLastError());
      attributes = nullptr;
      break;
    }
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                   &securityCapabilities, sizeof(securityCapabilities), nullptr,
                                   nullptr)) {
      PrintError(L"UpdateProcThreadAttribute", GetLastError());
      break;
    }

    std::wstring commandLine;
    for (int i = commandIndex; i < argc; ++i) {
      if (!commandLine.empty()) commandLine.push_back(L' ');
      commandLine += QuoteArg(argv[i]);
    }

    MakeStdHandleInheritable(STD_INPUT_HANDLE);
    MakeStdHandleInheritable(STD_OUTPUT_HANDLE);
    MakeStdHandleInheritable(STD_ERROR_HANDLE);

    STARTUPINFOEXW startupInfo = {};
    startupInfo.StartupInfo.cb = sizeof(startupInfo);
    startupInfo.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startupInfo.StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startupInfo.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startupInfo.StartupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    startupInfo.lpAttributeList = attributes;

    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');
    // Name the executable EXPLICITLY rather than letting CreateProcessW parse
    // it out of the command line. With a null lpApplicationName the parser may
    // fall back to a PATH search, which answers ERROR_ENVVAR_NOT_FOUND (203)
    // when it cannot resolve - a code that describes the search, not the real
    // problem. Naming it also removes the classic unquoted-path ambiguity about
    // which binary actually runs.
    const std::wstring applicationName = argv[commandIndex];
    if (!CreateProcessW(applicationName.c_str(), mutableCommandLine.data(), nullptr, nullptr, TRUE,
                        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
                        &startupInfo.StartupInfo, &processInfo)) {
      const DWORD spawnError = GetLastError();
      // Say WHICH input was bad. A bare code sent two rounds chasing the wrong
      // cause: whether the image is reachable at all, and whether the confined
      // environment still carries the variables Windows needs, are different
      // faults that this one code cannot distinguish.
      const DWORD imageAttributes = GetFileAttributesW(applicationName.c_str());
      // The first version of this printed SystemRoot and PATH only, and both
      // came back present - which retired the obvious reading of code 203 and
      // left nothing to go on. The set below is every input CreateProcessW
      // consults for an AppContainer child that the caller can plausibly have
      // stripped: the AC profile lives under LOCALAPPDATA, and the working
      // directory matters because the drive it sits on may differ from the
      // image's. Presence only, never values - this goes to public CI logs.
      wchar_t cwd[MAX_PATH];
      const DWORD cwdLen = GetCurrentDirectoryW(ARRAYSIZE(cwd), cwd);
      fwprintf(stderr,
               L"[convira_sbx_launch] image=%ls attrs=%lu cwd=%ls\n"
               L"[convira_sbx_launch] env SystemRoot=%ls SystemDrive=%ls PATH=%ls "
               L"LOCALAPPDATA=%ls APPDATA=%ls USERPROFILE=%ls TEMP=%ls\n",
               applicationName.c_str(), static_cast<unsigned long>(imageAttributes),
               cwdLen > 0 && cwdLen < ARRAYSIZE(cwd) ? cwd : L"<unavailable>",
               EnvPresence(L"SystemRoot"), EnvPresence(L"SystemDrive"), EnvPresence(L"PATH"),
               EnvPresence(L"LOCALAPPDATA"), EnvPresence(L"APPDATA"),
               EnvPresence(L"USERPROFILE"), EnvPresence(L"TEMP"));
      PrintError(L"CreateProcessW", spawnError);
      break;
    }
    spawned = true;

    job = CreateJobObjectW(nullptr, nullptr);
    if (job == nullptr) {
      PrintError(L"CreateJobObjectW", GetLastError());
      break;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits,
                                 sizeof(limits))) {
      PrintError(L"SetInformationJobObject", GetLastError());
      break;
    }
    if (!AssignProcessToJobObject(job, processInfo.hProcess)) {
      PrintError(L"AssignProcessToJobObject", GetLastError());
      break;
    }

    if (!probeReportFile.empty()) {
      BOOL caged = FALSE;
      if (!IsProcessInJob(processInfo.hProcess, job, &caged)) caged = FALSE;
      // Written while the child is STILL SUSPENDED - the probe's proof that
      // caging precedes the first instruction.
      WriteProbeReport(probeReportFile, caged, processInfo.dwProcessId);
    }

    if (ResumeThread(processInfo.hThread) == static_cast<DWORD>(-1)) {
      PrintError(L"ResumeThread", GetLastError());
      break;
    }

    WaitForSingleObject(processInfo.hProcess, INFINITE);
    waited = true;
    DWORD childExit = 1;
    if (GetExitCodeProcess(processInfo.hProcess, &childExit)) {
      exitCode = static_cast<int>(childExit);
    }
  } while (false);

  // Cleanup. A failure after CreateProcessW but before the wait completed
  // leaves a (possibly still suspended) child that job kill-on-close may not
  // cover yet: terminate it explicitly, then let the job handle close reap
  // any descendants.
  if (spawned && !waited) {
    TerminateProcess(processInfo.hProcess, 1);
  }
  if (processInfo.hThread != nullptr) CloseHandle(processInfo.hThread);
  if (processInfo.hProcess != nullptr) CloseHandle(processInfo.hProcess);
  if (job != nullptr) CloseHandle(job);
  if (attributes != nullptr) DeleteProcThreadAttributeList(attributes);
  for (const std::wstring& granted : appliedPaths) {
    RemoveSidAcesFromPath(granted, sid);
  }
  DeleteProfileIdempotent(profileName);
  FreeSid(sid);
  DeleteFileW(grantsFile.c_str());
  return exitCode;
}

#else  // !_WIN32 — never built here (the build script skips); fail closed.

#include <cstdio>

int main() {
  std::fprintf(stderr, "convira_sbx_launch is only supported on Windows\n");
  return 1;
}

#endif
