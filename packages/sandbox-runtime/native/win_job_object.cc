// Win32 Job Object + AppContainer controller for @convira/sandbox-runtime
// (A2 increment 2; AppContainer profile lifecycle added in HARDENING batch 5,
// ABI 2).
//
// Raw N-API (NAPI_VERSION=8, Electron-ABI-stable), mirroring runtime-core's
// safe_workspace_fs precedent. Exposes kill-on-close Job Objects with a hard
// process/job commit-memory cap (JOB_OBJECT_LIMIT_PROCESS_MEMORY +
// JOB_OBJECT_LIMIT_JOB_MEMORY), an ActiveProcessLimit, and an optional
// cumulative user-CPU ceiling (JOB_OBJECT_LIMIT_JOB_TIME /
// PerJobUserTimeLimit — the honest RLIMIT_CPU analog; a percent rate cap is
// NOT a budget and is only reported via getInfo, never used for a claim).
//
// ABI 2 adds the AppContainer profile surface consumed by
// `src/win-appcontainer.ts` (probe module + boot janitor):
// createAppContainerProfile / deriveAppContainerSid /
// deleteAppContainerProfile / removeAppContainerAce. The SPAWN side of
// AppContainer lives in the companion launcher EXE
// (win_appcontainer_launch.cc): SECURITY_CAPABILITIES must be present at
// CreateProcessW time, so it cannot be applied from Node after spawn the way
// job assignment is. The launcher also closes the pre-assignment race: it
// creates the child CREATE_SUSPENDED, assigns it to a kill-on-close job, and
// only then resumes — caged from the first instruction.
//
// HONEST LIMITATION of the post-spawn assignment path in THIS module: Node
// cannot spawn CREATE_SUSPENDED, so callers assign a pid to its job just
// after spawn. A hostile child could fork in that microsecond pre-assignment
// window and the fork would escape kill-on-close. Production Windows spawns
// go through the launcher (whose caging is race-free); the post-spawn hook
// remains only the outer backstop on the trusted launcher process itself.
//
// The build script (scripts/build-win-job-object-native.mjs) refuses to
// compile this anywhere but win32; the #else stubs below exist only so an
// accidental foreign-platform compile fails closed instead of linking a
// silently useless module.

#include <node_api.h>

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>

#include "win_appcontainer_common.h"
#endif

namespace {

constexpr int kBindingAbiVersion = 2;

void Throw(napi_env env, const char* code, const std::string& message) {
  napi_throw_error(env, code, message.c_str());
}

#ifdef _WIN32

std::string WindowsErrorMessage(DWORD value) {
  LPSTR raw = nullptr;
  const DWORD length = FormatMessageA(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, value, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      reinterpret_cast<LPSTR>(&raw), 0, nullptr);
  std::string message = length && raw ? std::string(raw, length) : "Windows error";
  if (raw) LocalFree(raw);
  while (!message.empty() && (message.back() == '\r' || message.back() == '\n')) {
    message.pop_back();
  }
  return message;
}

void ThrowWindows(napi_env env, const std::string& operation, DWORD value = GetLastError()) {
  Throw(env, "EIO", operation + ": " + WindowsErrorMessage(value) +
                        " (code " + std::to_string(value) + ")");
}

// jobId -> HANDLE registry. Handles are process-lifetime resources; closeJob
// releases them (and kill-on-close reaps any remaining members).
std::mutex g_jobs_mutex;
std::unordered_map<int32_t, HANDLE> g_jobs;
int32_t g_next_job_id = 1;

int32_t RegisterJob(HANDLE job) {
  std::lock_guard<std::mutex> guard(g_jobs_mutex);
  const int32_t id = g_next_job_id++;
  g_jobs.emplace(id, job);
  return id;
}

HANDLE TakeJob(int32_t id) {
  std::lock_guard<std::mutex> guard(g_jobs_mutex);
  auto it = g_jobs.find(id);
  if (it == g_jobs.end()) return nullptr;
  HANDLE job = it->second;
  g_jobs.erase(it);
  return job;
}

HANDLE PeekJob(int32_t id) {
  std::lock_guard<std::mutex> guard(g_jobs_mutex);
  auto it = g_jobs.find(id);
  return it == g_jobs.end() ? nullptr : it->second;
}

bool GetInt32(napi_env env, napi_value value, int32_t* out) {
  return napi_get_value_int32(env, value, out) == napi_ok;
}

bool GetStringUtf8(napi_env env, napi_value value, std::string* out) {
  size_t length = 0;
  if (napi_get_value_string_utf8(env, value, nullptr, 0, &length) != napi_ok) return false;
  std::vector<char> buffer(length + 1, '\0');
  size_t copied = 0;
  if (napi_get_value_string_utf8(env, value, buffer.data(), buffer.size(), &copied) != napi_ok) {
    return false;
  }
  out->assign(buffer.data(), copied);
  return true;
}

bool ReadArgs(napi_env env, napi_callback_info info, size_t expected,
              napi_value* values) {
  size_t argc = expected;
  if (napi_get_cb_info(env, info, &argc, values, nullptr, nullptr) != napi_ok ||
      argc != expected) {
    Throw(env, "EINVAL", "invalid win_job_object argument count");
    return false;
  }
  return true;
}

// Reads an optional positive-number property; false on type errors. `*found`
// reports presence so absent limits stay unset rather than becoming zero.
bool ReadOptionalPositive(napi_env env, napi_value object, const char* name,
                          double* out, bool* found) {
  *found = false;
  bool has = false;
  if (napi_has_named_property(env, object, name, &has) != napi_ok) return false;
  if (!has) return true;
  napi_value value;
  if (napi_get_named_property(env, object, name, &value) != napi_ok) return false;
  napi_valuetype type;
  if (napi_typeof(env, value, &type) != napi_ok) return false;
  if (type == napi_undefined || type == napi_null) return true;
  double number = 0;
  if (napi_get_value_double(env, value, &number) != napi_ok || number <= 0) {
    Throw(env, "EINVAL", std::string("win_job_object: ") + name +
                             " must be a positive number when present");
    return false;
  }
  *out = number;
  *found = true;
  return true;
}

// createJob({ memoryLimitMb?, maxProcesses?, cpuTimeMs?, killOnClose }) -> jobId
napi_value CreateJobNative(napi_env env, napi_callback_info info) {
  napi_value args[1];
  if (!ReadArgs(env, info, 1, args)) return nullptr;

  double memory_limit_mb = 0;
  bool has_memory = false;
  double max_processes = 0;
  bool has_processes = false;
  double cpu_time_ms = 0;
  bool has_cpu = false;
  if (!ReadOptionalPositive(env, args[0], "memoryLimitMb", &memory_limit_mb, &has_memory) ||
      !ReadOptionalPositive(env, args[0], "maxProcesses", &max_processes, &has_processes) ||
      !ReadOptionalPositive(env, args[0], "cpuTimeMs", &cpu_time_ms, &has_cpu)) {
    return nullptr;
  }
  bool kill_on_close = false;
  {
    napi_value value;
    if (napi_get_named_property(env, args[0], "killOnClose", &value) != napi_ok ||
        napi_get_value_bool(env, value, &kill_on_close) != napi_ok) {
      Throw(env, "EINVAL", "win_job_object: killOnClose must be a boolean");
      return nullptr;
    }
  }

  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  if (job == nullptr) {
    ThrowWindows(env, "CreateJobObjectW failed");
    return nullptr;
  }

  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
  if (kill_on_close) {
    limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  }
  if (has_memory) {
    const SIZE_T bytes = static_cast<SIZE_T>(memory_limit_mb) * 1024ull * 1024ull;
    limits.BasicLimitInformation.LimitFlags |=
        JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY;
    limits.ProcessMemoryLimit = bytes;
    limits.JobMemoryLimit = bytes;
  }
  if (has_processes) {
    limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limits.BasicLimitInformation.ActiveProcessLimit = static_cast<DWORD>(max_processes);
  }
  if (has_cpu) {
    // PerJobUserTimeLimit is in 100ns ticks; 1ms = 10,000 ticks.
    limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_TIME;
    limits.BasicLimitInformation.PerJobUserTimeLimit.QuadPart =
        static_cast<LONGLONG>(cpu_time_ms) * 10'000ll;
  }

  if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits,
                               sizeof(limits))) {
    const DWORD error = GetLastError();
    CloseHandle(job);
    ThrowWindows(env, "SetInformationJobObject failed", error);
    return nullptr;
  }

  const int32_t id = RegisterJob(job);
  napi_value result;
  napi_create_int32(env, id, &result);
  return result;
}

// assignProcess(jobId, pid)
napi_value AssignProcessNative(napi_env env, napi_callback_info info) {
  napi_value args[2];
  if (!ReadArgs(env, info, 2, args)) return nullptr;
  int32_t job_id = 0;
  int32_t pid = 0;
  if (!GetInt32(env, args[0], &job_id) || !GetInt32(env, args[1], &pid) || pid <= 0) {
    Throw(env, "EINVAL", "win_job_object: assignProcess needs (jobId, pid)");
    return nullptr;
  }
  HANDLE job = PeekJob(job_id);
  if (job == nullptr) {
    Throw(env, "EINVAL", "win_job_object: unknown jobId " + std::to_string(job_id));
    return nullptr;
  }
  HANDLE process =
      OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, static_cast<DWORD>(pid));
  if (process == nullptr) {
    ThrowWindows(env, "OpenProcess failed for pid " + std::to_string(pid));
    return nullptr;
  }
  const BOOL assigned = AssignProcessToJobObject(job, process);
  const DWORD error = assigned ? 0 : GetLastError();
  CloseHandle(process);
  if (!assigned) {
    ThrowWindows(env, "AssignProcessToJobObject failed for pid " + std::to_string(pid), error);
    return nullptr;
  }
  return nullptr;
}

// terminateJob(jobId, exitCode)
napi_value TerminateJobNative(napi_env env, napi_callback_info info) {
  napi_value args[2];
  if (!ReadArgs(env, info, 2, args)) return nullptr;
  int32_t job_id = 0;
  int32_t exit_code = 0;
  if (!GetInt32(env, args[0], &job_id) || !GetInt32(env, args[1], &exit_code)) {
    Throw(env, "EINVAL", "win_job_object: terminateJob needs (jobId, exitCode)");
    return nullptr;
  }
  HANDLE job = PeekJob(job_id);
  if (job == nullptr) {
    Throw(env, "EINVAL", "win_job_object: unknown jobId " + std::to_string(job_id));
    return nullptr;
  }
  if (!TerminateJobObject(job, static_cast<UINT>(exit_code))) {
    ThrowWindows(env, "TerminateJobObject failed");
    return nullptr;
  }
  return nullptr;
}

// closeJob(jobId) — kill-on-close reaps any remaining members.
napi_value CloseJobNative(napi_env env, napi_callback_info info) {
  napi_value args[1];
  if (!ReadArgs(env, info, 1, args)) return nullptr;
  int32_t job_id = 0;
  if (!GetInt32(env, args[0], &job_id)) {
    Throw(env, "EINVAL", "win_job_object: closeJob needs (jobId)");
    return nullptr;
  }
  HANDLE job = TakeJob(job_id);
  if (job == nullptr) {
    Throw(env, "EINVAL", "win_job_object: unknown jobId " + std::to_string(job_id));
    return nullptr;
  }
  CloseHandle(job);
  return nullptr;
}

// ─── AppContainer profile surface (ABI 2, win-appcontainer.ts) ─────────────

std::string SidToString(napi_env env, PSID sid) {
  LPWSTR raw = nullptr;
  if (!ConvertSidToStringSidW(sid, &raw)) {
    ThrowWindows(env, "ConvertSidToStringSidW failed");
    return std::string();
  }
  const std::string value = convira_appcontainer::WideToUtf8(raw);
  LocalFree(raw);
  return value;
}

void ThrowHresult(napi_env env, const std::string& operation, HRESULT hr) {
  ThrowWindows(env, operation, static_cast<DWORD>(HRESULT_CODE(hr)));
}

// createAppContainerProfile(name) -> AppContainer SID string. Idempotent:
// an already-existing profile resolves to its (deterministic) SID.
napi_value CreateAppContainerProfileNative(napi_env env, napi_callback_info info) {
  napi_value args[1];
  if (!ReadArgs(env, info, 1, args)) return nullptr;
  std::string name;
  if (!GetStringUtf8(env, args[0], &name) || name.empty()) {
    Throw(env, "EINVAL", "win_job_object: createAppContainerProfile needs (name)");
    return nullptr;
  }
  PSID sid = nullptr;
  const HRESULT hr =
      convira_appcontainer::CreateProfileOrDerive(convira_appcontainer::Utf8ToWide(name), &sid);
  if (FAILED(hr) || sid == nullptr) {
    ThrowHresult(env, "CreateAppContainerProfile failed for " + name, hr);
    return nullptr;
  }
  const std::string sidString = SidToString(env, sid);
  FreeSid(sid);
  if (sidString.empty()) return nullptr;
  napi_value result;
  napi_create_string_utf8(env, sidString.c_str(), NAPI_AUTO_LENGTH, &result);
  return result;
}

// deriveAppContainerSid(name) -> SID string (deterministic, no profile write).
napi_value DeriveAppContainerSidNative(napi_env env, napi_callback_info info) {
  napi_value args[1];
  if (!ReadArgs(env, info, 1, args)) return nullptr;
  std::string name;
  if (!GetStringUtf8(env, args[0], &name) || name.empty()) {
    Throw(env, "EINVAL", "win_job_object: deriveAppContainerSid needs (name)");
    return nullptr;
  }
  PSID sid = nullptr;
  const HRESULT hr =
      convira_appcontainer::DeriveSidForProfile(convira_appcontainer::Utf8ToWide(name), &sid);
  if (FAILED(hr) || sid == nullptr) {
    ThrowHresult(env, "DeriveAppContainerSidFromAppContainerName failed for " + name, hr);
    return nullptr;
  }
  const std::string sidString = SidToString(env, sid);
  FreeSid(sid);
  if (sidString.empty()) return nullptr;
  napi_value result;
  napi_create_string_utf8(env, sidString.c_str(), NAPI_AUTO_LENGTH, &result);
  return result;
}

// deleteAppContainerProfile(name) — idempotent ("not found" is success) so
// the launcher's finally and the boot janitor can both call it safely.
napi_value DeleteAppContainerProfileNative(napi_env env, napi_callback_info info) {
  napi_value args[1];
  if (!ReadArgs(env, info, 1, args)) return nullptr;
  std::string name;
  if (!GetStringUtf8(env, args[0], &name) || name.empty()) {
    Throw(env, "EINVAL", "win_job_object: deleteAppContainerProfile needs (name)");
    return nullptr;
  }
  const HRESULT hr =
      convira_appcontainer::DeleteProfileIdempotent(convira_appcontainer::Utf8ToWide(name));
  if (FAILED(hr)) {
    ThrowHresult(env, "DeleteAppContainerProfile failed for " + name, hr);
    return nullptr;
  }
  return nullptr;
}

// removeAppContainerAce(path, name) — strip every ACE carrying the profile's
// SID from the path's DACL (propagates to descendants). The boot janitor uses
// this so crash-orphaned ephemeral-SID ACEs cannot accumulate on user
// directories. A missing path is success (nothing to revoke).
napi_value RemoveAppContainerAceNative(napi_env env, napi_callback_info info) {
  napi_value args[2];
  if (!ReadArgs(env, info, 2, args)) return nullptr;
  std::string target;
  std::string name;
  if (!GetStringUtf8(env, args[0], &target) || target.empty() ||
      !GetStringUtf8(env, args[1], &name) || name.empty()) {
    Throw(env, "EINVAL", "win_job_object: removeAppContainerAce needs (path, name)");
    return nullptr;
  }
  PSID sid = nullptr;
  const HRESULT hr =
      convira_appcontainer::DeriveSidForProfile(convira_appcontainer::Utf8ToWide(name), &sid);
  if (FAILED(hr) || sid == nullptr) {
    ThrowHresult(env, "DeriveAppContainerSidFromAppContainerName failed for " + name, hr);
    return nullptr;
  }
  const DWORD status =
      convira_appcontainer::RemoveSidAcesFromPath(convira_appcontainer::Utf8ToWide(target), sid);
  FreeSid(sid);
  if (status != ERROR_SUCCESS) {
    ThrowWindows(env, "removeAppContainerAce failed for " + target, status);
    return nullptr;
  }
  return nullptr;
}

// One-time runtime detection: prove the AppContainer profile lifecycle works
// for THIS user (create + derive + delete a throwaway). A policy-locked host
// reports false here instead of crashing later; the throwaway name is
// pid-scoped so concurrent processes cannot collide.
bool DetectAppContainerSupport() {
  const std::wstring name =
      L"ConviraSbxDetect-" + std::to_wstring(GetCurrentProcessId());
  PSID sid = nullptr;
  if (FAILED(convira_appcontainer::CreateProfileOrDerive(name, &sid)) || sid == nullptr) {
    return false;
  }
  FreeSid(sid);
  return SUCCEEDED(convira_appcontainer::DeleteProfileIdempotent(name));
}

bool DetectNetworkCapabilitySids() {
  std::vector<std::vector<BYTE>> storage;
  std::vector<SID_AND_ATTRIBUTES> sids;
  return convira_appcontainer::BuildNetworkCapabilitySids(&storage, &sids);
}

// One-time detection of CPU rate control support (Windows 8+; reported for
// visibility only, never used to back the `cpu` capability claim).
bool DetectCpuRateControl() {
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  if (job == nullptr) return false;
  JOBOBJECT_CPU_RATE_CONTROL_INFORMATION rate = {};
  rate.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
  rate.CpuRate = 5000;  // 50% in 1/100ths of a percent.
  const BOOL ok =
      SetInformationJobObject(job, JobObjectCpuRateControlInformation, &rate, sizeof(rate));
  CloseHandle(job);
  return ok == TRUE;
}

napi_value GetInfoNative(napi_env env, napi_callback_info) {
  static const bool cpu_rate_control = DetectCpuRateControl();
  static const bool app_container = DetectAppContainerSupport();
  static const bool network_capability_sids = DetectNetworkCapabilitySids();
  napi_value result;
  napi_value abi;
  napi_value platform;
  napi_value primitives;
  napi_create_object(env, &result);
  napi_create_int32(env, kBindingAbiVersion, &abi);
  napi_create_string_utf8(env, "win32", NAPI_AUTO_LENGTH, &platform);
  napi_create_object(env, &primitives);
  const struct {
    const char* name;
    bool value;
  } flags[] = {
      {"processMemory", true},   {"jobMemory", true},   {"activeProcess", true},
      {"jobUserTime", true},     {"killOnClose", true}, {"cpuRateControl", cpu_rate_control},
      // ABI 2 (AppContainer). appContainer is runtime-proven (a throwaway
      // profile round-trip for THIS user); the spawn-side attribute and the
      // ACL/SID APIs are compile-target facts (_WIN32_WINNT=0x0A00), and the
      // spawn itself is only ever claimed via the launcher's own probes.
      {"appContainer", app_container},
      {"securityCapabilitiesSpawn", app_container},
      {"directorySidAcl", true},
      {"networkCapabilitySids", network_capability_sids},
  };
  for (const auto& flag : flags) {
    napi_value value;
    napi_get_boolean(env, flag.value, &value);
    napi_set_named_property(env, primitives, flag.name, value);
  }
  napi_set_named_property(env, result, "abiVersion", abi);
  napi_set_named_property(env, result, "platform", platform);
  napi_set_named_property(env, result, "primitives", primitives);
  return result;
}

#else  // !_WIN32 — never built here (the build script skips), fail closed.

napi_value Unsupported(napi_env env, napi_callback_info) {
  Throw(env, "ENOTSUP", "win_job_object is only supported on Windows");
  return nullptr;
}

napi_value CreateJobNative(napi_env env, napi_callback_info info) {
  return Unsupported(env, info);
}
napi_value AssignProcessNative(napi_env env, napi_callback_info info) {
  return Unsupported(env, info);
}
napi_value TerminateJobNative(napi_env env, napi_callback_info info) {
  return Unsupported(env, info);
}
napi_value CloseJobNative(napi_env env, napi_callback_info info) {
  return Unsupported(env, info);
}
napi_value GetInfoNative(napi_env env, napi_callback_info info) {
  return Unsupported(env, info);
}
napi_value CreateAppContainerProfileNative(napi_env env, napi_callback_info info) {
  return Unsupported(env, info);
}
napi_value DeriveAppContainerSidNative(napi_env env, napi_callback_info info) {
  return Unsupported(env, info);
}
napi_value DeleteAppContainerProfileNative(napi_env env, napi_callback_info info) {
  return Unsupported(env, info);
}
napi_value RemoveAppContainerAceNative(napi_env env, napi_callback_info info) {
  return Unsupported(env, info);
}

#endif

napi_value Init(napi_env env, napi_value exports) {
  const napi_property_descriptor properties[] = {
      {"getInfo", nullptr, GetInfoNative, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"createJob", nullptr, CreateJobNative, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"assignProcess", nullptr, AssignProcessNative, nullptr, nullptr, nullptr, napi_default,
       nullptr},
      {"terminateJob", nullptr, TerminateJobNative, nullptr, nullptr, nullptr, napi_default,
       nullptr},
      {"closeJob", nullptr, CloseJobNative, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"createAppContainerProfile", nullptr, CreateAppContainerProfileNative, nullptr, nullptr,
       nullptr, napi_default, nullptr},
      {"deriveAppContainerSid", nullptr, DeriveAppContainerSidNative, nullptr, nullptr, nullptr,
       napi_default, nullptr},
      {"deleteAppContainerProfile", nullptr, DeleteAppContainerProfileNative, nullptr, nullptr,
       nullptr, napi_default, nullptr},
      {"removeAppContainerAce", nullptr, RemoveAppContainerAceNative, nullptr, nullptr, nullptr,
       napi_default, nullptr},
  };
  napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties);
  return exports;
}

}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
