// Shared AppContainer helpers for the win_job_object addon and the
// convira_sbx_launch launcher EXE (HARDENING batch 5). Header-only so the two
// compile units cannot drift; win32-only (both consumers guard on _WIN32; the
// build script never compiles either elsewhere).
//
// Everything here is deliberately plain Win32 + C++17: profile lifecycle via
// userenv (CreateAppContainerProfile / DeriveAppContainerSidFromAppContainerName /
// DeleteAppContainerProfile), directory grants as GRANT/DENY ACEs for the
// AppContainer SID (SetEntriesInAclW + SetNamedSecurityInfoW with inheritance,
// so descendants are covered), and revocation that strips every ACE carrying
// the SID again - per-spawn profiles use ephemeral names, so leftover ACEs
// would otherwise accumulate on user directories until the DACL size limit.

#ifndef CONVIRA_WIN_APPCONTAINER_COMMON_H_
#define CONVIRA_WIN_APPCONTAINER_COMMON_H_

#ifdef _WIN32

#define NOMINMAX
#include <windows.h>

#include <aclapi.h>
#include <sddl.h>
#include <userenv.h>

#include <string>
#include <vector>

namespace convira_appcontainer {

inline std::wstring Utf8ToWide(const std::string& value) {
  if (value.empty()) return std::wstring();
  const int needed =
      MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
  if (needed <= 0) return std::wstring();
  std::wstring out(static_cast<size_t>(needed), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), out.data(),
                      needed);
  return out;
}

inline std::string WideToUtf8(const std::wstring& value) {
  if (value.empty()) return std::string();
  const int needed = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                         static_cast<int>(value.size()), nullptr, 0, nullptr,
                                         nullptr);
  if (needed <= 0) return std::string();
  std::string out(static_cast<size_t>(needed), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), out.data(),
                      needed, nullptr, nullptr);
  return out;
}

// \\?\-extend a path when it exceeds MAX_PATH so ACL calls keep working on
// long / UNC workspace paths; short canonical paths stay untouched (the
// common case, and the form every security API accepts everywhere).
inline std::wstring ExtendPathIfNeeded(const std::wstring& path) {
  if (path.size() < MAX_PATH) return path;
  if (path.rfind(L"\\\\?\\", 0) == 0) return path;
  if (path.rfind(L"\\\\", 0) == 0) return L"\\\\?\\UNC\\" + path.substr(2);
  return L"\\\\?\\" + path;
}

// Derive the deterministic AppContainer SID for a profile name. Caller frees
// the result with FreeSid.
inline HRESULT DeriveSidForProfile(const std::wstring& profileName, PSID* sid) {
  return DeriveAppContainerSidFromAppContainerName(profileName.c_str(), sid);
}

// Create the per-user profile (no admin needed) or reuse an existing one.
// On success *sid is owned by the caller (FreeSid).
inline HRESULT CreateProfileOrDerive(const std::wstring& profileName, PSID* sid) {
  const HRESULT created = CreateAppContainerProfile(
      profileName.c_str(), profileName.c_str(), profileName.c_str(), nullptr, 0, sid);
  if (SUCCEEDED(created)) return S_OK;
  if (created == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
    return DeriveSidForProfile(profileName, sid);
  }
  return created;
}

// Delete a profile, treating "not found" as success so cleanup paths and the
// boot janitor are idempotent.
inline HRESULT DeleteProfileIdempotent(const std::wstring& profileName) {
  const HRESULT hr = DeleteAppContainerProfile(profileName.c_str());
  if (SUCCEEDED(hr)) return S_OK;
  if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) ||
      hr == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND) ||
      hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND)) {
    return S_OK;
  }
  return hr;
}

// Rights carried by one ACE.
//
// A DENY ace must never be built from the grant flavor. The launcher passes
// write=false for every deny entry, so deriving the mask from `write` produced
// a deny of GENERIC_READ|GENERIC_EXECUTE only: a denyPaths carve-out nested
// inside a granted write tree stayed writable and deletable. An AppContainer
// child could not READ ~/.ssh or the convira-store, but could still overwrite
// or delete them - while SandboxSpawnConfig.denyPaths promises the path is
// hidden, and both other adapters implement it that way ((deny file-read*
// file-write*) on macOS, tmpfs/ro-bind on Linux).
//
// WRITE_DAC and WRITE_OWNER are denied too, so the child cannot rewrite the
// DACL to re-grant itself what this ACE removes.
//
// Windows evaluates DENY before ALLOW, so a broader deny mask can only ever
// remove access - there is no path by which this widens anything.
inline DWORD AceMaskFor(bool write, bool deny) {
  if (deny) {
    return (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | DELETE | WRITE_DAC | WRITE_OWNER);
  }
  return write ? (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | DELETE)
               : (GENERIC_READ | GENERIC_EXECUTE);
}

// Add one inheritable GRANT or DENY ACE for `sid` to the path's DACL.
// SetNamedSecurityInfoW propagates inheritable ACEs through the existing
// subtree (auto-inheritance), which is exactly what a directory grant needs.
inline DWORD ApplySidAceOnPath(const std::wstring& rawPath, PSID sid, bool write, bool deny) {
  const std::wstring path = ExtendPathIfNeeded(rawPath);
  PACL oldDacl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  DWORD status = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                       nullptr, nullptr, &oldDacl, nullptr, &descriptor);
  if (status != ERROR_SUCCESS) return status;

  EXPLICIT_ACCESS_W access = {};
  access.grfAccessPermissions = AceMaskFor(write, deny);
  access.grfAccessMode = deny ? DENY_ACCESS : GRANT_ACCESS;
  access.grfInheritance = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
  access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  access.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  access.Trustee.ptstrName = static_cast<LPWSTR>(sid);

  PACL newDacl = nullptr;
  status = SetEntriesInAclW(1, &access, oldDacl, &newDacl);
  if (status == ERROR_SUCCESS) {
    status = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
                                   DACL_SECURITY_INFORMATION, nullptr, nullptr, newDacl,
                                   nullptr);
  }
  if (newDacl != nullptr) LocalFree(newDacl);
  if (descriptor != nullptr) LocalFree(descriptor);
  return status;
}

// Remove every allow/deny ACE carrying `sid` from the path's DACL (and, via
// auto-inheritance, from descendants). "Path gone" counts as success: there
// is nothing left to revoke, and cleanup must be idempotent.
inline DWORD RemoveSidAcesFromPath(const std::wstring& rawPath, PSID sid) {
  const std::wstring path = ExtendPathIfNeeded(rawPath);
  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  DWORD status = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                       nullptr, nullptr, &dacl, nullptr, &descriptor);
  if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) return ERROR_SUCCESS;
  if (status != ERROR_SUCCESS) return status;
  if (dacl == nullptr) {
    if (descriptor != nullptr) LocalFree(descriptor);
    return ERROR_SUCCESS;
  }

  bool removedAny = false;
  for (DWORD index = dacl->AceCount; index > 0; --index) {
    LPVOID rawAce = nullptr;
    if (!GetAce(dacl, index - 1, &rawAce)) continue;
    const ACE_HEADER* header = static_cast<ACE_HEADER*>(rawAce);
    PSID aceSid = nullptr;
    if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
      aceSid = &static_cast<ACCESS_ALLOWED_ACE*>(rawAce)->SidStart;
    } else if (header->AceType == ACCESS_DENIED_ACE_TYPE) {
      aceSid = &static_cast<ACCESS_DENIED_ACE*>(rawAce)->SidStart;
    } else {
      continue;
    }
    if (EqualSid(aceSid, sid)) {
      if (DeleteAce(dacl, index - 1)) removedAny = true;
    }
  }
  if (removedAny) {
    status = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
                                   DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr);
  }
  if (descriptor != nullptr) LocalFree(descriptor);
  return status;
}

// Capability SIDs for a network-allowed spawn: INTERNET_CLIENT plus
// PRIVATE_NETWORK_CLIENT_SERVER (LAN). Loopback is intentionally absent -
// exempting a package from loopback isolation is an admin-only
// CheckNetIsolation operation a per-user install cannot perform.
inline bool BuildNetworkCapabilitySids(std::vector<std::vector<BYTE>>* storage,
                                       std::vector<SID_AND_ATTRIBUTES>* out) {
  const WELL_KNOWN_SID_TYPE kinds[] = {WinCapabilityInternetClientSid,
                                       WinCapabilityPrivateNetworkClientServerSid};
  for (const WELL_KNOWN_SID_TYPE kind : kinds) {
    std::vector<BYTE> buffer(SECURITY_MAX_SID_SIZE);
    DWORD size = static_cast<DWORD>(buffer.size());
    if (!CreateWellKnownSid(kind, nullptr, buffer.data(), &size)) return false;
    buffer.resize(size);
    storage->push_back(std::move(buffer));
    SID_AND_ATTRIBUTES entry = {};
    entry.Sid = storage->back().data();
    entry.Attributes = SE_GROUP_ENABLED;
    out->push_back(entry);
  }
  return true;
}

}  // namespace convira_appcontainer

#endif  // _WIN32

#endif  // CONVIRA_WIN_APPCONTAINER_COMMON_H_
