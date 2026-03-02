# KeyAuth‑CPP Secured Example

This repository is a hardened KeyAuth C++ example that integrates **WinSecRuntime** and **NigelCrypt** for runtime security and sensitive string protection.

It is designed to be:
- easy to compile
- safe for legit users
- configurable for higher security without changing your API

---

## Quick Start

1. open `x64/main.cpp` (or `x86/main.cpp`)  
2. replace the app config strings:
   - `name`
   - `ownerid`
   - `version`
   - `url`
   - `path`
3. build the solution in Visual Studio (`Release | x64` or `Release | x86`)

---

## Build & Run

### x64
```
x64/example.sln
```
Build `Release | x64`.

### x86
```
x86/example.sln
```
Build `Release | x86`.

---

## What’s Secured

This example includes:
- **WinSecRuntime** runtime integrity checks
- **NigelCrypt** runtime string protection
- **KeyAuth** client validation + session guarding

---

## WinSecRuntime (Runtime Security)

WinSecRuntime is integrated in both `x64/main.cpp` and `x86/main.cpp`.

### Core flow
```
WinSecRuntime::Initialize(...)
WinSecRuntime::StartIntegrityEngine(...)
WinSecRuntime::EnableAntiDebug(...)
WinSecRuntime::EnableHookGuard(...)
WinSecRuntime::RunAll(...)
```

If checks fail, the program exits early.

### Tunable Security Controls

These are defined near the top of each `main.cpp`:

```
constexpr WinSecRuntime::Mode kSecurityMode = WinSecRuntime::Mode::Aggressive;
constexpr bool kRunPeriodicChecks = true;
constexpr DWORD kPeriodicCheckMs = 20000;

constexpr bool kEnableSafeDllSearch = true;
constexpr bool kEnableDisallowUnc = true;
constexpr bool kEnableDisallowMotw = true;
constexpr bool kEnableIatWritableCheck = true;
constexpr bool kEnableIatBoundsCheck = true;
constexpr bool kEnableIatRequireExecutable = true;
constexpr bool kEnableIatDisallowSelf = true;
constexpr bool kEnableIatWriteProtect = false;
constexpr bool kEnableVmHeuristics = false;
constexpr int kVmMinCores = 0;
constexpr int kVmMinRamGb = 0;
constexpr uint32_t kNopSledThreshold = 0;
constexpr uint32_t kInt3SledThreshold = 0;
```

#### Recommended meanings
- **Aggressive** is balanced (good protection, low false positives).
- **Paranoid** can block legit users, use only if you set baselines.
- IAT write‑protect is off by default to avoid linker/runtime conflicts.
- VM heuristics are off by default to avoid blocking dev VM users.

### Full Config Block

The full `secure::runtime::Config` is built in:
```
build_security_config()
```

This is where you can set:
- module hashes
- IAT baselines
- text section baselines
- parent/chain checks
- prologue/inline‑hook checks

If you want all checks enforced, keep this logic:
```
const auto report = WinSecRuntime::RunAll(policy);
return report.ok();
```

---

## NigelCrypt (String Protection)

This example protects user‑visible strings and app config values using NigelCrypt.

### Usage
```
std::string value = nc("text", "aad:label");
```

### Notes
- NigelCrypt protects **runtime storage**, not compile‑time literals.
- If you need to remove plaintext literals from the binary, use the NigelCrypt packer and embed ciphertext.

---

## KeyAuth Integration

### App config
Replace these values in `x64/main.cpp` / `x86/main.cpp`:
```
name
ownerid
version
url
path
```

### Basic flow
```
KeyAuthApp.init()
KeyAuthApp.login()
KeyAuthApp.regstr()
KeyAuthApp.license()
KeyAuthApp.check()
```

### Session guard
This example runs:
- `checkAuthenticated()` in a background thread
- `sessionStatus()` periodic check

Do not remove those unless you fully replace them with your own protections.

---

## Troubleshooting

### GitHub “permission denied (publickey)”
Use this push command:
```
GIT_SSH_COMMAND='ssh -i /home/admin/.ssh/keyauth_cpp_secured_example -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new' git push
```

### Build errors
Make sure you build the correct configuration:
- Release | x64 for `x64/example.sln`
- Release | x86 for `x86/example.sln`

---

## FAQ

**Does this break API compatibility?**  
No. All changes are client‑side only.

**Will this block legit users?**  
Balanced settings are chosen by default. If you enable strict checks (e.g., IAT write‑protect, VM heuristics) you may see false positives.

**Can I turn off security?**  
Yes. Set `kSecurityMode` to `Minimal` and disable the toggles.

---

## Links

- KeyAuth App: https://keyauth.cc/app/
- C++ Example (base): https://github.com/KeyAuth/KeyAuth-CPP-Example

---

## License

KeyAuth is licensed under **Elastic License 2.0**.  
Do not remove or bypass license verification functionality.
