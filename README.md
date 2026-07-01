# AntiSkid

<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=JetBrains+Mono&size=26&duration=3000&pause=1000&color=00F7FF&center=true&vCenter=true&width=700&lines=Anti-Debug+%7C+Anti-VM+Protection;Windows+Low-Level+Security;Built+in+C%2B%2B;Lightweight+Runtime+Defense;Stay+Undetected+%F0%9F%94%A5" />
</p>

---

## 🧠 Overview

This project is a **lightweight Windows runtime protection module** written in **C++**, designed to detect:

* 🐞 Debuggers
* 🧪 Virtual Machines
* 🔍 Reverse engineering tools

If suspicious activity is detected, the program **immediately terminates execution** to prevent analysis or tampering.

> ⚠️ **Note:** This is **v1** and may contain bugs. Updates and improvements are coming soon.

---

## ⚙️ Features

### 🔎 Anti-Debugging Techniques

* `IsDebuggerPresent()` check
* `CheckRemoteDebuggerPresent()`
* Direct **PEB flag inspection**
* Detection of known tools:

  * x64dbg
  * IDA / IDA64
  * dnSpy
  * OllyDbg
  * Process Hacker

---

### 🖥️ Anti-VM Detection

* **CPUID vendor checks**

  * VMware
  * VirtualBox
  * KVM

* **Registry inspection**

  * BIOS manufacturer & product name

* **Driver/file detection**

  * `vmmouse.sys`
  * `VBoxMouse.sys`

---

## 🧩 How It Works

The system uses a **scoring mechanism**:

* Debugging activity increases `debugScore`
* VM indicators increase `vmScore`

```cpp
if (debugScore >= 3 || vmScore >= 2)
{
    ExitProcess(0);
}
```

✔ Smart threshold prevents false positives
✔ Multiple signals required before triggering

---

## 🚀 Usage

### 1. Build

Compile as a **DLL** using Visual Studio or any Windows toolchain.

### 2. Call Protection

```cpp
extern "C" void RunProtection();
```

Call this *early in your* application:

```cpp
RunProtection();
```

---

## 🧬 Exported Function

```cpp
__declspec(dllexport) void __cdecl RunProtection();
```

* Entry point for all protection checks
* Safe to call at startup or periodically

---

## ⚠️ Behavior

When a threat is detected:

* ❌ No warnings
* ❌ No logs
* ⚡ Immediate process termination

```cpp
void TriggerResponse()
{
    ExitProcess(0);
}
```

---

## 🛠️ Use Cases

* 🔐 Protect proprietary software
* 🎮 Anti-cheat / anti-tamper systems
* 🧪 Malware analysis evasion research (educational)
* 🧩 Reverse engineering resistance

---

## 📌 Notes

* Designed for **Windows only**
* Works on **x86 & x64**
* Minimal dependencies (WinAPI only)
* Fast execution, low overhead

---

## 🧊 Future Improvements

* 🧠 Heuristic-based detection
* ⏱️ Timing attack detection
* 🧬 Obfuscation layer
* 🔄 Self-integrity checks
* 🧱 Anti-dump protection

---

## 👾 Author

**FrostedFlakes666**

> "Coding For Fun wanted to make something so i can update"

---

<p align="center">
  ⚡ Stay sharp. Stay hidden. ⚡
</p>
