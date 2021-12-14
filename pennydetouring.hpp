#pragma once
#include <assert.h>
#include <windows.h>
#include <vector>

#if _WIN32 || _WIN64
	#if _WIN64
		#define ENV64
	#else
		#define ENV32
	#endif
#endif

#if __GNUC__
	#if __x86_64__ || __ppc64__
		#define ENV64
	#else
		#define ENV32
	#endif
#endif

#if defined(ENV64)
	#define HOOK_SIZE 12
	#define HOOK_ADDRESS_OFFSET 2
#elif defined(ENV32)
	#define HOOK_SIZE 7
	#define HOOK_ADDRESS_OFFSET 1
#endif

struct HookData {
public:
#if defined(ENV64)
	using PTR_T = unsigned long long;
#elif defined(ENV32)
	using PTR_T = unsigned int;
#endif
public:
	PTR_T src;
	std::vector<char> org;
	std::vector<char> jmp;
};

void SetHook(const HookData& hook, bool enable) {
	//cmp org and jmp size
	assert(hook.org.size() == hook.jmp.size());
	//cmp hook size
	assert(hook.jmp.size() == HOOK_SIZE);

	DWORD currentProtection{};
	VirtualProtect((LPVOID)hook.src, hook.jmp.size(), PAGE_EXECUTE_READWRITE, &currentProtection);

	std::memcpy((LPVOID)hook.src, enable ? hook.jmp.data() : hook.org.data(), hook.jmp.size());

	DWORD dummy{};
	VirtualProtect((LPVOID)hook.src, hook.jmp.size(), currentProtection, &dummy);
}

HookData CreateHook(LPVOID src, LPVOID dst) {
	HookData hook{};

	DWORD currentProtection{};
	VirtualProtect((LPVOID)src, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &currentProtection);

	hook.src = (HookData::PTR_T)src;
	hook.org.resize(HOOK_SIZE);
	hook.jmp.resize(HOOK_SIZE);

	std::memcpy(hook.org.data(), src, HOOK_SIZE);

#if defined(ENV64)
	hook.jmp[0] = 0x48;
	hook.jmp[1] = 0xB8;
	hook.jmp[10] = 0xFF;
	hook.jmp[11] = 0xE0;
#elif defined(ENV32)
	hook.jmp[0] = 0xB8;
	hook.jmp[5] = 0xFF;
	hook.jmp[6] = 0xE0;
#endif

	std::memcpy(hook.jmp.data() + HOOK_ADDRESS_OFFSET, &dst, sizeof(LPVOID));

	DWORD dummy{};
	VirtualProtect((LPVOID)src, HOOK_SIZE, currentProtection, &dummy);

	return std::move(hook);
}