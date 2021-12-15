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

namespace SCData {
	static const char x64movint[10] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	static const char x86movint[5] = { 0xB8, 0x00, 0x00, 0x00, 0x00};
	static const char x86_64jmpint[2] = { 0xFF, 0xE0 };
	static const char x86_64callint[2] = { 0xFF, 0xD0 };
	static const char x86_64pushint[8] = { 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57 };
	static const char x86_64popint[8] = { 0x5F, 0x5E, 0x5D, 0x5C, 0x5B, 0x5A, 0x59, 0x58 };
}

struct JHookData {
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

void SetJHook(const JHookData& hook, bool enable) {
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

JHookData CreateJHook(LPVOID src, LPVOID dst, int offset) {
	JHookData hook{};

	DWORD currentProtection{};
	VirtualProtect((LPBYTE)src + offset, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &currentProtection);

	hook.src = (JHookData::PTR_T)src + offset;
	hook.org.resize(HOOK_SIZE);
	hook.jmp.resize(HOOK_SIZE);

	std::memcpy(hook.org.data(), (LPVOID)hook.src, HOOK_SIZE);

#if defined(ENV64)
	std::memcpy(hook.jmp.data(), SCData::x64movint, sizeof(SCData::x64movint));
	std::memcpy(hook.jmp.data() + sizeof(SCData::x64movint), SCData::x86_64jmpint, sizeof(SCData::x86_64jmpint));
#elif defined(ENV32)
	std::memcpy(hook.jmp.data(), SCData::x86movint, sizeof(SCData::x86movint));
	std::memcpy(hook.jmp.data() + sizeof(SCData::x86movint), SCData::x86_64jmpint, sizeof(SCData::x86_64jmpint));
#endif

	std::memcpy(hook.jmp.data() + HOOK_ADDRESS_OFFSET, &dst, sizeof(LPVOID));

	DWORD dummy{};
	VirtualProtect((LPVOID)src, HOOK_SIZE, currentProtection, &dummy);

	return std::move(hook);
}

bool CreateDiscreteHook(LPVOID src, LPVOID dst, int size) {
#if defined(ENV64)
	size_t stSize = sizeof(SCData::x64movint) + sizeof(SCData::x86_64jmpint);

	size_t trSize = sizeof(SCData::x86_64pushint) + 
		sizeof(SCData::x64movint) +
		sizeof(SCData::x86_64callint) +
		sizeof(SCData::x86_64popint) +
		stSize +
		sizeof(SCData::x64movint) +
		sizeof(SCData::x86_64jmpint);
#elif defined(ENV32)
	size_t stSize = sizeof(SCData::x86movint) + sizeof(SCData::x86_64jmpint);

	size_t trSize = sizeof(SCData::x86_64pushint) +
		sizeof(SCData::x86movint) +
		sizeof(SCData::x86_64callint) +
		sizeof(SCData::x86_64popint) +
		stSize +
		sizeof(SCData::x86movint) +
		sizeof(SCData::x86_64jmpint);
#endif

	if (size < stSize)
		return false;
	stSize = size;

	LPBYTE trAddress = (LPBYTE)VirtualAlloc(NULL, trSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (trAddress == 0)
		return false;

	int cursor = 0;
	
	memcpy(&trAddress[cursor], SCData::x86_64pushint, sizeof(SCData::x86_64pushint));
	cursor += sizeof(SCData::x86_64pushint);

#if defined(ENV64)
	memcpy(&trAddress[cursor], SCData::x64movint, sizeof(SCData::x64movint));
	cursor += 2;
	memcpy(&trAddress[cursor], &dst, sizeof(DWORD64));
	cursor += 8;
#elif defined(ENV32)
	memcpy(&trAddress[cursor], SCData::x86movint, sizeof(SCData::x86movint));
	cursor += 1;
	memcpy(&trAddress[cursor], &dst, sizeof(DWORD));
	cursor += 4;
#endif

	memcpy(&trAddress[cursor], SCData::x86_64callint, sizeof(SCData::x86_64callint));
	cursor += sizeof(SCData::x86_64callint);

	memcpy(&trAddress[cursor], SCData::x86_64popint, sizeof(SCData::x86_64popint));
	cursor += sizeof(SCData::x86_64popint);

	LPBYTE rjmpAddr = (LPBYTE)src + stSize;
	
	DWORD currentProtection{};
	VirtualProtect(src, stSize, PAGE_EXECUTE_READWRITE, &currentProtection);

	memcpy(&trAddress[cursor], src, stSize);
	cursor += stSize;

#if defined(ENV64)
	memcpy(&trAddress[cursor], SCData::x64movint, sizeof(SCData::x64movint));
	cursor += 2;
	memcpy(&trAddress[cursor], &rjmpAddr, sizeof(DWORD64));
	cursor += 8;
#elif defined(ENV32)
	memcpy(&trAddress[cursor], SCData::x86movint, sizeof(SCData::x86movint));
	cursor += 1;
	memcpy(&trAddress[cursor], &rjmpAddr, sizeof(DWORD));
	cursor += 4;
#endif

	memcpy(&trAddress[cursor], SCData::x86_64jmpint, sizeof(SCData::x86_64jmpint));
	cursor += sizeof(SCData::x86_64jmpint);

#if defined(ENV64)
	memcpy(src, SCData::x64movint, sizeof(SCData::x64movint));
	memcpy((LPBYTE)src + 2, &trAddress, sizeof(DWORD64));
	memcpy((LPBYTE)src + 10, SCData::x86_64jmpint, sizeof(SCData::x86_64jmpint));
#elif defined(ENV32)
	memcpy(src, SCData::x86movint, sizeof(SCData::x86movint));
	memcpy((LPBYTE)src + 1, &trAddress, sizeof(DWORD));
	memcpy((LPBYTE)src + 5, SCData::x86_64jmpint, sizeof(SCData::x86_64jmpint));
#endif

	DWORD dummy{};
	VirtualProtect(src, stSize, currentProtection, &dummy);

	return true;
}