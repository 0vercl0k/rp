/*++

Module Name:

	rp_windbg.cpp

Abstract:

	WinDBG extension front-end for rp++.

	This translation unit is the *only* difference between the standalone
	rp++ executable and the WinDBG extension DLL. It does not modify the
	rp++ core in any way: it is a plain consumer of the public core API
	(Program, find_gadgets, only_unique_gadgets, search_and_display, ...)
	exactly like rp/main.cpp is.

	The core writes its results to stdout through fmt::print. Rather than
	teaching the core about the debugger (which would fork it away from
	upstream), we transparently redirect stdout while the core runs, then
	hand the captured text to the debugger via the WindbgExt output stream.

Environment:

	User mode, Windows. Loaded by WinDBG through DebugExtensionInitialize.

Author:

	Taha Draidia (@tahadraidia)

--*/

#define _CRT_SECURE_NO_WARNINGS

#include "options.hpp"
#include "platform.h"
#include "program.hpp"
#include "coloshell.hpp"
#include "toolbox.hpp"

#include "windbgext.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <fmt/printf.h>

#include <fcntl.h>
#include <io.h>

#define EXT_MAJOR_VER  1
#define EXT_MINOR_VER  0

// Keep in sync with NUM_V in rp/main.cpp (the rp++ version reported by -v).
#define NUM_V "2.1.5"
#ifdef ARCH_X64
#define VERSION_TMP NUM_V " x64 built the " __DATE__ " " __TIME__
#elif defined ARCH_X86
#define VERSION_TMP NUM_V " x86 built the " __DATE__ " " __TIME__
#else
#define VERSION_TMP NUM_V " arm64 built the " __DATE__ " " __TIME__
#endif

#define VERSION_TM VERSION_TMP " for " SYSTEM_PLATFORM

#ifdef _DEBUG
#define VERSION VERSION_TM " (Debug)"
#else
#define VERSION VERSION_TM " (Release)"
#endif

/*++

Abstract:

	rp++ keeps its parsed command line in a single global, declared extern in
	options.hpp. The standalone build defines it in rp/main.cpp; since that
	file is excluded from the extension build, we own the definition here.

--*/
Options_t g_opts;

/*++

Routine Description:

	Tokenize the raw argument string WinDBG hands to the extension (a single
	string, unlike argv) into whitespace separated arguments.

Arguments:

	args - Supplies the raw argument string.

Return Value:

	The list of individual arguments.

--*/
static
std::vector<std::string>
TokenizeArgs(const std::string& args)
{
	std::vector<std::string> tokens;
	std::stringstream ss(args);
	std::string token;

	while (ss >> token) {
		// Split "--opt=value" (and "-r=8") into two tokens at the first '=',
		// so both the "--opt value" and "--opt=value" forms are accepted.
		const auto eq = token.find('=');
		if (eq != std::string::npos && token.size() > 1 && token[0] == '-') {
			tokens.push_back(token.substr(0, eq));
			tokens.push_back(token.substr(eq + 1));
		} else {
			tokens.push_back(token);
		}
	}

	return tokens;
}

// An option and the spellings that select it (short and/or long).
using Aliases = std::initializer_list<const char*>;

static
bool
HasArg(const std::vector<std::string>& args, Aliases names)
{
	for (const auto& a : args) {
		for (const char* n : names) {
			if (a == n) {
				return true;
			}
		}
	}
	return false;
}

static
std::string
ArgValue(const std::vector<std::string>& args, Aliases names)
{
	for (auto it = args.begin(); it != args.end(); ++it) {
		for (const char* n : names) {
			if (*it == n && std::next(it) != args.end()) {
				return *std::next(it);
			}
		}
	}
	return std::string();
}

static
uint32_t
ArgValueU32(const std::vector<std::string>& args, Aliases names)
{
	uint32_t value = 0;
	std::stringstream(ArgValue(args, names)) >> value;
	return value;
}

/*++

Routine Description:

	Map a --raw value to a CPU architecture. Accepts both the numeric form
	(x86->0, x64->1, arm->2, arm64->3) and the named form (x86/x64/arm/arm64),
	as the standalone rp++ command line does.

Arguments:

	value - Supplies the architecture selector.

Return Value:

	The matching CPU::E_CPU, or CPU_UNKNOWN.

--*/
static
CPU::E_CPU
RawToCpu(const std::string& value)
{
	if (value == "0" || value == "x86")   return CPU::CPU_x86;
	if (value == "1" || value == "x64")   return CPU::CPU_x64;
	if (value == "2" || value == "arm")   return CPU::CPU_ARM;
	if (value == "3" || value == "arm64") return CPU::CPU_ARM64;
	return CPU::CPU_UNKNOWN;
}

/*++

Routine Description:

	Fill g_opts from the raw WinDBG argument string, mirroring the options the
	standalone rp++ exposes on its command line. Both short and long spellings
	are accepted, in either the "--opt value" or "--opt=value" form.

Arguments:

	args - Supplies the raw argument string.

Return Value:

	true if -h/--help was requested, false otherwise.

--*/
static
bool
BuildOptions(const std::string& args)
{
	const std::vector<std::string> list = TokenizeArgs(args);

	g_opts.file     = ArgValue(list, {"-f", "--file"});
	g_opts.rop      = HasArg(list, {"-r", "--rop"}) ? ArgValueU32(list, {"-r", "--rop"}) : 0;
	g_opts.raw      = HasArg(list, {"--raw"}) ? RawToCpu(ArgValue(list, {"--raw"})) : CPU::CPU_UNKNOWN;
	g_opts.unique   = HasArg(list, {"--unique"});
	g_opts.shexa    = ArgValue(list, {"--search-hexa"});
	g_opts.maxth    = HasArg(list, {"--max-thread"}) ? ArgValueU32(list, {"--max-thread"}) : 2;
	g_opts.badbytes = ArgValue(list, {"--bad-bytes"});
	g_opts.sint     = ArgValue(list, {"--search-int"});
	g_opts.version  = HasArg(list, {"-v", "--version"});
	g_opts.thumb    = HasArg(list, {"--thumb"});
	g_opts.va       = ArgValue(list, {"--va"});
	g_opts.allow_branches = HasArg(list, {"--allow-branches"});
	g_opts.print_bytes    = HasArg(list, {"--print-bytes"});

	return HasArg(list, {"-h", "--help"});
}

/*++

Abstract:

	StdoutRedirector transparently reroutes the process stdout to a temporary
	file for the lifetime of a capture, so the untouched rp++ core (which prints
	through fmt::print) can be consumed without any change.

	Begin() redirects, End() restores stdout and returns everything the core
	wrote. If End() is not called the destructor still restores stdout so the
	debugger session is never left in a broken state.

--*/
class StdoutRedirector {
public:
	StdoutRedirector() = default;

	StdoutRedirector(const StdoutRedirector&) = delete;
	StdoutRedirector& operator=(const StdoutRedirector&) = delete;

	~StdoutRedirector() noexcept
	{
		if (_active) {
			Restore();
		}
	}

	bool
	Begin() noexcept
	{
		char dir[MAX_PATH]{};

		if (::GetTempPathA(sizeof(dir), dir) == 0) {
			return false;
		}

		if (::GetTempFileNameA(dir, "rp", 0, _path) == 0) {
			return false;
		}

		std::fflush(stdout);

		// Remember where stdout was pointing so we can put it back. In a
		// windowless debugger stdout may not be attached to anything, hence
		// the guarded _dup.
		const int stdoutFd = _fileno(stdout);
		_savedFd = (stdoutFd >= 0) ? _dup(stdoutFd) : -1;

		// freopen rebinds stdout to our temp file regardless of its prior
		// state, which is what makes this robust inside WinDBG.
		if (std::freopen(_path, "w", stdout) == nullptr) {
			if (_savedFd >= 0) {
				_close(_savedFd);
				_savedFd = -1;
			}
			return false;
		}

		_active = true;
		return true;
	}

	std::string
	End()
	{
		if (!_active) {
			return std::string();
		}

		Restore();

		std::string captured;
		std::ifstream file(_path, std::ios::binary);
		if (file) {
			std::ostringstream ss;
			ss << file.rdbuf();
			captured = ss.str();
		}

		::DeleteFileA(_path);
		_path[0] = '\0';

		return captured;
	}

private:
	void
	Restore() noexcept
	{
		std::fflush(stdout);

		if (_savedFd >= 0) {
			// Rebinding the temp fd to the original destination also closes
			// the temp file, freeing it for deletion.
			_dup2(_savedFd, _fileno(stdout));
			_close(_savedFd);
			_savedFd = -1;
		} else {
			// No original stdout: release the temp file by pointing stdout at
			// the null device so it can be deleted.
			std::freopen("NUL", "w", stdout);
		}

		_active = false;
	}

	int  _savedFd{-1};
	bool _active{false};
	char _path[MAX_PATH]{};
};

/*++

Routine Description:

	Resolve the binary rp++ should operate on. If -f was supplied we honour it,
	otherwise we fall back to the full image path of the current debuggee.

Arguments:

	pExt - Supplies the extension helper.

	file - Returns the resolved path on success.

Return Value:

	S_OK on success, otherwise an HRESULT error code.

--*/
static
HRESULT
ResolveTargetFile(Ext* pExt, std::string& file)
{
	if (!g_opts.file.empty()) {
		file.assign(g_opts.file);
		return S_OK;
	}

	auto handle = pExt->GetDebuggeeHandle();
	if (!handle) {
		pExt->Err() << "rp++: no -f binary given and no live debuggee to fall back on.";
		return handle.error();
	}

	char imageName[MAX_PATH]{};
	DWORD imageSize = sizeof(imageName);

	if (!::QueryFullProcessImageNameA((HANDLE)*handle, 0 /* Win32 path */, imageName, &imageSize)) {
		pExt->Err() << "rp++: QueryFullProcessImageNameA() failed (" << ::GetLastError() << ").";
		return E_FAIL;
	}

	file.assign(imageName);
	return S_OK;
}

/*++

Routine Description:

	Parse a --va value into an address. Accepts the WinDBG backtick form
	(e.g. 00007ff6`12340000): the backtick is stripped, and its presence forces
	base-16 parsing so an address copied straight off the debugger just works.

Arguments:

	va - Supplies the address string.

Return Value:

	The parsed address.

--*/
static
uint64_t
ParseVa(std::string va)
{
	const bool had_tick = va.find('`') != std::string::npos;
	va.erase(std::remove(va.begin(), va.end(), '`'), va.end());
	return std::strtoull(va.c_str(), nullptr, had_tick ? 16 : 0);
}

/*++

Routine Description:

	Call the rp++ core's only_unique_gadgets() regardless of which revision of
	the core this is built against. Current upstream rp++ filters bad bytes
	inside a 3-argument overload; older revisions take just the multiset. The
	right one is selected at compile time so the extension stays buildable
	against either core without touching it.

Arguments:

	all      - Supplies the full gadget multiset.

	badbytes - Supplies the bad-byte list (used by the 3-argument core only).

	filtered - Receives the filtered count (updated by the 3-argument core only).

Return Value:

	The set of unique gadgets.

--*/
template <class Multiset>
static
GadgetSet
UniqueGadgets(Multiset& all,
              const std::vector<uint8_t>& badbytes,
              uint64_t& filtered)
{
	// Multiset is a template parameter so the calls below are dependent
	// expressions; that is what lets the requires-clause select an overload
	// instead of hard-erroring on the one that doesn't exist in this core.
	if constexpr (requires { only_unique_gadgets(all, badbytes, filtered); }) {
		return only_unique_gadgets(all, badbytes, filtered);
	} else {
		(void)badbytes;
		(void)filtered;
		return only_unique_gadgets(all);
	}
}

/*++

Routine Description:

	Drive the rp++ core exactly like rp/main.cpp does. Everything this function
	prints through fmt::print is captured by the caller and forwarded to the
	debugger, so no rp++ core code needs to know about WinDBG.

Arguments:

	file - Supplies the binary to analyze.

Return Value:

	None. Failures are surfaced as printed exceptions, mirroring rp/main.cpp.

--*/
static
void
RunCore(const std::string& file)
{
	if (g_opts.version) {
		fmt::print("You are currently using the version {} of rp++.\n", VERSION);
	}

	Program p(file, g_opts.raw);

	// Absolute VAs are printed when --va is given (base of 0 otherwise the
	// image base).
	const uint64_t base = g_opts.va.size() > 0
	                          ? ParseVa(g_opts.va)
	                          : p.get_image_base_address();

	if (g_opts.rop > 0) {
		const uint32_t options = g_opts.thumb ? 1 : 0;
		fmt::print("\nWait a few seconds, rp++ is looking for gadgets ({} "
		           "threads max)..\n",
		           g_opts.maxth);

		GadgetMultiset all_gadgets =
			p.find_gadgets(g_opts.rop, options, g_opts.maxth, base);

		fmt::print("A total of {} gadgets found.\n", all_gadgets.size());

		// display_gadget_lf() reads these from the enclosing scope.
		std::vector<uint8_t> badbyte_list;
		if (g_opts.badbytes.size() > 0) {
			badbyte_list = string_to_hex(g_opts.badbytes);
		}

		uint64_t nb_gadgets_filtered = 0;
		if (g_opts.unique) {
			auto unique_gadgets =
				UniqueGadgets(all_gadgets, badbyte_list, nb_gadgets_filtered);

			fmt::print("You decided to keep only the unique ones, {} unique "
			           "gadgets found.\n",
			           unique_gadgets.size());

			for (const auto& unique_gadget : unique_gadgets) {
				display_gadget_lf(unique_gadget.get_first_absolute_address(),
				                  unique_gadget);
			}
		} else {
			for (const auto& gadget : all_gadgets) {
				display_gadget_lf(gadget.get_first_absolute_address(), gadget);
			}
		}

		if (g_opts.badbytes.size() > 0) {
			fmt::print(
				"\n{} gadgets have been filtered because of your bad-bytes.\n",
				nb_gadgets_filtered);
		}
	}

	if (g_opts.shexa.size() > 0) {
		const std::vector<uint8_t>& hex_values = string_to_hex(g_opts.shexa);
		p.search_and_display(hex_values.data(), hex_values.size(), base);
	}

	if (g_opts.sint.size() > 0) {
		const uint32_t val = std::strtoul(g_opts.sint.c_str(), nullptr, 16);
		p.search_and_display((const uint8_t*)&val, sizeof(val), base);
	}
}

/*++

Routine Description:

	Print the !rp usage, mirroring the standalone rp++ help. Printed through
	fmt::print so it is captured and shown in the debugger.

--*/
static
void
PrintHelp()
{
	// Passed as an argument (not as the format string) so the literal braces in
	// "--raw {0,1,2,3}" are printed verbatim and not parsed by fmt's compile
	// time format string checker.
	fmt::print("{}", R"(Usage: !rp [OPTIONS]
Options:
  -h, --help                  Print this help message and exit
  -f TEXT                     Binary path (defaults to the current debuggee)
  -r UINT                     Find gadgets; arg is the gadget max size in instructions
  --raw {0,1,2,3}             Treat the input as a raw file (x86=0, x64=1, arm=2, arm64=3)
  --unique                    Display only unique gadgets
  --search-hexa TEXT          Try to find hex values
  --max-thread UINT           Maximum number of threads to use
  --bad-bytes TEXT            Bytes you don't want to see in the gadgets' addresses
  --search-int TEXT           Try to find a pointer on a specific integer value
  -v, --version               Print version information
  --thumb                     Enable thumb mode when looking for ARM gadgets
  --va TEXT                   Use this base instead of the binary's image base
  --allow-branches            Allow branches in a gadget
  --print-bytes               Print the gadget bytes
)");
}

/*++

Routine Description:

	Emit captured text to the debugger in chunks, broken on line boundaries.
	IDebugControl::Output has a bounded internal buffer, so a single call with
	a multi-megabyte gadget dump would be truncated or dropped; chunking keeps
	every line visible.

Arguments:

	pExt - Supplies the extension helper.

	text - Supplies the captured output.

--*/
static
void
EmitCaptured(Ext* pExt, const std::string& text)
{
	constexpr size_t kChunk = 8000;
	const size_t n = text.size();
	size_t pos = 0;

	while (pos < n) {
		size_t end = (pos + kChunk < n) ? pos + kChunk : n;

		// Prefer to break at the last newline within the window so lines are
		// never split across two Output() calls.
		if (end < n) {
			const size_t nl = text.rfind('\n', end);
			if (nl != std::string::npos && nl >= pos) {
				end = nl + 1;
			}
		}

		std::string chunk = text.substr(pos, end - pos);

		// Out() appends its own trailing newline, so drop one here to avoid
		// doubling blank lines between chunks.
		if (!chunk.empty() && chunk.back() == '\n') {
			chunk.pop_back();
		}

		pExt->Out() << chunk;
		pos = end;
	}
}

/*++

Routine Description:

	!rp entry point. Parses the argument string, resolves the target binary and
	runs the rp++ core with stdout redirected into the debugger.

Arguments:

	pExt - Supplies the extension helper (see windbgext.hpp).

Return Value:

	S_OK on success, otherwise an HRESULT error code.

--*/
WDBG_CMD(rp)
{
	const bool wants_help = BuildOptions(pExt->GetRawArgs());

	std::string file;
	HRESULT result = ResolveTargetFile(pExt, file);
	if (FAILED(result)) {
		return result;
	}

	StdoutRedirector redirector;
	if (!redirector.Begin()) {
		pExt->Err() << "rp++: failed to capture output.";
		return E_FAIL;
	}

	fmt::print("rp++: a fast ROP gadget finder for pe/elf/mach-o "
	           "x86/x64/ARM/ARM64 binaries\n"
	           "by Axel '0vercl0k' Souchet.\n\n");

	if (wants_help) {
		PrintHelp();
	} else {
		try {
			RunCore(file);
		} catch (const std::exception& e) {
			fmt::print("\n{}\n", e.what());
		} catch (...) {
			fmt::print("\nrp++: an unexpected error occurred while running.\n");
		}
	}

	EmitCaptured(pExt, redirector.End());
	return S_OK;
}

WDBG_CMD_VERSION(EXT_MAJOR_VER, EXT_MINOR_VER)
