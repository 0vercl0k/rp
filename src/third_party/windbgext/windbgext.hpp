/*++

Copyright (c) Taha Draidia. All rights reserved.

Module Name:

	windbgext.hpp

Abstract:

	Header-only C++23 wrapper over DbgEng API. Makes writing WinDBG extensions more fun.

Environment:

	User mode, Windows.

Author:

	Taha Draidia (@tahadraidia)

Copyright:

	Use of this source code is governed by a MIT-style license that
	can be found in the LICENSE file.

--*/

#ifndef _WINDBGEXT_H
#define _WINDBGEXT_H

#define WINDBGEXT_VERSION_MAJOR  0
#define WINDBGEXT_VERSION_MINOR  1
#define WINDBGEXT_VERSION_PATCH  0

#define WINDBGEXT_STRINGIFY_(x) #x
#define WINDBGEXT_STRINGIFY(x)  WINDBGEXT_STRINGIFY_(x)

#define WINDBGEXT_VERSION_STRING \
    WINDBGEXT_STRINGIFY(WINDBGEXT_VERSION_MAJOR) "." \
    WINDBGEXT_STRINGIFY(WINDBGEXT_VERSION_MINOR) "." \
    WINDBGEXT_STRINGIFY(WINDBGEXT_VERSION_PATCH)

#include <Windows.h>
#include <Dbgeng.h>

#include <cstring>
#include <sstream>
#include <string>
#include <expected>

/*++

Abstract:

	SessionInfo global will hold the debugging session metadata
	including session Type (User,Kernel) and Detailed type (DEBUG_CLASS_USER_WINDOWS, DEBUG_KERNEL_CONNECTION, ...).

--*/
struct SessionInfo {
	ULONG Class;
	ULONG Type;
};


inline SessionInfo g_SessionInfo{};

#define CODE_GUARD() 						\
	if (g_SessionInfo.Class == DEBUG_CLASS_UNINITIALIZED || \
		g_SessionInfo.Class == DEBUG_CLASS_KERNEL) {	\
			return std::unexpected(E_FAIL);		\
	}

#define POINTER_GUARD(p)				\
	if (!p) {					\
		return std::unexpected(E_POINTER);	\
	}

#define SESSION_GUARD()                                         \
        if (g_SessionInfo.Class == DEBUG_CLASS_UNINITIALIZED) { \
                return std::unexpected(E_FAIL);                 \
        }

template<class T>
using ExtResult = std::expected<T, HRESULT>;

template<class T>
HRESULT TypedQueryInterface(
	IUnknown*	src,
	T**		dst
	)	  
/*++

Routine Description:

	Template wrapper around QueryInterface(). 

Arguments:

	src - Supplies a pointer to the COM interface object. 

	dst - Returns a pointer to a pointer of the selected COM interface object. 

Return Value:
	
	S_OK on success, otherwise an HRESULT error code.

--*/
{
	if (!src || !dst)
		return E_POINTER;
	
	return src->QueryInterface(
		__uuidof(T),
	    	reinterpret_cast<void **>(dst)
	);
}

class WindbgExtStream {
public:
	explicit
	WindbgExtStream(IDebugControl* pControl, ULONG mask) noexcept
		: _pControl(pControl), _mask(mask){}

	WindbgExtStream() = default;

	WindbgExtStream(const WindbgExtStream&) = delete;
	WindbgExtStream& operator=(const WindbgExtStream&) = delete;

	template<typename T>
	WindbgExtStream& operator<<(T&& value)
	{
		_stream << std::forward<T>(value);
		return *this;
	}

	~WindbgExtStream() noexcept
	{
		try {
			auto text = _stream.str();
			if (_pControl != nullptr) {
				_pControl->Output(
					_mask,
					"%s\n",
					text.c_str()
				);
			} else {
				::OutputDebugStringA(text.c_str());
			}

		} catch(const std::exception& e) {
			auto msg = std::string("WindbgExtStream dcor failed: ") + e.what();
			::OutputDebugStringA(msg.c_str());
		}
	}

private:
	IDebugControl*  _pControl{};
	ULONG _mask{}; 
	std::ostringstream _stream{};
};

using ExtOutput = WindbgExtStream;

struct WindbgExtContext {
	IDebugClient*	client;
	PCSTR		args;
};

using ExtCTX = WindbgExtContext;

class WindbgExt {
public:

	PCSTR
	GetRawArgs() const noexcept
	{
		return _ctx.args ? _ctx.args : "";
	}

	size_t
	GetRawArgsLength() const noexcept
	{
		return _ctx.args ? std::strlen(_ctx.args) : 0;
	}

	WindbgExt(const WindbgExt&) = delete;
	WindbgExt& operator=(const WindbgExt&) = delete;
	WindbgExt(WindbgExt&&) = delete;
	WindbgExt& operator=(WindbgExt&&) = delete;

	ExtOutput Out() { return ExtOutput(control, DEBUG_OUTPUT_NORMAL); }
	ExtOutput Err() { return ExtOutput(control, DEBUG_OUTPUT_ERROR); }
	ExtOutput Warn() { return ExtOutput(control, DEBUG_OUTPUT_WARNING); }

	ExtResult<ULONG64>
	GetDebuggeeHandle() const
	{
		CODE_GUARD();

		ULONG64 handle;
		HRESULT result;

		POINTER_GUARD(systemObject);	

		result = systemObject->GetCurrentProcessHandle(&handle);
		if (FAILED(result))
			return std::unexpected(result);

		return handle;
	}

	ExtResult<ULONG>
	GetDebuggeePID() const
	{
		CODE_GUARD();

		ULONG pid;
		HRESULT result;

		POINTER_GUARD(systemObject);	

		result = systemObject->GetCurrentProcessSystemId(&pid);
		if (FAILED(result))
			return std::unexpected(result);

		return pid;
	}


	ExtResult<ULONG64>
	EvaluateU64(PCSTR expression)
	{
		SESSION_GUARD();

		DEBUG_VALUE value{};
		HRESULT result;

		POINTER_GUARD(control);	

		result = control->Evaluate(
			expression,
			DEBUG_VALUE_INT64,
			&value,
			nullptr
			);

		if (FAILED(result))
			return std::unexpected(result);

		return value.I64;
	}

	ExtResult<ULONG32>
	EvaluateU32(PCSTR expression)
	{
		SESSION_GUARD();

		DEBUG_VALUE value{};
		HRESULT result;

		POINTER_GUARD(control);	

		result = control->Evaluate(
			expression,
			DEBUG_VALUE_INT32,
			&value,
			nullptr
			);

		if (FAILED(result))
			return std::unexpected(result);

		return value.I32;
	}


	explicit
	WindbgExt(ExtCTX ctx) noexcept : _ctx(ctx) 
	{
		HRESULT result{};

		client = _ctx.client;

		result = TypedQueryInterface(_ctx.client, &control);

		if (SUCCEEDED(result)) {
			control->GetDebuggeeType(
				_pSessionClass,
				_pSessionType
				);
		}

		TypedQueryInterface(_ctx.client, &systemObject);
		TypedQueryInterface(_ctx.client, &registers);
		TypedQueryInterface(_ctx.client, &symbols);
		TypedQueryInterface(_ctx.client, &memory);

	}


	~WindbgExt()
	{
		if (systemObject)
			systemObject->Release();

		if (control)
			control->Release();

		if (registers)
			registers->Release();

		if (symbols)
			symbols->Release();

		if (memory)
			memory->Release();
	}

	
	IDebugSystemObjects*
	System()
	const noexcept
	{
		return systemObject;
	}

	IDebugControl*
	Control()
	const noexcept
	{
		return control;
	}

	IDebugDataSpaces*
	Memory()
	const noexcept
	{
		return memory;
	}

	IDebugSymbols*
	Symbols()
	const noexcept
	{
		return symbols;
	}

	IDebugRegisters*
	Registers()
	const noexcept
	{
		return registers;
	}

	IDebugClient*
	Client()
	const noexcept
	{
		return client;
	}

private:
	IDebugSystemObjects* systemObject{};
	IDebugControl* control{};
	IDebugDataSpaces* memory{};
	IDebugSymbols* symbols{};
	IDebugRegisters* registers{};
	IDebugClient* client{};

	ExtCTX _ctx{};
	PULONG _pSessionClass{&g_SessionInfo.Class};
	PULONG _pSessionType{&g_SessionInfo.Type};
};

using Ext = WindbgExt;

#define WindbgExport extern "C" __declspec(dllexport)
#define WindbgExtSignature WindbgExport HRESULT CALLBACK

/*++

Macro Description:

	Helper to create WindbgEXT, the user only needs to provide a name the extension.
	
	The core logic needs to be implemented by the user obviously, where the return value is an HRESULT.

	The user is provided with a raw pointer to a WindbgExt object named "pExt".	

Arguments:

	name - Extension name, special characters are not allowed except for "_".

Return Value:
	
	The user need to return an HRESULT, S_OK for success.

--*/
#define WDBG_CMD(name)                                  		\
	WindbgExtSignature name##_impl(Ext*);				\
	WindbgExtSignature name##(IDebugClient* pClient, PCSTR args)	\
	{								\
		ExtCTX ctx = ExtCTX{pClient, args};			\
		Ext ext = Ext(ctx);					\
		return name##_impl(&ext);				\
	}								\
	WindbgExtSignature name##_impl(Ext* pExt)			\

/*++

Macro Description:

	Optional helper around DebugExtensionInitialize() used to set extension version.


Arguments:

	major - ULONG value for major
	minor - ULONG value for minor

Return Value:

	Always returns S_OK.
	

--*/
#define WDBG_CMD_VERSION(major, minor)                  		\
	WindbgExtSignature						\
	DebugExtensionInitialize(PULONG Version, PULONG Flags)  	\
	{                                                      		\
		*Version = DEBUG_EXTENSION_VERSION(major, minor);	\
		*Flags = 0;                                         	\
		return S_OK;                                        	\
	}                                                       	\

/*++

Macro Description:

	This macro is optional, it serves a a way to clean up global state if any defined by consumer.

	This gets called before the extension gets unloaded.

--*/
#define WDBG_CMD_CLEANUP()                  				\
	WindbgExport							\
	void DebugExtensionUninitialize(void)				\

#endif
