#include "Cafe/OS/common/OSCommon.h"
#include "nlibnss.h"

#include <atomic>
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <sys/random.h>
#endif

namespace nlibnss
{
	static std::atomic<bool> s_initialized{false};
	static constexpr sint32 NSS_NOT_INITIALIZED = static_cast<sint32>(0xFFD1FFFBu);
	static constexpr sint32 NSS_INVALID_ARG = static_cast<sint32>(0xFFD1FFF7u);

	sint32 NSSInit()
	{
		s_initialized = true;
		return 0;
	}

	sint32 NSSFinish()
	{
		s_initialized = false;
		return 0;
	}

	sint32 NSSLibReady()
	{
		// A synthetic service handle; guests only use it to check initialization.
		return s_initialized ? 1 : -1;
	}

	sint32 NSSGetRandom(uint8* buffer, sint32 size)
	{
		if (!s_initialized)
			return NSS_NOT_INITIALIZED;
		if (!buffer || size < 0)
			return NSS_INVALID_ARG;
		for (sint32 offset = 0; offset < size;)
		{
			const sint32 count = std::min<sint32>(size - offset, 256);
#ifdef _WIN32
			if (BCryptGenRandom(nullptr, buffer + offset, count, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
				return -1;
#else
			if (::getentropy(buffer + offset, static_cast<size_t>(count)) != 0)
				return -1;
#endif
			offset += count;
		}
		return 0;
	}

	int NSSExportDeviceCertChain(uint8* uknPtr1, uint32be* uknLength1, uint8* uknPtr2, uint32be* uknLength2, uint32 uknR7, uint32 uknR8)
	{
		cemuLog_logDebug(LogType::Force, "NSSExportDeviceCertChain called but not implemented");
		cemu_assert_debug(false);

		// uknR3 = pointer (can be null, in which case only length is written)
		// uknR4 = length
		// uknR5 = pointer2
		// uknR6 = length2
		// uknR7 = some integer
		// uknR8 = ???

		*uknLength1 = 0x100;
		*uknLength2 = 0x100;


		return 0; // failed
	}

	int NSSSignatureGetSignatureLength()
	{
		// parameters are unknown
		cemu_assert_debug(false);
		return 0x1C; // signature length
	}

	class : public COSModule
	{
		public:
		std::string_view GetName() override
		{
			return "nlibnss";
		}

		void RPLMapped() override
		{
			s_initialized = false;
			cafeExportRegister("nlibnss", NSSInit, LogType::Placeholder);
			cafeExportRegister("nlibnss", NSSFinish, LogType::Placeholder);
			cafeExportRegister("nlibnss", NSSLibReady, LogType::Placeholder);
			cafeExportRegister("nlibnss", NSSGetRandom, LogType::Placeholder);
			cafeExportRegister("nlibnss", NSSSignatureGetSignatureLength, LogType::Placeholder);
			cafeExportRegister("nlibnss", NSSExportDeviceCertChain, LogType::Placeholder);
		};

	}s_COSnlibnssModule;

	COSModule* GetModule()
	{
		return &s_COSnlibnssModule;
	}
}
