#include <idc.idc>

// modified for acclient stuffs


/* makesig.idc: IDA script to automatically create and wildcard a function signature.
 * Copyright 2014, Asher Baker
 *
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *
 * 2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *
 * 3. This notice may not be removed or altered from any source distribution.
 */

static main()
{
	Wait(); // We won't work until autoanalysis is complete

	SetStatus(IDA_STATUS_WORK);
  auto maxSigs = 200;
	auto pAddress = get_next_func(0);

  auto madeSigs, noSigs;

  while (maxSigs > 0 && pAddress != BADADDR) {
   if (pAddress >= 0x004171E0) { // just to set us into the middle of functions a bit...
    auto res = MakeSig(pAddress);
    if (res > 0) {
     madeSigs = madeSigs + 1;
    }
    else {
     noSigs = noSigs + 1;
    }
    maxSigs = maxSigs - 1;
   }
   pAddress = get_next_func(pAddress);
  }

   msg("Found sigs %d // No sigs: %d\n", madeSigs, noSigs);

	SetStatus(IDA_STATUS_READY);
	return;
}

static MakeSig(startAddress)
{
	auto pAddress = GetFunctionAttr(startAddress, FUNCATTR_START);
	if (pAddress == BADADDR) {
		Warning("Make sure you are in a function!");
		return 0;
	}

	auto name = get_name(pAddress, GN_DEMANGLED);
	auto sig = "", found = 0;
	auto pFunctionEnd = GetFunctionAttr(pAddress, FUNCATTR_END) + 6;

	Message("Signature for %s:\n", name);
	while (pAddress != BADADDR) {
		auto pInfo = DecodeInstruction(pAddress);
		if (!pInfo) {
			msg("\tSomething went terribly wrong D:\n");
			return 0;
		}

		// isCode(GetFlags(pAddress)) == Opcode
		// isTail(GetFlags(pAddress)) == Operand
		// ((GetFlags(pAddress) & MS_CODE) == FF_IMMD) == :iiam:

		auto bDone = 0;

		if (pInfo.n == 1) {
			if (pInfo.Op0.type == o_near || pInfo.Op0.type == o_far) {
				if (Byte(pAddress) == 0x0F) { // Two-byte instruction
					sig = sig + sprintf("0F %02X ", Byte(pAddress + 1)) + PrintWildcards(GetDTSize(pInfo.Op0.dtype));
				} else {
					sig = sig + sprintf("%02X ", Byte(pAddress)) + PrintWildcards(GetDTSize(pInfo.Op0.dtype));
				}
				bDone = 1;
			}
		}

		if (!bDone) { // unknown, just wildcard addresses
			auto i = 0, itemSize = ItemSize(pAddress);
			for (i = 0; i < itemSize; i++) {
				auto pLoc = pAddress + i;
				if ((GetFixupTgtType(pLoc) & FIXUP_MASK) == FIXUP_OFF32) {
					sig = sig + PrintWildcards(4);
					i = i + 3;
				} else {
					sig = sig + sprintf("%02X ", Byte(pLoc));
				}
			}
		}

		if (IsGoodSig(sig)) {
			found = 1;
			break;
		}

		pAddress = NextHead(pAddress, pFunctionEnd);
	}

	if (found == 0) {
		//msg("%s\n\tRan out of bytes to create unique signature.\n", name);
		return MakeSigFromXRefs(startAddress);
	}

	auto len = strlen(sig) - 1, smsig = "\\x";
	for (i = 0; i < len; i++) {
		auto c = substr(sig, i, i + 1);
		if (c == " ") {
			smsig = smsig + "\\x";
		} else if (c == "?") {
			smsig = smsig + "2A";
		} else {
			smsig = smsig + c;
		}
	}

	Message("\t%s\n", sig);
 return 1;
}

static MakeSigFromXRefs(pAddress)
{
	pAddress = GetFunctionAttr(pAddress, FUNCATTR_START);
	if (pAddress == BADADDR) {
		Warning("Make sure you are in a function!");
		return 0;
	}
 
	auto sig = "", found = 0;
  auto dAddress = get_first_dref_to(pAddress);

  while (dAddress != BADADDR) {
    // this isnt right... but it works to limit search area? do we even want to...?
    //if (dAddress > 0x00791DC6 || dAddress < 0x00401000) {
    // dAddress = get_next_dref_to(pAddress, dAddress);
    // continue;
    //}

    sig = "";
    auto cAddress = dAddress;
    auto pEnd = cAddress + 32;

    while (cAddress != BADADDR) {
      auto pInfo = DecodeInstruction(cAddress);
      if (!pInfo) {
        msg("\tSomething went terribly wrong D:");
        return 0;
      }

      auto bDone = 0;

      if (pInfo.n == 1) {
        if (pInfo.Op0.type == o_near || pInfo.Op0.type == o_far) {
          if (Byte(cAddress) == 0x0F) { // Two-byte instruction
            sig = sig + sprintf("0F %02X ", Byte(cAddress + 1)) + PrintWildcards(GetDTSize(pInfo.Op0.dtype));
          } else {
            sig = sig + sprintf("%02X ", Byte(cAddress)) + PrintWildcards(GetDTSize(pInfo.Op0.dtype));
          }
          bDone = 1;
        }
      }

      if (!bDone) { // unknown, just wildcard addresses
        auto i = 0, itemSize = ItemSize(cAddress);
        for (i = 0; i < itemSize; i++) {
          auto pLoc = cAddress + i;
          if ((GetFixupTgtType(pLoc) & FIXUP_MASK) == FIXUP_OFF32) {
            sig = sig + PrintWildcards(4);
            i = i + 3;
          } else {
            sig = sig + sprintf("%02X ", Byte(pLoc));
          }
        }
      }

      if (IsGoodSig(sig)) {
        found = 1;
        break;
      }

      cAddress = NextHead(cAddress, pEnd);
    }

    if (found == 1) {
      break;
    }

    dAddress = get_next_dref_to(pAddress, dAddress);
  }

	if (found == 0) {
		msg("\tCould not find xref sig...\n");
		return 0;
	}

	Message("\txref: %s // %04X\n", sig, dAddress);

 return 0;
}

static GetDTSize(dtyp)
{
	if (dtyp == dt_byte) {
		return 1;
	} else if (dtyp == dt_word) {
		return 2;
	} else if (dtyp == dt_dword) {
		return 4;
	} else if (dtyp == dt_float) {
		return 4;
	} else if (dtyp == dt_double) {
		return 8;
	} else {
		Warning("Unknown type size (%d)", dtyp);
		return -1;
	}
}

static PrintWildcards(count)
{
	auto i = 0, string = "";
	for (i = 0; i < count; i++) {
		string = string + "?? ";
	}

	return string;
}

static IsGoodSig(sig)
{

	auto count = 0, addr;
	addr = FindBinary(addr, SEARCH_DOWN|SEARCH_NEXT, sig);
	while (count <= 2 && addr != BADADDR) {
		count = count + 1;
		addr = FindBinary(addr, SEARCH_DOWN|SEARCH_NEXT, sig);
	}

	//Message("%s(%d)\n", sig, count);

	return (count == 1);
}