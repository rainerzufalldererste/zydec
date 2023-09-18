////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2023, Christoph Stiller. All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without 
// modification, are permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation 
//    and/or other materials provided with the distribution.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
////////////////////////////////////////////////////////////////////////////////

#ifndef zydec_h__
#define zydec_h__

#include <stdint.h>

#ifndef ZYDIS_H
extern "C"
{
#define ZYDIS_STATIC_BUILD
#include "Zydis.h"
}
#endif

////////////////////////////////////////////////////////////////////////////////

struct ZydecFormattingInfo
{
  // Returns `true` on success.
  typedef bool ResolveAddressToFriendlyName(const size_t virtualAddress, char *friendlyName, const size_t friendlyNameCapacity, size_t *pOffsetFromStart, void *pUserData);

  ResolveAddressToFriendlyName *pResolveAddressToFriendlyName = nullptr;
  void *pUserData = nullptr;

  typedef bool RegisterAppendStringFunc(char **pBufferPos, size_t *pRemainingSize, const ZydisRegister reg, void *pUserData);

  RegisterAppendStringFunc *pWriteRegister = nullptr;
  RegisterAppendStringFunc *pWriteResultRegister = nullptr;
  void *pRegUserData = nullptr;

  typedef void AfterCallFunc(void *pUserData);

  AfterCallFunc *pAfterCall = nullptr;
  void *pCallUserData = nullptr;

  bool simplifyCommonShorthands = true;
  bool simplifyValueSelfModification = true;
};

////////////////////////////////////////////////////////////////////////////////

// Currently requires all 10 operands.
bool zydec_TranslateInstructionWithoutContext(const ZydisDecodedInstruction *pInstruction, const ZydisDecodedOperand *pOperands, const size_t operandCount, const size_t virtualAddress, char *buffer, const size_t bufferCapacity, bool *pHasTranslation, ZydecFormattingInfo *pInfo);

////////////////////////////////////////////////////////////////////////////////

struct ZydecLinearContext
{
  uint32_t regInfo[ZYDIS_REGISTER_MAX_VALUE] = {};
};

// Currently requires all 10 operands.
bool zydec_TranslateInstructionWithLinearContext(ZydecLinearContext *pContext, const ZydisDecodedInstruction *pInstruction, const ZydisDecodedOperand *pOperands, const size_t operandCount, const size_t virtualAddress, char *buffer, const size_t bufferCapacity, bool *pHasTranslation, ZydecFormattingInfo *pInfo);

#endif // zydec_h__
