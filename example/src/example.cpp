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

#include "zydec.h"

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

////////////////////////////////////////////////////////////////////////////////

#ifdef _DEBUG
#define DBG_BREAK() __debugbreak()
#else
#define DBG_BREAK()
#endif

#define FATAL(x, ...) do { printf(x "\n", __VA_ARGS__); DBG_BREAK(); exit(-1); } while (0)
#define FATAL_IF(conditional, x, ...) do { if (conditional) { FATAL(x, __VA_ARGS__); } } while (0)

////////////////////////////////////////////////////////////////////////////////

static const char ArgumentNoContext[] = "--no-context";
static const char ArgumentLinearContext[] = "--linear";
static const char ArgumentLoopMode[] = "--loop";
static const char ArgumentNoSimplification[] = "--no-simplify";
static const char ArgumentIsaSet[] = "--isa";
static const char ArgumentAfterCallRegisterRetentionWindows[] = "--register-retention=windows";
static const char ArgumentAfterCallRegisterRetentionLinux[] = "--register-retention=linux";

static bool LinearMode = true;
static bool LoopMode = false;
static bool ShowIsaSet = false;

////////////////////////////////////////////////////////////////////////////////

int main(int argc, char **pArgv)
{
  if (argc == 1)
  {
    printf("Usage: example <RawAssembledBinaryFile>\n\t[%s / %s / %s]\n\t[%s]\n\t[%s]\n\t[%s / %s]\n", ArgumentNoContext, ArgumentLinearContext, ArgumentLoopMode, ArgumentNoSimplification, ArgumentIsaSet, ArgumentAfterCallRegisterRetentionWindows, ArgumentAfterCallRegisterRetentionLinux);
    return 0;
  }

  const char *filename = pArgv[1];

  ZydecFormattingInfo info;
  ZydecLinearContext linearContext;

  // Parse additional arguments.
  if (argc > 2)
  {
    size_t argIndex = 2;
    size_t argsRemaining = (size_t)argc - 2;

    while (argsRemaining)
    {
      if (argsRemaining >= 1 && strncmp(pArgv[argIndex], ArgumentNoContext, sizeof(ArgumentNoContext)) == 0)
      {
        argIndex++;
        argsRemaining--;
        LinearMode = false;
      }
      else if (argsRemaining >= 1 && strncmp(pArgv[argIndex], ArgumentLinearContext, sizeof(ArgumentLinearContext)) == 0)
      {
        argIndex++;
        argsRemaining--;
        LinearMode = true;
      }
      else if (argsRemaining >= 1 && strncmp(pArgv[argIndex], ArgumentLoopMode, sizeof(ArgumentLoopMode)) == 0)
      {
        argIndex++;
        argsRemaining--;
        LinearMode = true;
        LoopMode = true;
      }
      else if (argsRemaining >= 1 && strncmp(pArgv[argIndex], ArgumentIsaSet, sizeof(ArgumentIsaSet)) == 0)
      {
        argIndex++;
        argsRemaining--;
        ShowIsaSet = true;
      }
      else if (argsRemaining >= 1 && strncmp(pArgv[argIndex], ArgumentNoSimplification, sizeof(ArgumentNoSimplification)) == 0)
      {
        argIndex++;
        argsRemaining--;
        info.simplifyCommonShorthands = false;
        info.simplifyValueSelfModification = false;
      }
      else if (argsRemaining >= 1 && strncmp(pArgv[argIndex], ArgumentAfterCallRegisterRetentionWindows, sizeof(ArgumentAfterCallRegisterRetentionWindows)) == 0)
      {
        argIndex++;
        argsRemaining--;
        info.afterCallRegisterRetentionMode = ZydecFormattingInfo::AfterCallRegisterRetentionMode::Windows;
      }
      else if (argsRemaining >= 1 && strncmp(pArgv[argIndex], ArgumentAfterCallRegisterRetentionLinux, sizeof(ArgumentAfterCallRegisterRetentionLinux)) == 0)
      {
        argIndex++;
        argsRemaining--;
        info.afterCallRegisterRetentionMode = ZydecFormattingInfo::AfterCallRegisterRetentionMode::Linux;
      }
      else
      {
        printf("Invalid Parameter '%s'. Aborting.", pArgv[argIndex]);
        return 1;
      }
    }
  }

  FILE *pFile = fopen(filename, "rb");
  FATAL_IF(pFile == nullptr, "Failed to open file. Aborting.");

  fseek(pFile, 0, SEEK_END);
  const size_t fileSize = _ftelli64(pFile);
  FATAL_IF(fileSize == 0, "The specified file is empty. Aborting.");

  fseek(pFile, 0, SEEK_SET);

  uint8_t *pData = reinterpret_cast<uint8_t *>(malloc(fileSize));
  FATAL_IF(pData == nullptr, "Memory allocation failure. Aborting.");
  FATAL_IF(fileSize != fread(pData, 1, fileSize, pFile), "Failed to read file contents. Aborting.");

  ZydisDecoder decoder;
  ZydisFormatter formatter;

  FATAL_IF(!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)), "Failed to initialize disassembler.");
  FATAL_IF(!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)) || !ZYAN_SUCCESS(ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE)) || !ZYAN_SUCCESS(ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE)), "Failed to initialize instruction formatter.");

  ZydisDecodedInstruction instruction;
  ZydisDecodedOperand operands[10];

  size_t virtualAddress = 0;
  constexpr size_t addressDisplayOffset = 0x140000000;

  char disasmBuffer[1024] = "";
  char decompBuffer[1024] = "";

  if (LoopMode && LinearMode)
  {
    const uint64_t hashStateBefore = linearContext.hashState;
    size_t addr = 0;

    while (addr < fileSize)
    {
      if (!(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, pData + addr, fileSize - addr, &instruction, operands))))
      {
        puts("Failed to decode instruction in loop pre-run. Aborting pre-run.");
        break;
      }

      bool hasTranslation;

      zydec_TranslateInstructionWithLinearContext(&linearContext, &instruction, operands, sizeof(operands) / sizeof(operands[0]), addr + addressDisplayOffset, decompBuffer, sizeof(decompBuffer), &hasTranslation, &info);

      if (instruction.length == 0)
      {
        puts("Invalid instruction length in loop pre-run. Aborting pre-run.");
        break;
      }

      addr += instruction.length;
    }

    linearContext.hashState = hashStateBefore;
  }

  printf("// %s\n\n", filename);
  
  while (virtualAddress < fileSize)
  {
    FATAL_IF(!(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, pData + virtualAddress, fileSize - virtualAddress, &instruction, operands))), "Invalid Instruction at 0x%" PRIX64 ".", virtualAddress);
    FATAL_IF(!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&formatter, &instruction, operands, sizeof(operands) / sizeof(operands[0]), disasmBuffer, sizeof(disasmBuffer), virtualAddress + addressDisplayOffset, nullptr)), "Failed to Format Instruction at 0x%" PRIX64 ".", virtualAddress);

    bool hasTranslation = false;

    if (LinearMode)
    {
      if (!zydec_TranslateInstructionWithLinearContext(&linearContext, &instruction, operands, sizeof(operands) / sizeof(operands[0]), virtualAddress + addressDisplayOffset, decompBuffer, sizeof(decompBuffer), &hasTranslation, &info) || !hasTranslation)
        decompBuffer[0] = '\0';
    }
    else
    {
      if (!zydec_TranslateInstructionWithoutContext(&instruction, operands, sizeof(operands) / sizeof(operands[0]), virtualAddress + addressDisplayOffset, decompBuffer, sizeof(decompBuffer), &hasTranslation, &info) || !hasTranslation)
        decompBuffer[0] = '\0';
    }

    if (ShowIsaSet)
    {
      const char *isaSet = ZydisISASetGetString(instruction.meta.isa_set);

      printf("% 8" PRIX64 " | %-64s | %-12s | %s\n", virtualAddress + addressDisplayOffset, disasmBuffer, isaSet ? isaSet : "", decompBuffer);
    }
    else
    {
      printf("% 8" PRIX64 " | %-64s | %s\n", virtualAddress + addressDisplayOffset, disasmBuffer, decompBuffer);
    }

    FATAL_IF(instruction.length == 0, "Invalid instruction length. Aborting.");
    virtualAddress += instruction.length;
  }

  return 0;
}
