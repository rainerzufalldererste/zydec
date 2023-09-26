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

#include <string.h>

////////////////////////////////////////////////////////////////////////////////

enum ZydecOperandFlags_ : size_t
{
  zof_none = 0,
  zof_noAddressDeref = 1 << 0,
};

typedef size_t ZydecOperandFlags;

////////////////////////////////////////////////////////////////////////////////

bool zydec_WriteRaw(char **pBufferPos, size_t *pRemainingSize, const char *text);
bool zydec_WriteOperand(char **pBufferPos, size_t *pRemainingSize, const ZydisDecodedOperand *pOperand, const size_t virtualAddress, ZydecFormattingInfo *pInfo, const ZydecOperandFlags flags = zof_none, const bool isNewResult = false);
bool zydec_WriteResultOperand(char **pBufferPos, size_t *pRemainingSize, const ZydisDecodedOperand *pOperand, const size_t virtualAddress, ZydecFormattingInfo *pInfo, const ZydecOperandFlags flags = zof_none);
bool zydec_WriteRegister(char **pBufferPos, size_t *pRemainingSize, const ZydisRegister reg, ZydecFormattingInfo *pInfo, const bool isNewResult);
bool zydec_WriteRegisterRaw(char **pBufferPos, size_t *pRemainingSize, const ZydisRegister reg);
bool zydec_WriteHex(char **pBufferPos, size_t *pRemainingSize, const uint64_t value);
bool zydec_WriteUInt(char **pBufferPos, size_t *pRemainingSize, const uint64_t value);
bool zydec_WriteInt(char **pBufferPos, size_t *pRemainingSize, const int64_t value);

////////////////////////////////////////////////////////////////////////////////

#define ERROR_CHECK(a) do { if (!(a)) return false; } while (false)

////////////////////////////////////////////////////////////////////////////////

bool zydec_TranslateInstructionWithoutContext(const ZydisDecodedInstruction *pInstruction, const ZydisDecodedOperand *pOperands, const size_t operandCount, const size_t virtualAddress, char *buffer, const size_t bufferCapacity, bool *pHasTranslation, ZydecFormattingInfo *pInfo)
{
  if (pInstruction == nullptr || pOperands == nullptr || operandCount < 10 || buffer == nullptr || bufferCapacity == 0 || pHasTranslation == nullptr)
    return false;

  char *bufferPos = buffer;
  size_t remainingSize = bufferCapacity - 1;

  *pHasTranslation = true;
  bufferPos[0] = '\0';

  const bool simplifyShorthands = pInfo == nullptr || pInfo->simplifyCommonShorthands;
  const bool simplifySelfModification = pInfo == nullptr || pInfo->simplifyValueSelfModification;

  switch (pInstruction->mnemonic)
  {
  case ZYDIS_MNEMONIC_MOV:
  case ZYDIS_MNEMONIC_MOVBE:
  case ZYDIS_MNEMONIC_MOVDIR64B:
  case ZYDIS_MNEMONIC_MOVDIRI:
  case ZYDIS_MNEMONIC_MOVLPD:
  case ZYDIS_MNEMONIC_MOVLPS:
  case ZYDIS_MNEMONIC_MOVNTI:
  case ZYDIS_MNEMONIC_MOVNTQ:
  case ZYDIS_MNEMONIC_MOVNTSD:
  case ZYDIS_MNEMONIC_MOVNTSS:
  case ZYDIS_MNEMONIC_MOVQ2DQ:
  case ZYDIS_MNEMONIC_MOVSX:
  case ZYDIS_MNEMONIC_MOVSXD:
  case ZYDIS_MNEMONIC_MOVZX:
  case ZYDIS_MNEMONIC_CBW:
  case ZYDIS_MNEMONIC_CDQ:
  case ZYDIS_MNEMONIC_CDQE:
  case ZYDIS_MNEMONIC_CQO:
  case ZYDIS_MNEMONIC_KMOVB:
  case ZYDIS_MNEMONIC_KMOVD:
  case ZYDIS_MNEMONIC_KMOVQ:
  case ZYDIS_MNEMONIC_KMOVW:
  {
    ERROR_CHECK(zydec_WriteResultOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));
    
    switch (pInstruction->mnemonic)
    {
    case ZYDIS_MNEMONIC_MOVBE:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "__byteswap("));
      break;

    case ZYDIS_MNEMONIC_MOVDIR64B:
    case ZYDIS_MNEMONIC_MOVDIRI:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "__atomic_write("));
      break;

    default:
      break;
    }

    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[1], virtualAddress, pInfo));

    switch (pInstruction->mnemonic)
    {
    case ZYDIS_MNEMONIC_MOVBE:
    case ZYDIS_MNEMONIC_MOVDIR64B:
    case ZYDIS_MNEMONIC_MOVDIRI:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ")"));
      break;

    case ZYDIS_MNEMONIC_MOVNTI:
    case ZYDIS_MNEMONIC_MOVNTQ:
    case ZYDIS_MNEMONIC_MOVNTSD:
    case ZYDIS_MNEMONIC_MOVNTSS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // move with non-temporal hint"));
      return true;

    case ZYDIS_MNEMONIC_MOVSX:
    case ZYDIS_MNEMONIC_MOVSXD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // move with sign extension"));
      return true;

    default:
      break;
    }
  
    break;
  }
  
  case ZYDIS_MNEMONIC_CMOVB:
  case ZYDIS_MNEMONIC_CMOVBE:
  case ZYDIS_MNEMONIC_CMOVL:
  case ZYDIS_MNEMONIC_CMOVLE:
  case ZYDIS_MNEMONIC_CMOVNB:
  case ZYDIS_MNEMONIC_CMOVNBE:
  case ZYDIS_MNEMONIC_CMOVNL:
  case ZYDIS_MNEMONIC_CMOVNLE:
  case ZYDIS_MNEMONIC_CMOVNO:
  case ZYDIS_MNEMONIC_CMOVNP:
  case ZYDIS_MNEMONIC_CMOVNS:
  case ZYDIS_MNEMONIC_CMOVNZ:
  case ZYDIS_MNEMONIC_CMOVO:
  case ZYDIS_MNEMONIC_CMOVP:
  case ZYDIS_MNEMONIC_CMOVS:
  case ZYDIS_MNEMONIC_CMOVZ:
  {
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if ("));

    switch (pInstruction->mnemonic)
    {
    case ZYDIS_MNEMONIC_CMOVB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "carry_flag"));
      break;

    case ZYDIS_MNEMONIC_CMOVBE:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "carry_flag || zero_flag"));
      break;

    case ZYDIS_MNEMONIC_CMOVL:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "sign_flag != overflow_flag"));
      break;

    case ZYDIS_MNEMONIC_CMOVLE:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "zero_flag || sign_flag != overflow_flag"));
      break;

    case ZYDIS_MNEMONIC_CMOVNB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "!carry_flag"));
      break;

    case ZYDIS_MNEMONIC_CMOVNBE:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "!carry_flag && !zero_flag"));
      break;

    case ZYDIS_MNEMONIC_CMOVNL:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "sign_flag == overflow_flag"));
      break;

    case ZYDIS_MNEMONIC_CMOVNLE:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "!zero_flag && sign_flag == overflow_flag"));
      break;

    case ZYDIS_MNEMONIC_CMOVNO:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "!overflow_flag"));
      break;

    case ZYDIS_MNEMONIC_CMOVNP:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "!parity_flag"));
      break;

    case ZYDIS_MNEMONIC_CMOVNS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "!sign_flag"));
      break;

    case ZYDIS_MNEMONIC_CMOVNZ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "!zero_flag"));
      break;

    case ZYDIS_MNEMONIC_CMOVO:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "overflow_flag"));
      break;

    case ZYDIS_MNEMONIC_CMOVP:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "parity_flag"));
      break;

    case ZYDIS_MNEMONIC_CMOVS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "sign_flag"));
      break;

    case ZYDIS_MNEMONIC_CMOVZ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "zero_flag"));
      break;

    default:
      break;
    }

    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ") "));
    ERROR_CHECK(zydec_WriteResultOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[1], virtualAddress, pInfo));

    switch (pInstruction->mnemonic)
    {
    case ZYDIS_MNEMONIC_CMOVB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if below"));
      break;

    case ZYDIS_MNEMONIC_CMOVBE:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if below or equal"));
      break;

    case ZYDIS_MNEMONIC_CMOVL:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if less"));
      break;

    case ZYDIS_MNEMONIC_CMOVLE:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if less or equal"));
      break;

    case ZYDIS_MNEMONIC_CMOVNB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if not below"));
      break;

    case ZYDIS_MNEMONIC_CMOVNBE:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if not below or equal"));
      break;

    case ZYDIS_MNEMONIC_CMOVNL:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if not less"));
      break;

    case ZYDIS_MNEMONIC_CMOVNLE:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if not less or equal"));
      break;

    case ZYDIS_MNEMONIC_CMOVNZ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if not zero / not equal"));
      break;

    case ZYDIS_MNEMONIC_CMOVZ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if zero / equal"));
      break;

    default:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ";"));
      break;
    }

    return true;
  }

  case ZYDIS_MNEMONIC_LEA:
    ERROR_CHECK(zydec_WriteResultOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = &"));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[1], virtualAddress, pInfo));
    break;

  case ZYDIS_MNEMONIC_TEST:
  case ZYDIS_MNEMONIC_CMP:
  {
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "compare("));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ", "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[1], virtualAddress, pInfo));

    if (pInstruction->mnemonic == ZYDIS_MNEMONIC_TEST)
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ") // set flags: carry, parity, zero"));
    else if (pInstruction->mnemonic == ZYDIS_MNEMONIC_CMP)
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ") // set flags: carry, overflow, signed, zero, aux_carry and parity"));
    else
      return false;

    return true;
  }

  case ZYDIS_MNEMONIC_CALL:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "("));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ")()"));

    if (pInfo != nullptr && pInfo->pAfterCall != nullptr)
      pInfo->pAfterCall(pInfo->pCallUserData);

    break;

  case ZYDIS_MNEMONIC_JMP:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    break;

  case ZYDIS_MNEMONIC_JB:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (carry_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if below"));
    return true;

  case ZYDIS_MNEMONIC_JBE:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (carry_flag || zero_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if below or equal"));
    return true;

  case ZYDIS_MNEMONIC_JCXZ:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if ((u16)c == 0) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    break;

  case ZYDIS_MNEMONIC_JECXZ:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if ((u32)c == 0) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    break;

  case ZYDIS_MNEMONIC_JL:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (sign_flag != overflow_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if less"));
    return true;

  case ZYDIS_MNEMONIC_JLE:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (zero_flag || sign_flag != overflow_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if less or equal"));
    return true;

  case ZYDIS_MNEMONIC_JNB:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (!carry_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if not below"));
    return true;

  case ZYDIS_MNEMONIC_JNBE:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (!carry_flag && !zero_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if not below or equal"));
    return true;

  case ZYDIS_MNEMONIC_JNL:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (sign_flag && overflow_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if not less"));
    return true;

  case ZYDIS_MNEMONIC_JNLE:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (!zero_flag && sign_flag == overflow_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if not less or equal"));
    return true;

  case ZYDIS_MNEMONIC_JNO:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (!overflow_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    break;

  case ZYDIS_MNEMONIC_JNP:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (!parity_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    break;

  case ZYDIS_MNEMONIC_JNS:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (!sign_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    break;

  case ZYDIS_MNEMONIC_JNZ:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (!zero_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if not zero / not equal"));
    return true;

  case ZYDIS_MNEMONIC_JO:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (overflow_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    break;

  case ZYDIS_MNEMONIC_JP:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (parity_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    break;

  case ZYDIS_MNEMONIC_JS:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (sign_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    break;

  case ZYDIS_MNEMONIC_JZ:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (zero_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if zero / equal"));
    return true;

  case ZYDIS_MNEMONIC_NOP:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "// nop"));
    return true;

  case ZYDIS_MNEMONIC_ADD:
  case ZYDIS_MNEMONIC_ADC:
  case ZYDIS_MNEMONIC_ADCX:
  case ZYDIS_MNEMONIC_ADOX:
  case ZYDIS_MNEMONIC_FADD:
  case ZYDIS_MNEMONIC_FADDP:
  case ZYDIS_MNEMONIC_SUB:
  case ZYDIS_MNEMONIC_AND:
  case ZYDIS_MNEMONIC_OR:
  case ZYDIS_MNEMONIC_XOR:
  case ZYDIS_MNEMONIC_ANDN:
  case ZYDIS_MNEMONIC_INC:
  case ZYDIS_MNEMONIC_DEC:
  case ZYDIS_MNEMONIC_FISUB:
  case ZYDIS_MNEMONIC_SHL:
  case ZYDIS_MNEMONIC_SHLX:
  case ZYDIS_MNEMONIC_SHLD:
  case ZYDIS_MNEMONIC_SHR:
  case ZYDIS_MNEMONIC_SHRX:
  case ZYDIS_MNEMONIC_SHRD:
  case ZYDIS_MNEMONIC_SALC:
  case ZYDIS_MNEMONIC_SAR:
  case ZYDIS_MNEMONIC_SARX:
  {
    if (simplifyShorthands)
    {
      if (pInstruction->operand_count == 3 /* yes, 3! who knows why. */ && pOperands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && pOperands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && pOperands[0].reg.value == pOperands[1].reg.value)
      {
        bool match = false;

        switch (pInstruction->mnemonic)
        {
        case ZYDIS_MNEMONIC_AND:
        case ZYDIS_MNEMONIC_OR:
          match = true;
          ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "// nop"));
          break;

        case ZYDIS_MNEMONIC_XOR:
          ERROR_CHECK(zydec_WriteResultOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
          ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = 0"));
          match = true;
          break;

        default:
          break;
        }

        if (match)
          return true;
      }
    }

    ERROR_CHECK(zydec_WriteResultOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));

    if (simplifySelfModification)
    {
      switch (pInstruction->mnemonic)
      {
      case ZYDIS_MNEMONIC_ADD:
      case ZYDIS_MNEMONIC_ADC:
      case ZYDIS_MNEMONIC_ADCX:
      case ZYDIS_MNEMONIC_ADOX:
      case ZYDIS_MNEMONIC_FADD:
      case ZYDIS_MNEMONIC_FADDP:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " += "));
        break;

      case ZYDIS_MNEMONIC_SUB:
      case ZYDIS_MNEMONIC_FISUB:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " -= "));
        break;

      case ZYDIS_MNEMONIC_AND:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " &= "));
        break;

      case ZYDIS_MNEMONIC_ANDN:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " &= ~"));
        break;

      case ZYDIS_MNEMONIC_OR:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " |= "));
        break;

      case ZYDIS_MNEMONIC_XOR:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " ^= "));
        break;

      case ZYDIS_MNEMONIC_INC:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "++;"));
        return true;

      case ZYDIS_MNEMONIC_DEC:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "--;"));
        return true;

      case ZYDIS_MNEMONIC_SHL:
      case ZYDIS_MNEMONIC_SHLX:
      case ZYDIS_MNEMONIC_SHLD:
      case ZYDIS_MNEMONIC_SALC:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " <<= "));
        break;

      case ZYDIS_MNEMONIC_SHR:
      case ZYDIS_MNEMONIC_SHRX:
      case ZYDIS_MNEMONIC_SHRD:
      case ZYDIS_MNEMONIC_SAR:
      case ZYDIS_MNEMONIC_SARX:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " >>= "));
        break;

      default:
        break;
      }
    }
    else
    {
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));
      ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));

      switch (pInstruction->mnemonic)
      {
      case ZYDIS_MNEMONIC_ADD:
      case ZYDIS_MNEMONIC_ADC:
      case ZYDIS_MNEMONIC_ADCX:
      case ZYDIS_MNEMONIC_ADOX:
      case ZYDIS_MNEMONIC_FADD:
      case ZYDIS_MNEMONIC_FADDP:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " + "));
        break;

      case ZYDIS_MNEMONIC_SUB:
      case ZYDIS_MNEMONIC_FISUB:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " - "));
        break;

      case ZYDIS_MNEMONIC_AND:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " & "));
        break;

      case ZYDIS_MNEMONIC_ANDN:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " & ~"));
        break;

      case ZYDIS_MNEMONIC_OR:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " | "));
        break;

      case ZYDIS_MNEMONIC_XOR:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " ^ "));
        break;

      case ZYDIS_MNEMONIC_INC:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "+ 1;"));
        return true;

      case ZYDIS_MNEMONIC_DEC:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "- 1;"));
        return true;

      case ZYDIS_MNEMONIC_SHL:
      case ZYDIS_MNEMONIC_SHLX:
      case ZYDIS_MNEMONIC_SHLD:
      case ZYDIS_MNEMONIC_SALC:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " << "));
        break;

      case ZYDIS_MNEMONIC_SHR:
      case ZYDIS_MNEMONIC_SHRX:
      case ZYDIS_MNEMONIC_SHRD:
      case ZYDIS_MNEMONIC_SAR:
      case ZYDIS_MNEMONIC_SARX:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " >> "));
        break;

      default:
        break;
      }
    }

    if (pInstruction->operand_count > 1)
      ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[1], virtualAddress, pInfo));

    switch (pInstruction->mnemonic)
    {
    case ZYDIS_MNEMONIC_ADC:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " + carry_flag"));
      break;

    case ZYDIS_MNEMONIC_ADCX:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " + carry_flag; // unsigned integer add with carry_flag"));
      return true;

    case ZYDIS_MNEMONIC_ADOX:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " + overflow_flag; // unsigned integer add with overflow_flag"));
      return true;

    default:
      break;
    }

    break;
  }

  case ZYDIS_MNEMONIC_MUL:
  case ZYDIS_MNEMONIC_IMUL:
  {
    if (pInstruction->operand_count == 1)
    {
      if (pOperands[0].element_size < 16)
      {
        ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_AX, pInfo, true));
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));
        ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_AL, pInfo, false));
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " * "));
      }
      else if (pOperands[0].element_size < 32)
      {
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "["));
        ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_DX, pInfo, true));
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ", "));
        ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_AX, pInfo, true));
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "] = "));
        ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_AX, pInfo, false));
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " * "));
      }
      else if (pOperands[0].element_size < 64)
      {
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "["));
        ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_EDX, pInfo, true));
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ", "));
        ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_EAX, pInfo, true));
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "] = "));
        ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_EAX, pInfo, false));
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " * "));
      }
      else
      {
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "["));
        ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_RDX, pInfo, true));
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ", "));
        ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_RAX, pInfo, true));
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "] = "));
        ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_RAX, pInfo, false));
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " * "));
      }

      ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    }
    else if (pInstruction->operand_count == 2)
    {
      ERROR_CHECK(zydec_WriteResultOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
      
      if (simplifySelfModification)
      {
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " *= "));
      }
      else
      {
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));
        ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " * "));
      }

      ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[1], virtualAddress, pInfo));
    }
    else
    {
      ERROR_CHECK(zydec_WriteResultOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));
      ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[1], virtualAddress, pInfo));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " * "));
      ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[2], virtualAddress, pInfo));
    }

    switch (pInstruction->mnemonic)
    {
    case ZYDIS_MNEMONIC_DIV:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // unsigned integer multiply"));
    case ZYDIS_MNEMONIC_IDIV:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // signed integer multiply"));
    default:
      break;
    }

    return true;
  }

  case ZYDIS_MNEMONIC_DIV:
  case ZYDIS_MNEMONIC_IDIV:
  {
    if (pOperands[0].element_size < 16)
    {
      ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_AL, pInfo, true));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));
      ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_AX, pInfo, false));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " / "));
    }
    else if (pOperands[0].element_size < 32)
    {
      ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_AX, pInfo, true));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));
      ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_AX, pInfo, false));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " / "));
    }
    else if (pOperands[0].element_size < 64)
    {
      ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_EAX, pInfo, true));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));
      ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_EAX, pInfo, false));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " / "));
    }
    else
    {
      ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_RAX, pInfo, true));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));
      ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_RAX, pInfo, false));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " / "));
    }

    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));

    if (pOperands[0].element_size < 16)
    {
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; "));
      ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_AH, pInfo, true));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));
      ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_AX, pInfo, false));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " % "));
    }
    else if (pOperands[0].element_size < 32)
    {
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; "));
      ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_DX, pInfo, true));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));
      ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_AX, pInfo, false));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " % "));
    }
    else if (pOperands[0].element_size < 64)
    {
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; "));
      ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_EDX, pInfo, true));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));
      ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_EAX, pInfo, false));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " % "));
    }
    else
    {
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; "));
      ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_RDX, pInfo, true));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));
      ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, ZYDIS_REGISTER_RAX, pInfo, false));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " % "));
    }

    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));

    switch (pInstruction->mnemonic)
    {
    case ZYDIS_MNEMONIC_DIV:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // unsigned integer divide"));
    case ZYDIS_MNEMONIC_IDIV:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // signed integer divide"));
    default:
      break;
    }

    return true;
  }

  case ZYDIS_MNEMONIC_RET:
  {
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "return"));
    break;
  }

  case ZYDIS_MNEMONIC_INT3:
  {
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "__builtin_trap(); // __debugbreak();"));
    return true;
  }

  case ZYDIS_MNEMONIC_SETB:
  case ZYDIS_MNEMONIC_SETBE:
  case ZYDIS_MNEMONIC_SETL:
  case ZYDIS_MNEMONIC_SETLE:
  case ZYDIS_MNEMONIC_SETNB:
  case ZYDIS_MNEMONIC_SETNBE:
  case ZYDIS_MNEMONIC_SETNL:
  case ZYDIS_MNEMONIC_SETNLE:
  case ZYDIS_MNEMONIC_SETNO:
  case ZYDIS_MNEMONIC_SETNP:
  case ZYDIS_MNEMONIC_SETNS:
  case ZYDIS_MNEMONIC_SETNZ:
  case ZYDIS_MNEMONIC_SETO:
  case ZYDIS_MNEMONIC_SETP:
  case ZYDIS_MNEMONIC_SETS:
  case ZYDIS_MNEMONIC_SETZ:
  {
    ERROR_CHECK(zydec_WriteResultOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = ("));

    switch (pInstruction->mnemonic)
    {
    case ZYDIS_MNEMONIC_SETB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "carry_flag"));
      break;

    case ZYDIS_MNEMONIC_SETBE:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "(carry_flag || zero_flag)"));
      break;

    case ZYDIS_MNEMONIC_SETL:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "sign_flag != overflow_flag"));
      break;

    case ZYDIS_MNEMONIC_SETLE:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "(zero_flag || sign_flag != overflow_flag)"));
      break;

    case ZYDIS_MNEMONIC_SETNB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "!carry_flag"));
      break;

    case ZYDIS_MNEMONIC_SETNBE:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "(!carry_flag && !zero_flag)"));
      break;

    case ZYDIS_MNEMONIC_SETNL:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "sign_flag == overflow_flag"));
      break;

    case ZYDIS_MNEMONIC_SETNLE:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "(!zero_flag && sign_flag == overflow_flag)"));
      break;

    case ZYDIS_MNEMONIC_SETNO:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "!overflow_flag"));
      break;

    case ZYDIS_MNEMONIC_SETNP:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "!parity_flag"));
      break;

    case ZYDIS_MNEMONIC_SETNS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "!sign_flag"));
      break;

    case ZYDIS_MNEMONIC_SETNZ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "!zero_flag"));
      break;

    case ZYDIS_MNEMONIC_SETO:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "overflow_flag"));
      break;

    case ZYDIS_MNEMONIC_SETP:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "parity_flag"));
      break;

    case ZYDIS_MNEMONIC_SETS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "sign_flag"));
      break;

    case ZYDIS_MNEMONIC_SETZ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "zero_flag"));
      break;

    default:
      break;
    }

    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " ? 1 : 0);"));

    switch (pInstruction->mnemonic)
    {
    case ZYDIS_MNEMONIC_SETB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " // if below"));
      break;

    case ZYDIS_MNEMONIC_SETBE:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " // if below or equal"));
      break;

    case ZYDIS_MNEMONIC_SETL:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " // if less"));
      break;

    case ZYDIS_MNEMONIC_SETLE:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " // if less or equal"));
      break;

    case ZYDIS_MNEMONIC_SETNB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " // if not below"));
      break;

    case ZYDIS_MNEMONIC_SETNBE:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " // if not below or equal"));
      break;

    case ZYDIS_MNEMONIC_SETNL:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " // if not less"));
      break;

    case ZYDIS_MNEMONIC_SETNLE:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " // if not less or equal"));
      break;

    case ZYDIS_MNEMONIC_SETNZ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " // if not zero / not equal"));
      break;

    case ZYDIS_MNEMONIC_SETZ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " // if zero / equal"));
      break;

    default:
      break;
    }

    return true;
  }

  case ZYDIS_MNEMONIC_BSF:
  {
    ERROR_CHECK(zydec_WriteResultOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = __bitscan_forward("));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[1], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ")"));
    break;
  }

  case ZYDIS_MNEMONIC_BSR:
  {
    ERROR_CHECK(zydec_WriteResultOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = __bitscan_reverse("));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[1], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ")"));
    break;
  }

  case ZYDIS_MNEMONIC_POPCNT:
  {
    ERROR_CHECK(zydec_WriteResultOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = __popcnt("));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[1], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ")"));
    break;
  }

  case ZYDIS_MNEMONIC_PREFETCH:
  case ZYDIS_MNEMONIC_PREFETCHNTA:
  case ZYDIS_MNEMONIC_PREFETCHT0:
  case ZYDIS_MNEMONIC_PREFETCHT1:
  case ZYDIS_MNEMONIC_PREFETCHT2:
  case ZYDIS_MNEMONIC_PREFETCHW:
  case ZYDIS_MNEMONIC_PREFETCHWT1:
  {
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_prefetch("));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ")"));
    break;
  }

  case ZYDIS_MNEMONIC_KORTESTB:
  case ZYDIS_MNEMONIC_KORTESTW:
  case ZYDIS_MNEMONIC_KORTESTD:
  case ZYDIS_MNEMONIC_KORTESTQ:
  case ZYDIS_MNEMONIC_KTESTB:
  case ZYDIS_MNEMONIC_KTESTW:
  case ZYDIS_MNEMONIC_KTESTD:
  case ZYDIS_MNEMONIC_KTESTQ:
  {
    switch (pInstruction->mnemonic)
    {
    case ZYDIS_MNEMONIC_KORTESTB:
    case ZYDIS_MNEMONIC_KORTESTW:
    case ZYDIS_MNEMONIC_KORTESTD:
    case ZYDIS_MNEMONIC_KORTESTQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kortest"));
      break;

    case ZYDIS_MNEMONIC_KTESTB:
    case ZYDIS_MNEMONIC_KTESTW:
    case ZYDIS_MNEMONIC_KTESTD:
    case ZYDIS_MNEMONIC_KTESTQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_ktest"));
      break;

    default:
      break;
    }

    switch (pInstruction->mnemonic)
    {
    case ZYDIS_MNEMONIC_KORTESTB:
    case ZYDIS_MNEMONIC_KTESTB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_u8"));
      break;

    case ZYDIS_MNEMONIC_KORTESTW:
    case ZYDIS_MNEMONIC_KTESTW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_u16"));
      break;

    case ZYDIS_MNEMONIC_KORTESTD:
    case ZYDIS_MNEMONIC_KTESTD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_u32"));
      break;

    case ZYDIS_MNEMONIC_KORTESTQ:
    case ZYDIS_MNEMONIC_KTESTQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_u64"));
      break;

    default:
      break;
    }

    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "("));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ", "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[1], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "); // set zero_flag & carry_flag accordingly"));

    return true;
  }

  case ZYDIS_MNEMONIC_VGATHERPF0DPS:
  case ZYDIS_MNEMONIC_VGATHERPF1DPS:
  case ZYDIS_MNEMONIC_VGATHERPF0DPD:
  case ZYDIS_MNEMONIC_VGATHERPF1DPD:
  case ZYDIS_MNEMONIC_VGATHERPF0QPS:
  case ZYDIS_MNEMONIC_VGATHERPF1QPS:
  case ZYDIS_MNEMONIC_VGATHERPF0QPD:
  case ZYDIS_MNEMONIC_VGATHERPF1QPD:
  case ZYDIS_MNEMONIC_VSCATTERPF0QPD:
  case ZYDIS_MNEMONIC_VSCATTERPF1QPD:
  case ZYDIS_MNEMONIC_VSCATTERPF0QPS:
  case ZYDIS_MNEMONIC_VSCATTERPF1QPS:
  {
    switch (pInstruction->mnemonic)
    {
    case ZYDIS_MNEMONIC_VGATHERPF0DPS:
    case ZYDIS_MNEMONIC_VGATHERPF1DPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_prefetch_i32extgather_ps("));
      break;

    case ZYDIS_MNEMONIC_VGATHERPF0DPD:
    case ZYDIS_MNEMONIC_VGATHERPF1DPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_prefetch_i32extgather_pd("));
      break;

    case ZYDIS_MNEMONIC_VGATHERPF0QPS:
    case ZYDIS_MNEMONIC_VGATHERPF1QPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_prefetch_i64gather_ps("));
      break;

    case ZYDIS_MNEMONIC_VGATHERPF0QPD:
    case ZYDIS_MNEMONIC_VGATHERPF1QPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_prefetch_i64gather_pd("));
      break;

    case ZYDIS_MNEMONIC_VSCATTERPF0QPD:
    case ZYDIS_MNEMONIC_VSCATTERPF1QPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_prefetch_i64scatter_pd("));
      break;

    case ZYDIS_MNEMONIC_VSCATTERPF0QPS:
    case ZYDIS_MNEMONIC_VSCATTERPF1QPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_prefetch_i64scatter_ps("));
      break;

    default:
      break;
    }

    for (size_t operandIndex = 0; operandIndex < pInstruction->operand_count; operandIndex++)
    {
      if (operandIndex > 0)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ", "));

      ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[operandIndex], virtualAddress, pInfo));
    }

    switch (pInstruction->mnemonic)
    {
    case ZYDIS_MNEMONIC_VGATHERPF0DPS:
    case ZYDIS_MNEMONIC_VGATHERPF0DPD:
    case ZYDIS_MNEMONIC_VGATHERPF0QPS:
    case ZYDIS_MNEMONIC_VGATHERPF0QPD:
    case ZYDIS_MNEMONIC_VSCATTERPF0QPD:
    case ZYDIS_MNEMONIC_VSCATTERPF0QPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "); // part 1 / 2"));
      return true;

    case ZYDIS_MNEMONIC_VGATHERPF1DPS:
    case ZYDIS_MNEMONIC_VGATHERPF1DPD:
    case ZYDIS_MNEMONIC_VGATHERPF1QPS:
    case ZYDIS_MNEMONIC_VGATHERPF1QPD:
    case ZYDIS_MNEMONIC_VSCATTERPF1QPD:
    case ZYDIS_MNEMONIC_VSCATTERPF1QPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "); // part 2 / 2"));
      return true;

    default:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ")"));
      break;
    }
  }

  case ZYDIS_MNEMONIC_KADDB:
  case ZYDIS_MNEMONIC_KADDW:
  case ZYDIS_MNEMONIC_KADDD:
  case ZYDIS_MNEMONIC_KADDQ:
  case ZYDIS_MNEMONIC_KANDB:
  case ZYDIS_MNEMONIC_KANDW:
  case ZYDIS_MNEMONIC_KANDD:
  case ZYDIS_MNEMONIC_KANDQ:
  case ZYDIS_MNEMONIC_KORB:
  case ZYDIS_MNEMONIC_KORW:
  case ZYDIS_MNEMONIC_KORD:
  case ZYDIS_MNEMONIC_KORQ:
  case ZYDIS_MNEMONIC_KSHIFTLB:
  case ZYDIS_MNEMONIC_KSHIFTLW:
  case ZYDIS_MNEMONIC_KSHIFTLD:
  case ZYDIS_MNEMONIC_KSHIFTLQ:
  case ZYDIS_MNEMONIC_KSHIFTRB:
  case ZYDIS_MNEMONIC_KSHIFTRW:
  case ZYDIS_MNEMONIC_KSHIFTRD:
  case ZYDIS_MNEMONIC_KSHIFTRQ:
  case ZYDIS_MNEMONIC_KXORB:
  case ZYDIS_MNEMONIC_KXORW:
  case ZYDIS_MNEMONIC_KXORD:
  case ZYDIS_MNEMONIC_KXORQ:
  {
    ERROR_CHECK(zydec_WriteResultOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));

    if (simplifyShorthands)
    {
      if (pInstruction->operand_count == 3 && pOperands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && pOperands[2].type == ZYDIS_OPERAND_TYPE_REGISTER && pOperands[1].reg.value == pOperands[2].reg.value)
      {
        bool match = false;

        switch (pInstruction->mnemonic)
        {
        case ZYDIS_MNEMONIC_KANDB:
        case ZYDIS_MNEMONIC_KANDW:
        case ZYDIS_MNEMONIC_KANDD:
        case ZYDIS_MNEMONIC_KANDQ:
        case ZYDIS_MNEMONIC_KORB:
        case ZYDIS_MNEMONIC_KORW:
        case ZYDIS_MNEMONIC_KORD:
        case ZYDIS_MNEMONIC_KORQ:
          match = true;
          break;

        case ZYDIS_MNEMONIC_KXORB:
        case ZYDIS_MNEMONIC_KXORW:
        case ZYDIS_MNEMONIC_KXORD:
        case ZYDIS_MNEMONIC_KXORQ:
          match = true;
          ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "0"));
          break;

        default:
          break;
        }

        if (match)
        {
          ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ";"));
          return true;
        }
      }
    }

    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[1], virtualAddress, pInfo));
    
    switch (pInstruction->mnemonic)
    {
    case ZYDIS_MNEMONIC_KSHIFTLB:
    case ZYDIS_MNEMONIC_KSHIFTLW:
    case ZYDIS_MNEMONIC_KSHIFTLD:
    case ZYDIS_MNEMONIC_KSHIFTLQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " << "));
      break;
      
    case ZYDIS_MNEMONIC_KSHIFTRB:
    case ZYDIS_MNEMONIC_KSHIFTRW:
    case ZYDIS_MNEMONIC_KSHIFTRD:
    case ZYDIS_MNEMONIC_KSHIFTRQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " >> "));
      break;

    case ZYDIS_MNEMONIC_KADDB:
    case ZYDIS_MNEMONIC_KADDW:
    case ZYDIS_MNEMONIC_KADDD:
    case ZYDIS_MNEMONIC_KADDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " + "));
      break;

    case ZYDIS_MNEMONIC_KANDB:
    case ZYDIS_MNEMONIC_KANDW:
    case ZYDIS_MNEMONIC_KANDD:
    case ZYDIS_MNEMONIC_KANDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " & "));
      break;

    case ZYDIS_MNEMONIC_KORB:
    case ZYDIS_MNEMONIC_KORW:
    case ZYDIS_MNEMONIC_KORD:
    case ZYDIS_MNEMONIC_KORQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " | "));
      break;

    case ZYDIS_MNEMONIC_KXORB:
    case ZYDIS_MNEMONIC_KXORW:
    case ZYDIS_MNEMONIC_KXORD:
    case ZYDIS_MNEMONIC_KXORQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " ^ "));
      break;

    default:
      break;
    }

    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[2], virtualAddress, pInfo));

    break;
  }

  case ZYDIS_MNEMONIC_MOVAPS:
  case ZYDIS_MNEMONIC_MOVAPD:
  case ZYDIS_MNEMONIC_MOVDQA:
  case ZYDIS_MNEMONIC_VMOVAPS:
  case ZYDIS_MNEMONIC_VMOVAPD:
  case ZYDIS_MNEMONIC_VMOVDQA:
  case ZYDIS_MNEMONIC_VMOVDQA32:
  case ZYDIS_MNEMONIC_VMOVDQA64:
  case ZYDIS_MNEMONIC_MOVNTDQ:
  case ZYDIS_MNEMONIC_VMOVNTDQ:
  case ZYDIS_MNEMONIC_MOVNTPD:
  case ZYDIS_MNEMONIC_VMOVNTPD:
  case ZYDIS_MNEMONIC_MOVNTPS:
  case ZYDIS_MNEMONIC_VMOVNTPS:
  case ZYDIS_MNEMONIC_MOVNTDQA:
  case ZYDIS_MNEMONIC_VMOVNTDQA:
  {
    bool isReg2RegMove = false;
    size_t operandIndex = 0;

    if (pOperands[0].type == ZYDIS_OPERAND_TYPE_MEMORY || pOperands[0].type == ZYDIS_OPERAND_TYPE_POINTER)
    {
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_aligned_store"));
    }
    else if (pOperands[1].type == ZYDIS_OPERAND_TYPE_MEMORY || pOperands[1].type == ZYDIS_OPERAND_TYPE_POINTER)
    {
      ERROR_CHECK(zydec_WriteResultOperand(&bufferPos, &remainingSize, &pOperands[operandIndex++], virtualAddress, pInfo, zof_noAddressDeref));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = _mm_aligned_load"));
    }
    else if (pInstruction->operand_count == 2)
    {
      isReg2RegMove = true;
    }
    else
    {
      ERROR_CHECK(zydec_WriteResultOperand(&bufferPos, &remainingSize, &pOperands[operandIndex++], virtualAddress, pInfo, zof_noAddressDeref));

      if (pInstruction->operand_count == 3)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = _mm_maskz_mov"));
      else if (pInstruction->operand_count == 4)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = _mm_mask_mov"));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = _mm_mov"));
    }

    if (!isReg2RegMove)
    {
      switch (pInstruction->mnemonic)
      {
      case ZYDIS_MNEMONIC_MOVAPS:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_ps("));
        break;

      case ZYDIS_MNEMONIC_MOVAPD:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_pd("));
        break;

      case ZYDIS_MNEMONIC_MOVDQA:
      case ZYDIS_MNEMONIC_VMOVDQA:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_si("));
        break;

      case ZYDIS_MNEMONIC_VMOVDQA32:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_epi32("));
        break;

      case ZYDIS_MNEMONIC_VMOVDQA64:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_epi64("));
        break;

      case ZYDIS_MNEMONIC_MOVNTDQ:
      case ZYDIS_MNEMONIC_VMOVNTDQ:
      case ZYDIS_MNEMONIC_MOVNTDQA:
      case ZYDIS_MNEMONIC_VMOVNTDQA:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_stream_si("));
        break;

      case ZYDIS_MNEMONIC_MOVNTPD:
      case ZYDIS_MNEMONIC_VMOVNTPD:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_stream_pd("));
        break;

      case ZYDIS_MNEMONIC_MOVNTPS:
      case ZYDIS_MNEMONIC_VMOVNTPS:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_stream_ps("));
        break;

      default:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "("));
        break;
      }
    }

    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[operandIndex++], virtualAddress, pInfo, zof_noAddressDeref, isReg2RegMove));
    const size_t startOperandIndex = operandIndex;

    if (isReg2RegMove)
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));
    else if (startOperandIndex < pInstruction->operand_count)
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ", "));

    for (; operandIndex < pInstruction->operand_count; operandIndex++)
    {
      if (operandIndex > startOperandIndex)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ", "));

      ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[operandIndex], virtualAddress, pInfo, zof_noAddressDeref));
    }

    if (!isReg2RegMove)
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ")"));

    break;
  }

  case ZYDIS_MNEMONIC_MOVUPS:
  case ZYDIS_MNEMONIC_MOVUPD:
  case ZYDIS_MNEMONIC_MOVQ:
  case ZYDIS_MNEMONIC_MOVD:
  case ZYDIS_MNEMONIC_MOVSS:
  case ZYDIS_MNEMONIC_MOVSD:
  case ZYDIS_MNEMONIC_MOVDQU:
  case ZYDIS_MNEMONIC_MOVDQ2Q:
  case ZYDIS_MNEMONIC_VMOVUPS:
  case ZYDIS_MNEMONIC_VMOVUPD:
  case ZYDIS_MNEMONIC_VMOVQ:
  case ZYDIS_MNEMONIC_VMOVD:
  case ZYDIS_MNEMONIC_VMOVSS:
  case ZYDIS_MNEMONIC_VMOVSD:
  case ZYDIS_MNEMONIC_VMOVSH:
  case ZYDIS_MNEMONIC_VMOVDQU:
  case ZYDIS_MNEMONIC_VMOVDQU16:
  case ZYDIS_MNEMONIC_VMOVDQU32:
  case ZYDIS_MNEMONIC_VMOVDQU64:
  case ZYDIS_MNEMONIC_VMOVDQU8:
  case ZYDIS_MNEMONIC_LDDQU:
  case ZYDIS_MNEMONIC_VPMASKMOVD:
  case ZYDIS_MNEMONIC_VPMASKMOVQ:
  case ZYDIS_MNEMONIC_VMASKMOVPD:
  case ZYDIS_MNEMONIC_VMASKMOVPS:
  case ZYDIS_MNEMONIC_MASKMOVQ:
  case ZYDIS_MNEMONIC_MASKMOVDQU:
  {
    bool isReg2RegMove = false;
    size_t operandIndex = 0;

    if (pOperands[0].type == ZYDIS_OPERAND_TYPE_MEMORY || pOperands[0].type == ZYDIS_OPERAND_TYPE_POINTER)
    {
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_unaligned_store"));
    }
    else if (pOperands[1].type == ZYDIS_OPERAND_TYPE_MEMORY || pOperands[1].type == ZYDIS_OPERAND_TYPE_POINTER)
    {
      ERROR_CHECK(zydec_WriteResultOperand(&bufferPos, &remainingSize, &pOperands[operandIndex++], virtualAddress, pInfo, zof_noAddressDeref));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = _mm_unaligned_load"));
    }
    else if (pInstruction->operand_count == 2)
    {
      isReg2RegMove = true;
    }
    else
    {
      if (pInstruction->operand_count == 3)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_maskz_mov_unaligned"));
      else if (pInstruction->operand_count == 4)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mask_mov_unaligned"));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mov_unaligned"));
    }

    if (!isReg2RegMove)
    {
      switch (pInstruction->mnemonic)
      {
      case ZYDIS_MNEMONIC_MOVUPS:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_ps("));
        break;

      case ZYDIS_MNEMONIC_MOVUPD:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_pd("));
        break;

      case ZYDIS_MNEMONIC_MOVD:
      case ZYDIS_MNEMONIC_VMOVD:
      case ZYDIS_MNEMONIC_VMOVDQU32:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_epi32("));
        break;

      case ZYDIS_MNEMONIC_MOVQ:
      case ZYDIS_MNEMONIC_VMOVQ:
      case ZYDIS_MNEMONIC_VMOVDQU64:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_epi64("));
        break;

      case ZYDIS_MNEMONIC_VPMASKMOVD:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mask_epi32("));
        break;

      case ZYDIS_MNEMONIC_VPMASKMOVQ:
      case ZYDIS_MNEMONIC_MASKMOVQ:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mask_epi64("));
        break;

      case ZYDIS_MNEMONIC_VMASKMOVPD:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mask_pd("));
        break;

      case ZYDIS_MNEMONIC_VMASKMOVPS:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mask_ps("));
        break;

      case ZYDIS_MNEMONIC_MASKMOVDQU:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mask_si128("));
        break;

      case ZYDIS_MNEMONIC_MOVSS:
      case ZYDIS_MNEMONIC_VMOVSS:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_ss("));
        break;

      case ZYDIS_MNEMONIC_MOVSD:
      case ZYDIS_MNEMONIC_VMOVSD:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_sd("));
        break;

      case ZYDIS_MNEMONIC_VMOVSH:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_sh("));
        break;

      case ZYDIS_MNEMONIC_LDDQU:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_cross_cache_line_si("));
        break;

      case ZYDIS_MNEMONIC_MOVDQU:
      case ZYDIS_MNEMONIC_VMOVDQU:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_si("));
        break;

      case ZYDIS_MNEMONIC_VMOVDQU16:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_epi16("));
        break;

      case ZYDIS_MNEMONIC_VMOVDQU8:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_epi8("));
        break;

      case ZYDIS_MNEMONIC_MOVDQ2Q:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_pi("));
        break;

      default:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "("));
        break;
      }
    }

    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[operandIndex++], virtualAddress, pInfo, zof_noAddressDeref, isReg2RegMove));
    const size_t startOperandIndex = operandIndex;

    if (isReg2RegMove)
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));
    else if (startOperandIndex < pInstruction->operand_count)
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ", "));

    for (; operandIndex < pInstruction->operand_count; operandIndex++)
    {
      if (operandIndex > startOperandIndex)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ", "));

      ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[operandIndex], virtualAddress, pInfo, zof_noAddressDeref));
    }

    if (!isReg2RegMove)
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ")"));

    break;
  }

  case ZYDIS_MNEMONIC_PAND:
  case ZYDIS_MNEMONIC_VPAND:
  case ZYDIS_MNEMONIC_VPANDQ:
  case ZYDIS_MNEMONIC_VPANDD:
  case ZYDIS_MNEMONIC_PANDN:
  case ZYDIS_MNEMONIC_VPANDN:
  case ZYDIS_MNEMONIC_VPANDNQ:
  case ZYDIS_MNEMONIC_VPANDND:
  case ZYDIS_MNEMONIC_PCMPEQB:
  case ZYDIS_MNEMONIC_PCMPEQW:
  case ZYDIS_MNEMONIC_PCMPEQD:
  case ZYDIS_MNEMONIC_PCMPEQQ:
  case ZYDIS_MNEMONIC_VPCMPEQB:
  case ZYDIS_MNEMONIC_VPCMPEQW:
  case ZYDIS_MNEMONIC_VPCMPEQD:
  case ZYDIS_MNEMONIC_VPCMPEQQ:
  case ZYDIS_MNEMONIC_PCMPGTB:
  case ZYDIS_MNEMONIC_PCMPGTW:
  case ZYDIS_MNEMONIC_PCMPGTD:
  case ZYDIS_MNEMONIC_PCMPGTQ:
  case ZYDIS_MNEMONIC_VPCMPGTB:
  case ZYDIS_MNEMONIC_VPCMPGTW:
  case ZYDIS_MNEMONIC_VPCMPGTD:
  case ZYDIS_MNEMONIC_VPCMPGTQ:
  case ZYDIS_MNEMONIC_PACKUSWB:
  case ZYDIS_MNEMONIC_PACKUSDW:
  case ZYDIS_MNEMONIC_VPACKUSWB:
  case ZYDIS_MNEMONIC_VPACKUSDW:
  case ZYDIS_MNEMONIC_PACKSSWB:
  case ZYDIS_MNEMONIC_PACKSSDW:
  case ZYDIS_MNEMONIC_VPACKSSWB:
  case ZYDIS_MNEMONIC_VPACKSSDW:
  case ZYDIS_MNEMONIC_PADDB:
  case ZYDIS_MNEMONIC_PADDW:
  case ZYDIS_MNEMONIC_PADDD:
  case ZYDIS_MNEMONIC_PADDQ:
  case ZYDIS_MNEMONIC_VPADDB:
  case ZYDIS_MNEMONIC_VPADDW:
  case ZYDIS_MNEMONIC_VPADDD:
  case ZYDIS_MNEMONIC_VPADDQ:
  case ZYDIS_MNEMONIC_ADDPS:
  case ZYDIS_MNEMONIC_ADDPD:
  case ZYDIS_MNEMONIC_ADDSS:
  case ZYDIS_MNEMONIC_ADDSD:
  case ZYDIS_MNEMONIC_VADDPS:
  case ZYDIS_MNEMONIC_VADDPD:
  case ZYDIS_MNEMONIC_VADDSS:
  case ZYDIS_MNEMONIC_VADDSD:
  case ZYDIS_MNEMONIC_PADDSB:
  case ZYDIS_MNEMONIC_PADDSW:
  case ZYDIS_MNEMONIC_VPADDSB:
  case ZYDIS_MNEMONIC_VPADDSW:
  case ZYDIS_MNEMONIC_EMMS:
  case ZYDIS_MNEMONIC_PMADDWD:
  case ZYDIS_MNEMONIC_VPMADDWD:
  case ZYDIS_MNEMONIC_PMULHW:
  case ZYDIS_MNEMONIC_VPMULHW:
  case ZYDIS_MNEMONIC_PMULLW:
  case ZYDIS_MNEMONIC_VPMULLW:
  case ZYDIS_MNEMONIC_POR:
  case ZYDIS_MNEMONIC_VPOR:
  case ZYDIS_MNEMONIC_VPORD:
  case ZYDIS_MNEMONIC_VPORQ:
  case ZYDIS_MNEMONIC_PABSW:
  case ZYDIS_MNEMONIC_VPABSW:
  case ZYDIS_MNEMONIC_PABSB:
  case ZYDIS_MNEMONIC_VPABSB:
  case ZYDIS_MNEMONIC_PABSD:
  case ZYDIS_MNEMONIC_VPABSD:
  case ZYDIS_MNEMONIC_ADDSUBPS:
  case ZYDIS_MNEMONIC_VADDSUBPS:
  case ZYDIS_MNEMONIC_ADDSUBPD:
  case ZYDIS_MNEMONIC_VADDSUBPD:
  case ZYDIS_MNEMONIC_PALIGNR:
  case ZYDIS_MNEMONIC_VPALIGNR:
  case ZYDIS_MNEMONIC_PAVGB:
  case ZYDIS_MNEMONIC_VPAVGB:
  case ZYDIS_MNEMONIC_PAVGW:
  case ZYDIS_MNEMONIC_VPAVGW:
  case ZYDIS_MNEMONIC_PBLENDW:
  case ZYDIS_MNEMONIC_VPBLENDW:
  case ZYDIS_MNEMONIC_PBLENDVB:
  case ZYDIS_MNEMONIC_VPBLENDVB:
  case ZYDIS_MNEMONIC_VPBLENDD:
  case ZYDIS_MNEMONIC_BLENDPS:
  case ZYDIS_MNEMONIC_VBLENDPS:
  case ZYDIS_MNEMONIC_BLENDPD:
  case ZYDIS_MNEMONIC_VBLENDPD:
  case ZYDIS_MNEMONIC_BLENDVPS:
  case ZYDIS_MNEMONIC_VBLENDVPS:
  case ZYDIS_MNEMONIC_BLENDVPD:
  case ZYDIS_MNEMONIC_VBLENDVPD:
  case ZYDIS_MNEMONIC_VBROADCASTF128:
  case ZYDIS_MNEMONIC_VBROADCASTF32X2:
  case ZYDIS_MNEMONIC_VBROADCASTF32X4:
  case ZYDIS_MNEMONIC_VBROADCASTF32X8:
  case ZYDIS_MNEMONIC_VBROADCASTF64X2:
  case ZYDIS_MNEMONIC_VBROADCASTF64X4:
  case ZYDIS_MNEMONIC_VBROADCASTI128:
  case ZYDIS_MNEMONIC_VBROADCASTI32X2:
  case ZYDIS_MNEMONIC_VBROADCASTI32X4:
  case ZYDIS_MNEMONIC_VBROADCASTI32X8:
  case ZYDIS_MNEMONIC_VBROADCASTI64X2:
  case ZYDIS_MNEMONIC_VBROADCASTI64X4:
  case ZYDIS_MNEMONIC_VBROADCASTSD:
  case ZYDIS_MNEMONIC_VBROADCASTSS:
  case ZYDIS_MNEMONIC_VPBROADCASTB:
  case ZYDIS_MNEMONIC_VPBROADCASTD:
  case ZYDIS_MNEMONIC_VPBROADCASTMB2Q:
  case ZYDIS_MNEMONIC_VPBROADCASTMW2D:
  case ZYDIS_MNEMONIC_VPBROADCASTQ:
  case ZYDIS_MNEMONIC_VPBROADCASTW:
  case ZYDIS_MNEMONIC_PSLLDQ:
  case ZYDIS_MNEMONIC_VPSLLDQ:
  case ZYDIS_MNEMONIC_PSRLDQ:
  case ZYDIS_MNEMONIC_VPSRLDQ:
  case ZYDIS_MNEMONIC_ROUNDSS:
  case ZYDIS_MNEMONIC_VROUNDSS:
  case ZYDIS_MNEMONIC_ROUNDSD:
  case ZYDIS_MNEMONIC_VROUNDSD:
  case ZYDIS_MNEMONIC_ROUNDPS:
  case ZYDIS_MNEMONIC_VROUNDPS:
  case ZYDIS_MNEMONIC_ROUNDPD:
  case ZYDIS_MNEMONIC_VROUNDPD:
  case ZYDIS_MNEMONIC_CLFLUSH:
  case ZYDIS_MNEMONIC_CLFLUSHOPT:
  case ZYDIS_MNEMONIC_CMPSS:
  case ZYDIS_MNEMONIC_VCMPSS:
  case ZYDIS_MNEMONIC_CMPSD:
  case ZYDIS_MNEMONIC_VCMPSD:
  case ZYDIS_MNEMONIC_CMPPS:
  case ZYDIS_MNEMONIC_VCMPPS:
  case ZYDIS_MNEMONIC_CMPPD:
  case ZYDIS_MNEMONIC_VCMPPD:
  case ZYDIS_MNEMONIC_PCMPESTRI:
  case ZYDIS_MNEMONIC_PCMPESTRM:
  case ZYDIS_MNEMONIC_COMISS:
  case ZYDIS_MNEMONIC_VCOMISS:
  case ZYDIS_MNEMONIC_COMISD:
  case ZYDIS_MNEMONIC_VCOMISD:
  case ZYDIS_MNEMONIC_VCOMISH:
  case ZYDIS_MNEMONIC_CRC32:
  case ZYDIS_MNEMONIC_CVTPI2PS:
  case ZYDIS_MNEMONIC_CVTPS2PI:
  case ZYDIS_MNEMONIC_CVTSI2SS:
  case ZYDIS_MNEMONIC_VCVTSI2SS:
  case ZYDIS_MNEMONIC_CVTSS2SI:
  case ZYDIS_MNEMONIC_VCVTSS2SI:
  case ZYDIS_MNEMONIC_PMOVSXWD:
  case ZYDIS_MNEMONIC_VPMOVSXWD:
  case ZYDIS_MNEMONIC_PMOVSXWQ:
  case ZYDIS_MNEMONIC_VPMOVSXWQ:
  case ZYDIS_MNEMONIC_PMOVSXDQ:
  case ZYDIS_MNEMONIC_VPMOVSXDQ:
  case ZYDIS_MNEMONIC_CVTDQ2PS:
  case ZYDIS_MNEMONIC_VCVTDQ2PS:
  case ZYDIS_MNEMONIC_CVTDQ2PD:
  case ZYDIS_MNEMONIC_VCVTDQ2PD:
  case ZYDIS_MNEMONIC_PMOVSXBW:
  case ZYDIS_MNEMONIC_VPMOVSXBW:
  case ZYDIS_MNEMONIC_PMOVSXBD:
  case ZYDIS_MNEMONIC_VPMOVSXBD:
  case ZYDIS_MNEMONIC_PMOVSXBQ:
  case ZYDIS_MNEMONIC_VPMOVSXBQ:
  case ZYDIS_MNEMONIC_PMOVZXWD:
  case ZYDIS_MNEMONIC_VPMOVZXWD:
  case ZYDIS_MNEMONIC_PMOVZXWQ:
  case ZYDIS_MNEMONIC_VPMOVZXWQ:
  case ZYDIS_MNEMONIC_PMOVZXDQ:
  case ZYDIS_MNEMONIC_VPMOVZXDQ:
  case ZYDIS_MNEMONIC_PMOVZXBW:
  case ZYDIS_MNEMONIC_VPMOVZXBW:
  case ZYDIS_MNEMONIC_PMOVZXBD:
  case ZYDIS_MNEMONIC_VPMOVZXBD:
  case ZYDIS_MNEMONIC_PMOVZXBQ:
  case ZYDIS_MNEMONIC_VPMOVZXBQ:
  case ZYDIS_MNEMONIC_VCVTPH2PS:
  case ZYDIS_MNEMONIC_VCVTNEPS2BF16:
  case ZYDIS_MNEMONIC_CVTPD2DQ:
  case ZYDIS_MNEMONIC_VCVTPD2DQ:
  case ZYDIS_MNEMONIC_CVTPD2PI:
  case ZYDIS_MNEMONIC_CVTPD2PS:
  case ZYDIS_MNEMONIC_VCVTPD2PS:
  case ZYDIS_MNEMONIC_CVTPI2PD:
  case ZYDIS_MNEMONIC_CVTPS2DQ:
  case ZYDIS_MNEMONIC_VCVTPS2DQ:
  case ZYDIS_MNEMONIC_CVTPS2PD:
  case ZYDIS_MNEMONIC_VCVTPS2PD:
  case ZYDIS_MNEMONIC_VCVTPS2PH:
  case ZYDIS_MNEMONIC_CVTSD2SI:
  case ZYDIS_MNEMONIC_VCVTSD2SI:
  case ZYDIS_MNEMONIC_CVTSD2SS:
  case ZYDIS_MNEMONIC_VCVTSD2SS:
  case ZYDIS_MNEMONIC_CVTSI2SD:
  case ZYDIS_MNEMONIC_VCVTSI2SD:
  case ZYDIS_MNEMONIC_CVTSS2SD:
  case ZYDIS_MNEMONIC_VCVTSS2SD:
  case ZYDIS_MNEMONIC_CVTTPS2PI:
  case ZYDIS_MNEMONIC_CVTTPD2DQ:
  case ZYDIS_MNEMONIC_VCVTTPD2DQ:
  case ZYDIS_MNEMONIC_CVTTPD2PI:
  case ZYDIS_MNEMONIC_CVTTPS2DQ:
  case ZYDIS_MNEMONIC_VCVTTPS2DQ:
  case ZYDIS_MNEMONIC_CVTTSD2SI:
  case ZYDIS_MNEMONIC_DIVPD:
  case ZYDIS_MNEMONIC_DIVPS:
  case ZYDIS_MNEMONIC_DIVSD:
  case ZYDIS_MNEMONIC_DIVSS:
  case ZYDIS_MNEMONIC_VDIVPD:
  case ZYDIS_MNEMONIC_VDIVPS:
  case ZYDIS_MNEMONIC_VDIVSD:
  case ZYDIS_MNEMONIC_VDIVSS:
  case ZYDIS_MNEMONIC_DPPD:
  case ZYDIS_MNEMONIC_VDPPD:
  case ZYDIS_MNEMONIC_DPPS:
  case ZYDIS_MNEMONIC_VDPPS:
  case ZYDIS_MNEMONIC_VPDPWSSD:
  case ZYDIS_MNEMONIC_VPDPWSSDS:
  case ZYDIS_MNEMONIC_VPDPBUSD:
  case ZYDIS_MNEMONIC_VPDPBUSDS:
  case ZYDIS_MNEMONIC_PEXTRB:
  case ZYDIS_MNEMONIC_VPEXTRB:
  case ZYDIS_MNEMONIC_PEXTRW:
  case ZYDIS_MNEMONIC_VPEXTRW:
  case ZYDIS_MNEMONIC_PEXTRD:
  case ZYDIS_MNEMONIC_VPEXTRD:
  case ZYDIS_MNEMONIC_PEXTRQ:
  case ZYDIS_MNEMONIC_VPEXTRQ:
  case ZYDIS_MNEMONIC_EXTRACTPS:
  case ZYDIS_MNEMONIC_VEXTRACTPS:
  case ZYDIS_MNEMONIC_VEXTRACTF128:
  case ZYDIS_MNEMONIC_VEXTRACTI128:
  case ZYDIS_MNEMONIC_VFMADD132PD:
  case ZYDIS_MNEMONIC_VFMADD213PD:
  case ZYDIS_MNEMONIC_VFMADD231PD:
  case ZYDIS_MNEMONIC_VFMADD132PS:
  case ZYDIS_MNEMONIC_VFMADD213PS:
  case ZYDIS_MNEMONIC_VFMADD231PS:
  case ZYDIS_MNEMONIC_VFMADD132SD:
  case ZYDIS_MNEMONIC_VFMADD213SD:
  case ZYDIS_MNEMONIC_VFMADD231SD:
  case ZYDIS_MNEMONIC_VFMADD132SS:
  case ZYDIS_MNEMONIC_VFMADD213SS:
  case ZYDIS_MNEMONIC_VFMADD231SS:
  case ZYDIS_MNEMONIC_VFMADDSUB132PD:
  case ZYDIS_MNEMONIC_VFMADDSUB213PD:
  case ZYDIS_MNEMONIC_VFMADDSUB231PD:
  case ZYDIS_MNEMONIC_VFMADDSUB132PS:
  case ZYDIS_MNEMONIC_VFMADDSUB213PS:
  case ZYDIS_MNEMONIC_VFMADDSUB231PS:
  case ZYDIS_MNEMONIC_VFMSUB132PD:
  case ZYDIS_MNEMONIC_VFMSUB213PD:
  case ZYDIS_MNEMONIC_VFMSUB231PD:
  case ZYDIS_MNEMONIC_VFMSUB132PS:
  case ZYDIS_MNEMONIC_VFMSUB213PS:
  case ZYDIS_MNEMONIC_VFMSUB231PS:
  case ZYDIS_MNEMONIC_VFMSUB132SD:
  case ZYDIS_MNEMONIC_VFMSUB213SD:
  case ZYDIS_MNEMONIC_VFMSUB231SD:
  case ZYDIS_MNEMONIC_VFMSUB132SS:
  case ZYDIS_MNEMONIC_VFMSUB213SS:
  case ZYDIS_MNEMONIC_VFMSUB231SS:
  case ZYDIS_MNEMONIC_VFMSUBADD132PD:
  case ZYDIS_MNEMONIC_VFMSUBADD213PD:
  case ZYDIS_MNEMONIC_VFMSUBADD231PD:
  case ZYDIS_MNEMONIC_VFMSUBADD132PS:
  case ZYDIS_MNEMONIC_VFMSUBADD213PS:
  case ZYDIS_MNEMONIC_VFMSUBADD231PS:
  case ZYDIS_MNEMONIC_VFNMADD132PD:
  case ZYDIS_MNEMONIC_VFNMADD213PD:
  case ZYDIS_MNEMONIC_VFNMADD231PD:
  case ZYDIS_MNEMONIC_VFNMADD132PS:
  case ZYDIS_MNEMONIC_VFNMADD213PS:
  case ZYDIS_MNEMONIC_VFNMADD231PS:
  case ZYDIS_MNEMONIC_VFNMADD132SD:
  case ZYDIS_MNEMONIC_VFNMADD213SD:
  case ZYDIS_MNEMONIC_VFNMADD231SD:
  case ZYDIS_MNEMONIC_VFNMADD132SS:
  case ZYDIS_MNEMONIC_VFNMADD213SS:
  case ZYDIS_MNEMONIC_VFNMADD231SS:
  case ZYDIS_MNEMONIC_VFNMSUB132PD:
  case ZYDIS_MNEMONIC_VFNMSUB213PD:
  case ZYDIS_MNEMONIC_VFNMSUB231PD:
  case ZYDIS_MNEMONIC_VFNMSUB132PS:
  case ZYDIS_MNEMONIC_VFNMSUB213PS:
  case ZYDIS_MNEMONIC_VFNMSUB231PS:
  case ZYDIS_MNEMONIC_VFNMSUB132SD:
  case ZYDIS_MNEMONIC_VFNMSUB213SD:
  case ZYDIS_MNEMONIC_VFNMSUB231SD:
  case ZYDIS_MNEMONIC_VFNMSUB132SS:
  case ZYDIS_MNEMONIC_VFNMSUB213SS:
  case ZYDIS_MNEMONIC_VFNMSUB231SS:
  case ZYDIS_MNEMONIC_STMXCSR:
  case ZYDIS_MNEMONIC_PHADDW:
  case ZYDIS_MNEMONIC_VPHADDW:
  case ZYDIS_MNEMONIC_PHADDD:
  case ZYDIS_MNEMONIC_VPHADDD:
  case ZYDIS_MNEMONIC_HADDPD:
  case ZYDIS_MNEMONIC_VHADDPD:
  case ZYDIS_MNEMONIC_HADDPS:
  case ZYDIS_MNEMONIC_VHADDPS:
  case ZYDIS_MNEMONIC_PHADDSW:
  case ZYDIS_MNEMONIC_VPHADDSW:
  case ZYDIS_MNEMONIC_PHSUBW:
  case ZYDIS_MNEMONIC_VPHSUBW:
  case ZYDIS_MNEMONIC_PHSUBD:
  case ZYDIS_MNEMONIC_VPHSUBD:
  case ZYDIS_MNEMONIC_HSUBPD:
  case ZYDIS_MNEMONIC_VHSUBPD:
  case ZYDIS_MNEMONIC_HSUBPS:
  case ZYDIS_MNEMONIC_VHSUBPS:
  case ZYDIS_MNEMONIC_PHSUBSW:
  case ZYDIS_MNEMONIC_VPHSUBSW:
  case ZYDIS_MNEMONIC_VPGATHERDD:
  case ZYDIS_MNEMONIC_VPGATHERDQ:
  case ZYDIS_MNEMONIC_VGATHERDPD:
  case ZYDIS_MNEMONIC_VGATHERDPS:
  case ZYDIS_MNEMONIC_VPGATHERQD:
  case ZYDIS_MNEMONIC_VPGATHERQQ:
  case ZYDIS_MNEMONIC_VGATHERQPD:
  case ZYDIS_MNEMONIC_VGATHERQPS:
  case ZYDIS_MNEMONIC_PINSRB:
  case ZYDIS_MNEMONIC_VPINSRB:
  case ZYDIS_MNEMONIC_PINSRW:
  case ZYDIS_MNEMONIC_VPINSRW:
  case ZYDIS_MNEMONIC_PINSRD:
  case ZYDIS_MNEMONIC_VPINSRD:
  case ZYDIS_MNEMONIC_PINSRQ:
  case ZYDIS_MNEMONIC_VPINSRQ:
  case ZYDIS_MNEMONIC_INSERTPS:
  case ZYDIS_MNEMONIC_VINSERTPS:
  case ZYDIS_MNEMONIC_VINSERTF128:
  case ZYDIS_MNEMONIC_VINSERTI128:
  case ZYDIS_MNEMONIC_LFENCE:
  case ZYDIS_MNEMONIC_MOVHPS:
  case ZYDIS_MNEMONIC_MOVHPD:
  case ZYDIS_MNEMONIC_VPMADD52HUQ:
  case ZYDIS_MNEMONIC_VPMADD52LUQ:
  case ZYDIS_MNEMONIC_PMADDUBSW:
  case ZYDIS_MNEMONIC_VPMADDUBSW:
  case ZYDIS_MNEMONIC_PMAXSB:
  case ZYDIS_MNEMONIC_VPMAXSB:
  case ZYDIS_MNEMONIC_PMAXSW:
  case ZYDIS_MNEMONIC_VPMAXSW:
  case ZYDIS_MNEMONIC_PMAXSD:
  case ZYDIS_MNEMONIC_VPMAXSD:
  case ZYDIS_MNEMONIC_VPMAXSQ:
  case ZYDIS_MNEMONIC_PMAXUB:
  case ZYDIS_MNEMONIC_VPMAXUB:
  case ZYDIS_MNEMONIC_PMAXUW:
  case ZYDIS_MNEMONIC_VPMAXUW:
  case ZYDIS_MNEMONIC_PMAXUD:
  case ZYDIS_MNEMONIC_VPMAXUD:
  case ZYDIS_MNEMONIC_VPMAXUQ:
  case ZYDIS_MNEMONIC_MAXPD:
  case ZYDIS_MNEMONIC_VMAXPD:
  case ZYDIS_MNEMONIC_MAXPS:
  case ZYDIS_MNEMONIC_VMAXPS:
  case ZYDIS_MNEMONIC_MAXSD:
  case ZYDIS_MNEMONIC_VMAXSD:
  case ZYDIS_MNEMONIC_MAXSS:
  case ZYDIS_MNEMONIC_VMAXSS:
  case ZYDIS_MNEMONIC_PMINSB:
  case ZYDIS_MNEMONIC_VPMINSB:
  case ZYDIS_MNEMONIC_PMINSW:
  case ZYDIS_MNEMONIC_VPMINSW:
  case ZYDIS_MNEMONIC_PMINSD:
  case ZYDIS_MNEMONIC_VPMINSD:
  case ZYDIS_MNEMONIC_VPMINSQ:
  case ZYDIS_MNEMONIC_PMINUB:
  case ZYDIS_MNEMONIC_VPMINUB:
  case ZYDIS_MNEMONIC_PMINUW:
  case ZYDIS_MNEMONIC_VPMINUW:
  case ZYDIS_MNEMONIC_PMINUD:
  case ZYDIS_MNEMONIC_VPMINUD:
  case ZYDIS_MNEMONIC_VPMINUQ:
  case ZYDIS_MNEMONIC_MINPD:
  case ZYDIS_MNEMONIC_VMINPD:
  case ZYDIS_MNEMONIC_MINPS:
  case ZYDIS_MNEMONIC_VMINPS:
  case ZYDIS_MNEMONIC_MINSD:
  case ZYDIS_MNEMONIC_VMINSD:
  case ZYDIS_MNEMONIC_MINSS:
  case ZYDIS_MNEMONIC_VMINSS:
  case ZYDIS_MNEMONIC_PHMINPOSUW:
  case ZYDIS_MNEMONIC_VPHMINPOSUW:
  case ZYDIS_MNEMONIC_MOVDDUP:
  case ZYDIS_MNEMONIC_VMOVDDUP:
  case ZYDIS_MNEMONIC_MOVSHDUP:
  case ZYDIS_MNEMONIC_VMOVSHDUP:
  case ZYDIS_MNEMONIC_MOVHLPS:
  case ZYDIS_MNEMONIC_VMOVHLPS:
  case ZYDIS_MNEMONIC_MOVSLDUP:
  case ZYDIS_MNEMONIC_VMOVSLDUP:
  case ZYDIS_MNEMONIC_MOVLHPS:
  case ZYDIS_MNEMONIC_VMOVLHPS:
  case ZYDIS_MNEMONIC_PMOVMSKB:
  case ZYDIS_MNEMONIC_VPMOVMSKB:
  case ZYDIS_MNEMONIC_MOVMSKPD:
  case ZYDIS_MNEMONIC_VMOVMSKPD:
  case ZYDIS_MNEMONIC_MOVMSKPS:
  case ZYDIS_MNEMONIC_VMOVMSKPS:
  case ZYDIS_MNEMONIC_MPSADBW:
  case ZYDIS_MNEMONIC_VMPSADBW:
  case ZYDIS_MNEMONIC_PMULDQ:
  case ZYDIS_MNEMONIC_VPMULDQ:
  case ZYDIS_MNEMONIC_PMULUDQ:
  case ZYDIS_MNEMONIC_VPMULUDQ:
  case ZYDIS_MNEMONIC_MULPD:
  case ZYDIS_MNEMONIC_VMULPD:
  case ZYDIS_MNEMONIC_MULPS:
  case ZYDIS_MNEMONIC_VMULPS:
  case ZYDIS_MNEMONIC_MULSD:
  case ZYDIS_MNEMONIC_VMULSD:
  case ZYDIS_MNEMONIC_MULSS:
  case ZYDIS_MNEMONIC_VMULSS:
  case ZYDIS_MNEMONIC_PMULHRSW:
  case ZYDIS_MNEMONIC_VPMULHRSW:
  case ZYDIS_MNEMONIC_PMULLD:
  case ZYDIS_MNEMONIC_VPMULLD:
  case ZYDIS_MNEMONIC_ORPD:
  case ZYDIS_MNEMONIC_VORPD:
  case ZYDIS_MNEMONIC_ORPS:
  case ZYDIS_MNEMONIC_VORPS:
  case ZYDIS_MNEMONIC_PAUSE:
  case ZYDIS_MNEMONIC_VPERMILPD:
  case ZYDIS_MNEMONIC_VPERMILPS:
  case ZYDIS_MNEMONIC_VPERM2F128:
  case ZYDIS_MNEMONIC_VPERM2I128:
  case ZYDIS_MNEMONIC_VPERMQ:
  case ZYDIS_MNEMONIC_VPERMPD:
  case ZYDIS_MNEMONIC_VPERMPS:
  case ZYDIS_MNEMONIC_RCPPS:
  case ZYDIS_MNEMONIC_VRCPPS:
  case ZYDIS_MNEMONIC_RCPSS:
  case ZYDIS_MNEMONIC_VRCPSS:
  case ZYDIS_MNEMONIC_RSQRTPS:
  case ZYDIS_MNEMONIC_VRSQRTPS:
  case ZYDIS_MNEMONIC_RSQRTSS:
  case ZYDIS_MNEMONIC_VRSQRTSS:
  case ZYDIS_MNEMONIC_PSADBW:
  case ZYDIS_MNEMONIC_VPSADBW:
  case ZYDIS_MNEMONIC_SFENCE:
  case ZYDIS_MNEMONIC_PSHUFB:
  case ZYDIS_MNEMONIC_PSHUFW:
  case ZYDIS_MNEMONIC_PSHUFD:
  case ZYDIS_MNEMONIC_VPSHUFB:
  case ZYDIS_MNEMONIC_VPSHUFD:
  case ZYDIS_MNEMONIC_SHUFPS:
  case ZYDIS_MNEMONIC_VSHUFPS:
  case ZYDIS_MNEMONIC_SHUFPD:
  case ZYDIS_MNEMONIC_VSHUFPD:
  case ZYDIS_MNEMONIC_PSHUFHW:
  case ZYDIS_MNEMONIC_VPSHUFHW:
  case ZYDIS_MNEMONIC_PSHUFLW:
  case ZYDIS_MNEMONIC_VPSHUFLW:
  case ZYDIS_MNEMONIC_PSIGNB:
  case ZYDIS_MNEMONIC_VPSIGNB:
  case ZYDIS_MNEMONIC_PSIGNW:
  case ZYDIS_MNEMONIC_VPSIGNW:
  case ZYDIS_MNEMONIC_PSIGND:
  case ZYDIS_MNEMONIC_VPSIGND:
  case ZYDIS_MNEMONIC_PSLLW:
  case ZYDIS_MNEMONIC_VPSLLW:
  case ZYDIS_MNEMONIC_PSLLD:
  case ZYDIS_MNEMONIC_VPSLLD:
  case ZYDIS_MNEMONIC_PSLLQ:
  case ZYDIS_MNEMONIC_VPSLLQ:
  case ZYDIS_MNEMONIC_VPSLLVD:
  case ZYDIS_MNEMONIC_VPSLLVQ:
  case ZYDIS_MNEMONIC_SQRTPD:
  case ZYDIS_MNEMONIC_VSQRTPD:
  case ZYDIS_MNEMONIC_SQRTPS:
  case ZYDIS_MNEMONIC_VSQRTPS:
  case ZYDIS_MNEMONIC_SQRTSD:
  case ZYDIS_MNEMONIC_VSQRTSD:
  case ZYDIS_MNEMONIC_SQRTSS:
  case ZYDIS_MNEMONIC_VSQRTSS:
  case ZYDIS_MNEMONIC_PSRAW:
  case ZYDIS_MNEMONIC_VPSRAW:
  case ZYDIS_MNEMONIC_PSRAD:
  case ZYDIS_MNEMONIC_VPSRAD:
  case ZYDIS_MNEMONIC_VPSRAQ:
  case ZYDIS_MNEMONIC_VPSRAVW:
  case ZYDIS_MNEMONIC_VPSRAVD:
  case ZYDIS_MNEMONIC_VPSRAVQ:
  case ZYDIS_MNEMONIC_PSRLW:
  case ZYDIS_MNEMONIC_VPSRLW:
  case ZYDIS_MNEMONIC_PSRLD:
  case ZYDIS_MNEMONIC_VPSRLD:
  case ZYDIS_MNEMONIC_PSRLQ:
  case ZYDIS_MNEMONIC_VPSRLQ:
  case ZYDIS_MNEMONIC_VPSRLVW:
  case ZYDIS_MNEMONIC_VPSRLVD:
  case ZYDIS_MNEMONIC_VPSRLVQ:
  case ZYDIS_MNEMONIC_PSUBB:
  case ZYDIS_MNEMONIC_VPSUBB:
  case ZYDIS_MNEMONIC_PSUBW:
  case ZYDIS_MNEMONIC_VPSUBW:
  case ZYDIS_MNEMONIC_PSUBD:
  case ZYDIS_MNEMONIC_VPSUBD:
  case ZYDIS_MNEMONIC_PSUBQ:
  case ZYDIS_MNEMONIC_VPSUBQ:
  case ZYDIS_MNEMONIC_SUBPD:
  case ZYDIS_MNEMONIC_VSUBPD:
  case ZYDIS_MNEMONIC_SUBPS:
  case ZYDIS_MNEMONIC_VSUBPS:
  case ZYDIS_MNEMONIC_SUBSD:
  case ZYDIS_MNEMONIC_VSUBSD:
  case ZYDIS_MNEMONIC_SUBSS:
  case ZYDIS_MNEMONIC_VSUBSS:
  case ZYDIS_MNEMONIC_PSUBSB:
  case ZYDIS_MNEMONIC_VPSUBSB:
  case ZYDIS_MNEMONIC_PSUBSW:
  case ZYDIS_MNEMONIC_VPSUBSW:
  case ZYDIS_MNEMONIC_PTEST:
  case ZYDIS_MNEMONIC_VPTEST:
  case ZYDIS_MNEMONIC_VTESTPD:
  case ZYDIS_MNEMONIC_VTESTPS:
  case ZYDIS_MNEMONIC_UCOMISD:
  case ZYDIS_MNEMONIC_UCOMISS:
  case ZYDIS_MNEMONIC_PUNPCKHBW:
  case ZYDIS_MNEMONIC_VPUNPCKHBW:
  case ZYDIS_MNEMONIC_PUNPCKHWD:
  case ZYDIS_MNEMONIC_VPUNPCKHWD:
  case ZYDIS_MNEMONIC_PUNPCKHDQ:
  case ZYDIS_MNEMONIC_VPUNPCKHDQ:
  case ZYDIS_MNEMONIC_PUNPCKHQDQ:
  case ZYDIS_MNEMONIC_VPUNPCKHQDQ:
  case ZYDIS_MNEMONIC_UNPCKHPD:
  case ZYDIS_MNEMONIC_VUNPCKHPD:
  case ZYDIS_MNEMONIC_UNPCKHPS:
  case ZYDIS_MNEMONIC_VUNPCKHPS:
  case ZYDIS_MNEMONIC_PUNPCKLBW:
  case ZYDIS_MNEMONIC_VPUNPCKLBW:
  case ZYDIS_MNEMONIC_PUNPCKLWD:
  case ZYDIS_MNEMONIC_VPUNPCKLWD:
  case ZYDIS_MNEMONIC_PUNPCKLDQ:
  case ZYDIS_MNEMONIC_VPUNPCKLDQ:
  case ZYDIS_MNEMONIC_PUNPCKLQDQ:
  case ZYDIS_MNEMONIC_VPUNPCKLQDQ:
  case ZYDIS_MNEMONIC_UNPCKLPD:
  case ZYDIS_MNEMONIC_VUNPCKLPD:
  case ZYDIS_MNEMONIC_UNPCKLPS:
  case ZYDIS_MNEMONIC_VUNPCKLPS:
  case ZYDIS_MNEMONIC_PXOR:
  case ZYDIS_MNEMONIC_VPXOR:
  case ZYDIS_MNEMONIC_XORPS:
  case ZYDIS_MNEMONIC_VXORPS:
  case ZYDIS_MNEMONIC_XORPD:
  case ZYDIS_MNEMONIC_VXORPD:
  case ZYDIS_MNEMONIC_VZEROALL:
  case ZYDIS_MNEMONIC_VZEROUPPER:
  case ZYDIS_MNEMONIC_VP2INTERSECTD:
  case ZYDIS_MNEMONIC_VP2INTERSECTQ:
  case ZYDIS_MNEMONIC_VP4DPWSSD:
  case ZYDIS_MNEMONIC_VP4DPWSSDS:
  case ZYDIS_MNEMONIC_V4FMADDPS:
  case ZYDIS_MNEMONIC_V4FMADDSS:
  case ZYDIS_MNEMONIC_V4FNMADDPS:
  case ZYDIS_MNEMONIC_V4FNMADDSS:
  case ZYDIS_MNEMONIC_VPABSQ:
  case ZYDIS_MNEMONIC_VADDPH:
  case ZYDIS_MNEMONIC_VADDSH:
  case ZYDIS_MNEMONIC_PADDUSW:
  case ZYDIS_MNEMONIC_VPADDUSW:
  case ZYDIS_MNEMONIC_PADDUSB:
  case ZYDIS_MNEMONIC_VPADDUSB:
  case ZYDIS_MNEMONIC_VALIGND:
  case ZYDIS_MNEMONIC_VALIGNQ:
  case ZYDIS_MNEMONIC_VANDNPS:
  case ZYDIS_MNEMONIC_VANDNPD:
  case ZYDIS_MNEMONIC_VPSHUFBITQMB:
  case ZYDIS_MNEMONIC_VPBLENDMB:
  case ZYDIS_MNEMONIC_VPBLENDMW:
  case ZYDIS_MNEMONIC_VPBLENDMD:
  case ZYDIS_MNEMONIC_VPBLENDMQ:
  case ZYDIS_MNEMONIC_VBLENDMPS:
  case ZYDIS_MNEMONIC_VBLENDMPD:
  case ZYDIS_MNEMONIC_VPCMPB:
  case ZYDIS_MNEMONIC_VPCMPW:
  case ZYDIS_MNEMONIC_VPCMPD:
  case ZYDIS_MNEMONIC_VPCMPQ:
  case ZYDIS_MNEMONIC_VPCMPUB:
  case ZYDIS_MNEMONIC_VPCMPUW:
  case ZYDIS_MNEMONIC_VPCMPUD:
  case ZYDIS_MNEMONIC_VPCMPUQ:
  case ZYDIS_MNEMONIC_VCMPPH:
  case ZYDIS_MNEMONIC_VFCMULCPH:
  case ZYDIS_MNEMONIC_VFCMULCSH:
  case ZYDIS_MNEMONIC_VPCOMPRESSB:
  case ZYDIS_MNEMONIC_VPCOMPRESSW:
  case ZYDIS_MNEMONIC_VPCOMPRESSD:
  case ZYDIS_MNEMONIC_VPCOMPRESSQ:
  case ZYDIS_MNEMONIC_VCOMPRESSPD:
  case ZYDIS_MNEMONIC_VCOMPRESSPS:
  case ZYDIS_MNEMONIC_VPCONFLICTD:
  case ZYDIS_MNEMONIC_VPCONFLICTQ:
  case ZYDIS_MNEMONIC_VCVTW2PH:
  case ZYDIS_MNEMONIC_VCVTDQ2PH:
  case ZYDIS_MNEMONIC_VCVTQQ2PH:
  case ZYDIS_MNEMONIC_VCVTPD2PH:
  case ZYDIS_MNEMONIC_VCVTUW2PH:
  case ZYDIS_MNEMONIC_VCVTUDQ2PH:
  case ZYDIS_MNEMONIC_VCVTUQQ2PH:
  case ZYDIS_MNEMONIC_VCVTQQ2PS:
  case ZYDIS_MNEMONIC_VCVTQQ2PD:
  case ZYDIS_MNEMONIC_VCVTPH2PD:
  case ZYDIS_MNEMONIC_VCVTPH2W:
  case ZYDIS_MNEMONIC_VCVTPH2DQ:
  case ZYDIS_MNEMONIC_VCVTPH2QQ:
  case ZYDIS_MNEMONIC_VCVTPH2UW:
  case ZYDIS_MNEMONIC_VCVTPH2UDQ:
  case ZYDIS_MNEMONIC_VCVTPH2UQQ:
  case ZYDIS_MNEMONIC_VCVTPD2QQ:
  case ZYDIS_MNEMONIC_VCVTPS2QQ:
  case ZYDIS_MNEMONIC_VCVTUDQ2PS:
  case ZYDIS_MNEMONIC_VCVTUQQ2PS:
  case ZYDIS_MNEMONIC_VCVTPS2UDQ:
  case ZYDIS_MNEMONIC_VCVTPS2UQQ:
  case ZYDIS_MNEMONIC_VCVTUDQ2PD:
  case ZYDIS_MNEMONIC_VCVTUQQ2PD:
  case ZYDIS_MNEMONIC_VCVTPD2UDQ:
  case ZYDIS_MNEMONIC_VCVTPD2UQQ:
  case ZYDIS_MNEMONIC_VCVTSI2SH:
  case ZYDIS_MNEMONIC_VCVTUSI2SH:
  case ZYDIS_MNEMONIC_VCVTSS2SH:
  case ZYDIS_MNEMONIC_VCVTSD2SH:
  case ZYDIS_MNEMONIC_VCVTSH2SI:
  case ZYDIS_MNEMONIC_VCVTSH2USI:
  case ZYDIS_MNEMONIC_VCVTSH2SS:
  case ZYDIS_MNEMONIC_VCVTSH2SD:
  case ZYDIS_MNEMONIC_VPMOVQB:
  case ZYDIS_MNEMONIC_VPMOVDB:
  case ZYDIS_MNEMONIC_VPMOVWB:
  case ZYDIS_MNEMONIC_VPMOVQW:
  case ZYDIS_MNEMONIC_VPMOVDW:
  case ZYDIS_MNEMONIC_VPMOVQD:
  case ZYDIS_MNEMONIC_VCVTNE2PS2BF16:
  case ZYDIS_MNEMONIC_VCVTSD2USI:
  case ZYDIS_MNEMONIC_VCVTSS2USI:
  case ZYDIS_MNEMONIC_VCVTUSI2SD:
  case ZYDIS_MNEMONIC_VCVTUSI2SS:
  case ZYDIS_MNEMONIC_VPMOVSWB:
  case ZYDIS_MNEMONIC_VPMOVSDB:
  case ZYDIS_MNEMONIC_VPMOVSQB:
  case ZYDIS_MNEMONIC_VPMOVSDW:
  case ZYDIS_MNEMONIC_VPMOVSQW:
  case ZYDIS_MNEMONIC_VPMOVSQD:
  case ZYDIS_MNEMONIC_VCVTTSD2SI:
  case ZYDIS_MNEMONIC_VCVTTSD2USI:
  case ZYDIS_MNEMONIC_CVTTSS2SI:
  case ZYDIS_MNEMONIC_VCVTTSS2SI:
  case ZYDIS_MNEMONIC_VCVTTSS2USI:
  case ZYDIS_MNEMONIC_VCVTTSH2SI:
  case ZYDIS_MNEMONIC_VCVTTSH2USI:
  case ZYDIS_MNEMONIC_VCVTTPH2QQ:
  case ZYDIS_MNEMONIC_VCVTTPS2QQ:
  case ZYDIS_MNEMONIC_VCVTTPD2QQ:
  case ZYDIS_MNEMONIC_VCVTTPH2DQ:
  case ZYDIS_MNEMONIC_VCVTTPH2W:
  case ZYDIS_MNEMONIC_VCVTTPH2UQQ:
  case ZYDIS_MNEMONIC_VCVTTPS2UQQ:
  case ZYDIS_MNEMONIC_VCVTTPD2UQQ:
  case ZYDIS_MNEMONIC_VCVTTPD2UDQ:
  case ZYDIS_MNEMONIC_VCVTTPS2UDQ:
  case ZYDIS_MNEMONIC_VCVTTPH2UDQ:
  case ZYDIS_MNEMONIC_VCVTTPH2UW:
  case ZYDIS_MNEMONIC_VPMOVUSWB:
  case ZYDIS_MNEMONIC_VPMOVUSDB:
  case ZYDIS_MNEMONIC_VPMOVUSQB:
  case ZYDIS_MNEMONIC_VPMOVUSDW:
  case ZYDIS_MNEMONIC_VPMOVUSQW:
  case ZYDIS_MNEMONIC_VPMOVUSQD:
  case ZYDIS_MNEMONIC_VCVTPH2PSX:
  case ZYDIS_MNEMONIC_VCVTPS2PHX:
  case ZYDIS_MNEMONIC_VDBPSADBW:
  case ZYDIS_MNEMONIC_VDIVPH:
  case ZYDIS_MNEMONIC_VDIVSH:
  case ZYDIS_MNEMONIC_VDPBF16PS:
  case ZYDIS_MNEMONIC_VEXP2PD:
  case ZYDIS_MNEMONIC_VEXP2PS:
  case ZYDIS_MNEMONIC_VPEXPANDB:
  case ZYDIS_MNEMONIC_VPEXPANDW:
  case ZYDIS_MNEMONIC_VPEXPANDD:
  case ZYDIS_MNEMONIC_VPEXPANDQ:
  case ZYDIS_MNEMONIC_VEXPANDPS:
  case ZYDIS_MNEMONIC_VEXPANDPD:
  case ZYDIS_MNEMONIC_VEXTRACTF32X4:
  case ZYDIS_MNEMONIC_VEXTRACTF32X8:
  case ZYDIS_MNEMONIC_VEXTRACTF64X2:
  case ZYDIS_MNEMONIC_VEXTRACTF64X4:
  case ZYDIS_MNEMONIC_VEXTRACTI32X4:
  case ZYDIS_MNEMONIC_VEXTRACTI32X8:
  case ZYDIS_MNEMONIC_VEXTRACTI64X2:
  case ZYDIS_MNEMONIC_VEXTRACTI64X4:
  case ZYDIS_MNEMONIC_VFCMADDCPH:
  case ZYDIS_MNEMONIC_VFCMADDCSH:
  case ZYDIS_MNEMONIC_VFIXUPIMMPD:
  case ZYDIS_MNEMONIC_VFIXUPIMMPS:
  case ZYDIS_MNEMONIC_VFIXUPIMMSD:
  case ZYDIS_MNEMONIC_VFIXUPIMMSS:
  case ZYDIS_MNEMONIC_VFMADDCPH:
  case ZYDIS_MNEMONIC_VFMADDCSH:
  case ZYDIS_MNEMONIC_VFMADD132PH:
  case ZYDIS_MNEMONIC_VFMADD213PH:
  case ZYDIS_MNEMONIC_VFMADD231PH:
  case ZYDIS_MNEMONIC_VFMADD132SH:
  case ZYDIS_MNEMONIC_VFMADD213SH:
  case ZYDIS_MNEMONIC_VFMADD231SH:
  case ZYDIS_MNEMONIC_VFMADDSUB132PH:
  case ZYDIS_MNEMONIC_VFMADDSUB213PH:
  case ZYDIS_MNEMONIC_VFMADDSUB231PH:
  case ZYDIS_MNEMONIC_VFMSUB132PH:
  case ZYDIS_MNEMONIC_VFMSUB213PH:
  case ZYDIS_MNEMONIC_VFMSUB231PH:
  case ZYDIS_MNEMONIC_VFMSUB132SH:
  case ZYDIS_MNEMONIC_VFMSUB213SH:
  case ZYDIS_MNEMONIC_VFMSUB231SH:
  case ZYDIS_MNEMONIC_VFMSUBADD132PH:
  case ZYDIS_MNEMONIC_VFMSUBADD213PH:
  case ZYDIS_MNEMONIC_VFMSUBADD231PH:
  case ZYDIS_MNEMONIC_VFMULCPH:
  case ZYDIS_MNEMONIC_VFMULCSH:
  case ZYDIS_MNEMONIC_VFNMADD132PH:
  case ZYDIS_MNEMONIC_VFNMADD213PH:
  case ZYDIS_MNEMONIC_VFNMADD231PH:
  case ZYDIS_MNEMONIC_VFNMADD132SH:
  case ZYDIS_MNEMONIC_VFNMADD213SH:
  case ZYDIS_MNEMONIC_VFNMADD231SH:
  case ZYDIS_MNEMONIC_VFNMSUB132PH:
  case ZYDIS_MNEMONIC_VFNMSUB213PH:
  case ZYDIS_MNEMONIC_VFNMSUB231PH:
  case ZYDIS_MNEMONIC_VFNMSUB132SH:
  case ZYDIS_MNEMONIC_VFNMSUB213SH:
  case ZYDIS_MNEMONIC_VFNMSUB231SH:
  case ZYDIS_MNEMONIC_VFPCLASSPD:
  case ZYDIS_MNEMONIC_VFPCLASSPS:
  case ZYDIS_MNEMONIC_VFPCLASSPH:
  case ZYDIS_MNEMONIC_VGETEXPPD:
  case ZYDIS_MNEMONIC_VGETEXPPS:
  case ZYDIS_MNEMONIC_VGETEXPPH:
  case ZYDIS_MNEMONIC_VGETEXPSD:
  case ZYDIS_MNEMONIC_VGETEXPSS:
  case ZYDIS_MNEMONIC_VGETEXPSH:
  case ZYDIS_MNEMONIC_VGETMANTPD:
  case ZYDIS_MNEMONIC_VGETMANTPS:
  case ZYDIS_MNEMONIC_VGETMANTPH:
  case ZYDIS_MNEMONIC_VGETMANTSD:
  case ZYDIS_MNEMONIC_VGETMANTSS:
  case ZYDIS_MNEMONIC_VGETMANTSH:
  case ZYDIS_MNEMONIC_VPSCATTERDD:
  case ZYDIS_MNEMONIC_VPSCATTERDQ:
  case ZYDIS_MNEMONIC_VPSCATTERQD:
  case ZYDIS_MNEMONIC_VPSCATTERQQ:
  case ZYDIS_MNEMONIC_VSCATTERDPS:
  case ZYDIS_MNEMONIC_VSCATTERDPD:
  case ZYDIS_MNEMONIC_VSCATTERQPS:
  case ZYDIS_MNEMONIC_VSCATTERQPD:
  case ZYDIS_MNEMONIC_VINSERTF32X4:
  case ZYDIS_MNEMONIC_VINSERTF32X8:
  case ZYDIS_MNEMONIC_VINSERTF64X2:
  case ZYDIS_MNEMONIC_VINSERTF64X4:
  case ZYDIS_MNEMONIC_VINSERTI32X4:
  case ZYDIS_MNEMONIC_VINSERTI32X8:
  case ZYDIS_MNEMONIC_VINSERTI64X2:
  case ZYDIS_MNEMONIC_VINSERTI64X4:
  case ZYDIS_MNEMONIC_KANDNB:
  case ZYDIS_MNEMONIC_KANDNW:
  case ZYDIS_MNEMONIC_KANDND:
  case ZYDIS_MNEMONIC_KANDNQ:
  case ZYDIS_MNEMONIC_KNOTB:
  case ZYDIS_MNEMONIC_KNOTW:
  case ZYDIS_MNEMONIC_KNOTD:
  case ZYDIS_MNEMONIC_KNOTQ:
  case ZYDIS_MNEMONIC_KUNPCKBW:
  case ZYDIS_MNEMONIC_KUNPCKWD:
  case ZYDIS_MNEMONIC_KUNPCKDQ:
  case ZYDIS_MNEMONIC_KXNORB:
  case ZYDIS_MNEMONIC_KXNORW:
  case ZYDIS_MNEMONIC_KXNORD:
  case ZYDIS_MNEMONIC_KXNORQ:
  case ZYDIS_MNEMONIC_VPLZCNTD:
  case ZYDIS_MNEMONIC_VPLZCNTQ:
  case ZYDIS_MNEMONIC_VMAXPH:
  case ZYDIS_MNEMONIC_VMAXSH:
  case ZYDIS_MNEMONIC_VMINPH:
  case ZYDIS_MNEMONIC_VMINSH:
  case ZYDIS_MNEMONIC_VPMOVB2M:
  case ZYDIS_MNEMONIC_VPMOVW2M:
  case ZYDIS_MNEMONIC_VPMOVD2M:
  case ZYDIS_MNEMONIC_VPMOVQ2M:
  case ZYDIS_MNEMONIC_VPMOVM2B:
  case ZYDIS_MNEMONIC_VPMOVM2W:
  case ZYDIS_MNEMONIC_VPMOVM2D:
  case ZYDIS_MNEMONIC_VPMOVM2Q:
  case ZYDIS_MNEMONIC_VMULPH:
  case ZYDIS_MNEMONIC_VMULSH:
  case ZYDIS_MNEMONIC_VSUBPH:
  case ZYDIS_MNEMONIC_VSUBSH:
  case ZYDIS_MNEMONIC_VCMPSH:
  case ZYDIS_MNEMONIC_VPMULHUW:
  case ZYDIS_MNEMONIC_VPMULHUD:
  case ZYDIS_MNEMONIC_VPMULLQ:
  case ZYDIS_MNEMONIC_VPMULTISHIFTQB:
  case ZYDIS_MNEMONIC_VPERMT2B:
  case ZYDIS_MNEMONIC_VPERMT2W:
  case ZYDIS_MNEMONIC_VPERMT2D:
  case ZYDIS_MNEMONIC_VPERMT2Q:
  case ZYDIS_MNEMONIC_VPERMT2PS:
  case ZYDIS_MNEMONIC_VPERMT2PD:
  case ZYDIS_MNEMONIC_VPERMB:
  case ZYDIS_MNEMONIC_VPERMW:
  case ZYDIS_MNEMONIC_VPERMD:
  case ZYDIS_MNEMONIC_VPOPCNTB:
  case ZYDIS_MNEMONIC_VPOPCNTW:
  case ZYDIS_MNEMONIC_VPOPCNTD:
  case ZYDIS_MNEMONIC_VPOPCNTQ:
  case ZYDIS_MNEMONIC_VRANGEPD:
  case ZYDIS_MNEMONIC_VRANGEPS:
  case ZYDIS_MNEMONIC_VRANGESD:
  case ZYDIS_MNEMONIC_VRANGESS:
  case ZYDIS_MNEMONIC_VRCPPH:
  case ZYDIS_MNEMONIC_VRCPSH:
  case ZYDIS_MNEMONIC_VRCP14PD:
  case ZYDIS_MNEMONIC_VRCP14PS:
  case ZYDIS_MNEMONIC_VRCP14SD:
  case ZYDIS_MNEMONIC_VRCP14SS:
  case ZYDIS_MNEMONIC_VRCP28PD:
  case ZYDIS_MNEMONIC_VRCP28PS:
  case ZYDIS_MNEMONIC_VRCP28SD:
  case ZYDIS_MNEMONIC_VRCP28SS:
  case ZYDIS_MNEMONIC_VREDUCEPD:
  case ZYDIS_MNEMONIC_VREDUCEPS:
  case ZYDIS_MNEMONIC_VREDUCEPH:
  case ZYDIS_MNEMONIC_VREDUCESD:
  case ZYDIS_MNEMONIC_VREDUCESS:
  case ZYDIS_MNEMONIC_VREDUCESH:
  case ZYDIS_MNEMONIC_VPROLD:
  case ZYDIS_MNEMONIC_VPROLQ:
  case ZYDIS_MNEMONIC_VPROLVD:
  case ZYDIS_MNEMONIC_VPROLVQ:
  case ZYDIS_MNEMONIC_VPRORD:
  case ZYDIS_MNEMONIC_VPRORQ:
  case ZYDIS_MNEMONIC_VPRORVD:
  case ZYDIS_MNEMONIC_VPRORVQ:
  case ZYDIS_MNEMONIC_VRNDSCALEPD:
  case ZYDIS_MNEMONIC_VRNDSCALEPS:
  case ZYDIS_MNEMONIC_VRNDSCALEPH:
  case ZYDIS_MNEMONIC_VRNDSCALESD:
  case ZYDIS_MNEMONIC_VRNDSCALESS:
  case ZYDIS_MNEMONIC_VRNDSCALESH:
  case ZYDIS_MNEMONIC_VRSQRTPH:
  case ZYDIS_MNEMONIC_VRSQRTSH:
  case ZYDIS_MNEMONIC_VRSQRT14PD:
  case ZYDIS_MNEMONIC_VRSQRT14PS:
  case ZYDIS_MNEMONIC_VRSQRT14SD:
  case ZYDIS_MNEMONIC_VRSQRT14SS:
  case ZYDIS_MNEMONIC_VRSQRT28PD:
  case ZYDIS_MNEMONIC_VRSQRT28PS:
  case ZYDIS_MNEMONIC_VRSQRT28SD:
  case ZYDIS_MNEMONIC_VRSQRT28SS:
  case ZYDIS_MNEMONIC_VSCALEFPD:
  case ZYDIS_MNEMONIC_VSCALEFPS:
  case ZYDIS_MNEMONIC_VSCALEFPH:
  case ZYDIS_MNEMONIC_VSCALEFSD:
  case ZYDIS_MNEMONIC_VSCALEFSS:
  case ZYDIS_MNEMONIC_VSCALEFSH:
  case ZYDIS_MNEMONIC_VPXORQ:
  case ZYDIS_MNEMONIC_VPXORD:
  case ZYDIS_MNEMONIC_VPSHLB:
  case ZYDIS_MNEMONIC_VPSHLW:
  case ZYDIS_MNEMONIC_VPSHLD:
  case ZYDIS_MNEMONIC_VPSHLQ:
  case ZYDIS_MNEMONIC_VPSHLDW:
  case ZYDIS_MNEMONIC_VPSHLDD:
  case ZYDIS_MNEMONIC_VPSHLDQ:
  case ZYDIS_MNEMONIC_VPSHLDVW:
  case ZYDIS_MNEMONIC_VPSHLDVD:
  case ZYDIS_MNEMONIC_VPSHLDVQ:
  case ZYDIS_MNEMONIC_VPSHRDW:
  case ZYDIS_MNEMONIC_VPSHRDD:
  case ZYDIS_MNEMONIC_VPSHRDQ:
  case ZYDIS_MNEMONIC_VPSHRDVW:
  case ZYDIS_MNEMONIC_VPSHRDVD:
  case ZYDIS_MNEMONIC_VPSHRDVQ:
  case ZYDIS_MNEMONIC_VSHUFF32X4:
  case ZYDIS_MNEMONIC_VSHUFF64X2:
  case ZYDIS_MNEMONIC_VSHUFI32X4:
  case ZYDIS_MNEMONIC_VSHUFI64X2:
  case ZYDIS_MNEMONIC_VPSLLVW:
  case ZYDIS_MNEMONIC_VSQRTPH:
  case ZYDIS_MNEMONIC_VSQRTSH:
  case ZYDIS_MNEMONIC_VPSUBRD:
  case ZYDIS_MNEMONIC_VPSUBUSB:
  case ZYDIS_MNEMONIC_VPSUBUSW:
  case ZYDIS_MNEMONIC_VPTERNLOGD:
  case ZYDIS_MNEMONIC_VPTERNLOGQ:
  case ZYDIS_MNEMONIC_VPTESTMB:
  case ZYDIS_MNEMONIC_VPTESTMW:
  case ZYDIS_MNEMONIC_VPTESTMD:
  case ZYDIS_MNEMONIC_VPTESTMQ:
  case ZYDIS_MNEMONIC_VPTESTNMB:
  case ZYDIS_MNEMONIC_VPTESTNMW:
  case ZYDIS_MNEMONIC_VPTESTNMD:
  case ZYDIS_MNEMONIC_VPTESTNMQ:
  case ZYDIS_MNEMONIC_VUCOMISH:
  {
    if (pInstruction->operand_count > 1)
    {
      ERROR_CHECK(zydec_WriteResultOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress, pInfo));
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));
    }

    bool addressParam = false;
    bool maySelfReference = true;

    if (simplifyShorthands)
    {
      if (pInstruction->operand_count == 3 && pOperands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && pOperands[2].type == ZYDIS_OPERAND_TYPE_REGISTER && pOperands[1].reg.value == pOperands[2].reg.value)
      {
        bool match = false;

        switch (pInstruction->mnemonic)
        {
        case ZYDIS_MNEMONIC_PAND:
        case ZYDIS_MNEMONIC_VPAND:
        case ZYDIS_MNEMONIC_VPANDQ:
        case ZYDIS_MNEMONIC_VPANDD:
        case ZYDIS_MNEMONIC_POR:
        case ZYDIS_MNEMONIC_VPOR:
        case ZYDIS_MNEMONIC_VPORD:
        case ZYDIS_MNEMONIC_VPORQ:
        case ZYDIS_MNEMONIC_ORPD:
        case ZYDIS_MNEMONIC_VORPD:
        case ZYDIS_MNEMONIC_ORPS:
        case ZYDIS_MNEMONIC_VORPS:
          match = true;
          ERROR_CHECK(zydec_WriteRegister(&bufferPos, &remainingSize, pOperands[1].reg.value, pInfo, false));
          break;

        case ZYDIS_MNEMONIC_PXOR:
        case ZYDIS_MNEMONIC_VPXOR:
        case ZYDIS_MNEMONIC_XORPS:
        case ZYDIS_MNEMONIC_VXORPS:
        case ZYDIS_MNEMONIC_XORPD:
        case ZYDIS_MNEMONIC_VXORPD:
        case ZYDIS_MNEMONIC_VPXORQ:
        case ZYDIS_MNEMONIC_VPXORD:
          match = true;
          ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "0"));
          break;

        case ZYDIS_MNEMONIC_PCMPEQB:
        case ZYDIS_MNEMONIC_VPCMPEQB:
        case ZYDIS_MNEMONIC_PCMPEQW:
        case ZYDIS_MNEMONIC_VPCMPEQW:
        case ZYDIS_MNEMONIC_PCMPEQD:
        case ZYDIS_MNEMONIC_VPCMPEQD:
        case ZYDIS_MNEMONIC_PCMPEQQ:
        case ZYDIS_MNEMONIC_VPCMPEQQ:
          match = true;
          ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "-1"));
          break;

        default:
          break;
        }

        if (match)
        {
          ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ";"));
          return true;
        }
      }
    }

    switch (pInstruction->mnemonic)
    {
    case ZYDIS_MNEMONIC_PAND:
    case ZYDIS_MNEMONIC_VPAND:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_and_si("));
      break;

    case ZYDIS_MNEMONIC_VPANDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_and_epi64("));
      break;

    case ZYDIS_MNEMONIC_VPANDD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_and_epi32("));
      break;

    case ZYDIS_MNEMONIC_PANDN:
    case ZYDIS_MNEMONIC_VPANDN:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_andnot_si("));
      break;

    case ZYDIS_MNEMONIC_VPANDNQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_andnot_epi64("));
      break;

    case ZYDIS_MNEMONIC_VPANDND:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_andnot_epi32("));
      break;

    case ZYDIS_MNEMONIC_VANDNPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_andnot_ps("));
      break;

    case ZYDIS_MNEMONIC_VANDNPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_andnot_pd("));
      break;

    case ZYDIS_MNEMONIC_PCMPEQB:
    case ZYDIS_MNEMONIC_VPCMPEQB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmpeq_epi8("));
      break;

    case ZYDIS_MNEMONIC_PCMPEQW:
    case ZYDIS_MNEMONIC_VPCMPEQW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmpeq_epi16("));
      break;

    case ZYDIS_MNEMONIC_PCMPEQD:
    case ZYDIS_MNEMONIC_VPCMPEQD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmpeq_epi32("));
      break;

    case ZYDIS_MNEMONIC_PCMPEQQ:
    case ZYDIS_MNEMONIC_VPCMPEQQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmpeq_epi64("));
      break;

    case ZYDIS_MNEMONIC_PCMPGTB:
    case ZYDIS_MNEMONIC_VPCMPGTB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmpgt_epi8("));
      break;

    case ZYDIS_MNEMONIC_PCMPGTW:
    case ZYDIS_MNEMONIC_VPCMPGTW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmpgt_epi16("));
      break;

    case ZYDIS_MNEMONIC_PCMPGTD:
    case ZYDIS_MNEMONIC_VPCMPGTD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmpgt_epi32("));
      break;

    case ZYDIS_MNEMONIC_PCMPGTQ:
    case ZYDIS_MNEMONIC_VPCMPGTQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmpgt_epi64("));
      break;

    case ZYDIS_MNEMONIC_PACKUSWB:
    case ZYDIS_MNEMONIC_VPACKUSWB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_packus_epu16_to_epi8("));
      break;

    case ZYDIS_MNEMONIC_PACKUSDW:
    case ZYDIS_MNEMONIC_VPACKUSDW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_packus_epu32_to_epi16("));
      break;

    case ZYDIS_MNEMONIC_PACKSSWB:
    case ZYDIS_MNEMONIC_VPACKSSWB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_packs_epu16_to_epi8("));
      break;

    case ZYDIS_MNEMONIC_PACKSSDW:
    case ZYDIS_MNEMONIC_VPACKSSDW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_packs_epu32_to_epi16("));
      break;

    case ZYDIS_MNEMONIC_PADDB:
    case ZYDIS_MNEMONIC_VPADDB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_add_epi8("));
      break;

    case ZYDIS_MNEMONIC_PADDW:
    case ZYDIS_MNEMONIC_VPADDW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_add_epi16("));
      break;

    case ZYDIS_MNEMONIC_PADDD:
    case ZYDIS_MNEMONIC_VPADDD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_add_epi32("));
      break;

    case ZYDIS_MNEMONIC_PADDQ:
    case ZYDIS_MNEMONIC_VPADDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_add_epi64("));
      break;

    case ZYDIS_MNEMONIC_ADDPS:
    case ZYDIS_MNEMONIC_VADDPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_add_ps("));
      break;

    case ZYDIS_MNEMONIC_ADDPD:
    case ZYDIS_MNEMONIC_VADDPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_add_pd("));
      break;

    case ZYDIS_MNEMONIC_ADDSS:
    case ZYDIS_MNEMONIC_VADDSS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_add_ss("));
      break;

    case ZYDIS_MNEMONIC_ADDSD:
    case ZYDIS_MNEMONIC_VADDSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_add_sd("));
      break;

    case ZYDIS_MNEMONIC_PADDSB:
    case ZYDIS_MNEMONIC_PADDSW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_adds_epi8("));
      break;

    case ZYDIS_MNEMONIC_VPADDSB:
    case ZYDIS_MNEMONIC_VPADDSW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_adds_epi16("));
      break;

    case ZYDIS_MNEMONIC_EMMS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_empty("));
      break;

    case ZYDIS_MNEMONIC_PMADDWD:
    case ZYDIS_MNEMONIC_VPMADDWD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_pmadd_epi16("));
      break;

    case ZYDIS_MNEMONIC_PMULHW:
    case ZYDIS_MNEMONIC_VPMULHW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mulhi_epi16("));
      break;

    case ZYDIS_MNEMONIC_PMULLW:
    case ZYDIS_MNEMONIC_VPMULLW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mullo_epi16("));
      break;

    case ZYDIS_MNEMONIC_POR:
    case ZYDIS_MNEMONIC_VPOR:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_or_si("));
      break;

    case ZYDIS_MNEMONIC_VPORD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_or_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPORQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_or_epi64("));
      break;

    case ZYDIS_MNEMONIC_PABSB:
    case ZYDIS_MNEMONIC_VPABSB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_abs_epi16("));
      break;

    case ZYDIS_MNEMONIC_PABSW:
    case ZYDIS_MNEMONIC_VPABSW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_abs_epi16("));
      break;

    case ZYDIS_MNEMONIC_PABSD:
    case ZYDIS_MNEMONIC_VPABSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_abs_epi32("));
      break;

    case ZYDIS_MNEMONIC_ADDSUBPS:
    case ZYDIS_MNEMONIC_VADDSUBPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_addsub_ps("));
      break;
      
    case ZYDIS_MNEMONIC_ADDSUBPD:
    case ZYDIS_MNEMONIC_VADDSUBPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_addsub_pd("));
      break;
      
    case ZYDIS_MNEMONIC_PALIGNR:
    case ZYDIS_MNEMONIC_VPALIGNR:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_alignr_epi8("));
      break;

    case ZYDIS_MNEMONIC_PAVGB:
    case ZYDIS_MNEMONIC_VPAVGB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_avg_epu8("));
      break;

    case ZYDIS_MNEMONIC_PAVGW:
    case ZYDIS_MNEMONIC_VPAVGW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_avg_epu16("));
      break;

    case ZYDIS_MNEMONIC_PBLENDW:
    case ZYDIS_MNEMONIC_VPBLENDW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_blend_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPBLENDD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_blend_epi32("));
      break;

    case ZYDIS_MNEMONIC_BLENDPS:
    case ZYDIS_MNEMONIC_VBLENDPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_blend_ps("));
      break;

    case ZYDIS_MNEMONIC_BLENDPD:
    case ZYDIS_MNEMONIC_VBLENDPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_blend_pd("));
      break;

    case ZYDIS_MNEMONIC_PBLENDVB:
    case ZYDIS_MNEMONIC_VPBLENDVB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_blendv_epi8("));
      break;

    case ZYDIS_MNEMONIC_BLENDVPS:
    case ZYDIS_MNEMONIC_VBLENDVPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_blendv_ps("));
      break;

    case ZYDIS_MNEMONIC_BLENDVPD:
    case ZYDIS_MNEMONIC_VBLENDVPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_blendv_pd("));
      break;

    case ZYDIS_MNEMONIC_VBROADCASTF128:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_broadcast_f128("));
      break;
      
    case ZYDIS_MNEMONIC_VBROADCASTF32X2:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_broadcast_f32x2("));
      break;

    case ZYDIS_MNEMONIC_VBROADCASTF32X4:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_broadcast_f32x4("));
      break;

    case ZYDIS_MNEMONIC_VBROADCASTF32X8:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_broadcast_f32x8("));
      break;

    case ZYDIS_MNEMONIC_VBROADCASTF64X2:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_broadcast_f64x2("));
      break;

    case ZYDIS_MNEMONIC_VBROADCASTF64X4:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_broadcast_f64x4("));
      break;

    case ZYDIS_MNEMONIC_VBROADCASTI128:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_broadcastsi128_si256("));
      break;

    case ZYDIS_MNEMONIC_VBROADCASTI32X2:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_broadcast_i32x2("));
      break;

    case ZYDIS_MNEMONIC_VBROADCASTI32X4:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_broadcast_i32x4("));
      break;

    case ZYDIS_MNEMONIC_VBROADCASTI32X8:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_broadcast_i32x8("));
      break;

    case ZYDIS_MNEMONIC_VBROADCASTI64X2:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_broadcast_i64x2("));
      break;

    case ZYDIS_MNEMONIC_VBROADCASTI64X4:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_broadcast_i64x4("));
      break;
    
    case ZYDIS_MNEMONIC_VBROADCASTSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_broadcast_sd("));
      break;
      
    case ZYDIS_MNEMONIC_VBROADCASTSS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_broadcast_ss("));
      break;
      
    case ZYDIS_MNEMONIC_VPBROADCASTB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_broadcast_epi8("));
      break;

    case ZYDIS_MNEMONIC_VPBROADCASTW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_broadcast_epi16("));
      break;
      
    case ZYDIS_MNEMONIC_VPBROADCASTD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_broadcast_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPBROADCASTQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_broadcast_epi64("));
      break;
      
    case ZYDIS_MNEMONIC_VPBROADCASTMB2Q:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_broadcastmb_epi64("));
      break;

    case ZYDIS_MNEMONIC_VPBROADCASTMW2D:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_broadcastmw_epi32("));
      break;

    case ZYDIS_MNEMONIC_PSLLDQ:
    case ZYDIS_MNEMONIC_VPSLLDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_bslli_epi128("));
      break;

    case ZYDIS_MNEMONIC_PSRLDQ:
    case ZYDIS_MNEMONIC_VPSRLDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_bsrli_epi128("));
      break;

    case ZYDIS_MNEMONIC_ROUNDSS:
    case ZYDIS_MNEMONIC_VROUNDSS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_round_ss("));
      break;

    case ZYDIS_MNEMONIC_ROUNDSD:
    case ZYDIS_MNEMONIC_VROUNDSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_round_sd("));
      break;

    case ZYDIS_MNEMONIC_ROUNDPS:
    case ZYDIS_MNEMONIC_VROUNDPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_round_ps("));
      break;

    case ZYDIS_MNEMONIC_ROUNDPD:
    case ZYDIS_MNEMONIC_VROUNDPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_round_pd("));
      break;

    case ZYDIS_MNEMONIC_CLFLUSH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_clflush("));
      addressParam = true;
      break;

    case ZYDIS_MNEMONIC_CLFLUSHOPT:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_clflushopt("));
      addressParam = true;
      break;

    case ZYDIS_MNEMONIC_CMPSS:
    case ZYDIS_MNEMONIC_VCMPSS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmp_ss("));
      break;

    case ZYDIS_MNEMONIC_CMPSD:
    case ZYDIS_MNEMONIC_VCMPSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmp_sd("));
      break;

    case ZYDIS_MNEMONIC_CMPPS:
    case ZYDIS_MNEMONIC_VCMPPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmp_ps("));
      break;

    case ZYDIS_MNEMONIC_CMPPD:
    case ZYDIS_MNEMONIC_VCMPPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmp_pd("));
      break;

    case ZYDIS_MNEMONIC_PCMPESTRI:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmpstr("));
      break;

    case ZYDIS_MNEMONIC_PCMPESTRM:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmpestrm("));
      break;

    case ZYDIS_MNEMONIC_COMISS:
    case ZYDIS_MNEMONIC_VCOMISS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_comieq_ss("));
      break;

    case ZYDIS_MNEMONIC_COMISD:
    case ZYDIS_MNEMONIC_VCOMISD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_comieq_sd("));
      break;

    case ZYDIS_MNEMONIC_VCOMISH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_comieq_sh("));
      break;

    case ZYDIS_MNEMONIC_CRC32:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_crc32("));
      break;

    case ZYDIS_MNEMONIC_CVTPI2PS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtpi_ps("));
      break;

    case ZYDIS_MNEMONIC_CVTPS2PI:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtps_pi("));
      break;

    case ZYDIS_MNEMONIC_CVTSI2SS:
    case ZYDIS_MNEMONIC_VCVTSI2SS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsi_ss("));
      break;

    case ZYDIS_MNEMONIC_CVTSS2SI:
    case ZYDIS_MNEMONIC_VCVTSS2SI:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtss_si("));
      break;

    case ZYDIS_MNEMONIC_PMOVSXWD:
    case ZYDIS_MNEMONIC_VPMOVSXWD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepi16_epi32("));
      break;

    case ZYDIS_MNEMONIC_PMOVSXWQ:
    case ZYDIS_MNEMONIC_VPMOVSXWQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepi16_epi64("));
      break;

    case ZYDIS_MNEMONIC_PMOVSXDQ:
    case ZYDIS_MNEMONIC_VPMOVSXDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepi32_epi64("));
      break;

    case ZYDIS_MNEMONIC_CVTDQ2PS:
    case ZYDIS_MNEMONIC_VCVTDQ2PS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepi32_ps("));
      break;

    case ZYDIS_MNEMONIC_CVTDQ2PD:
    case ZYDIS_MNEMONIC_VCVTDQ2PD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepi32_pd("));
      break;

    case ZYDIS_MNEMONIC_PMOVSXBW:
    case ZYDIS_MNEMONIC_VPMOVSXBW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepi8_epi16("));
      break;

    case ZYDIS_MNEMONIC_PMOVSXBD:
    case ZYDIS_MNEMONIC_VPMOVSXBD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepi8_epi32("));
      break;

    case ZYDIS_MNEMONIC_PMOVSXBQ:
    case ZYDIS_MNEMONIC_VPMOVSXBQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepi8_epi64("));
      break;

    case ZYDIS_MNEMONIC_PMOVZXWD:
    case ZYDIS_MNEMONIC_VPMOVZXWD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepu16_epi32("));
      break;

    case ZYDIS_MNEMONIC_PMOVZXWQ:
    case ZYDIS_MNEMONIC_VPMOVZXWQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepu16_epi64("));
      break;

    case ZYDIS_MNEMONIC_PMOVZXDQ:
    case ZYDIS_MNEMONIC_VPMOVZXDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepu32_epi64("));
      break;

    case ZYDIS_MNEMONIC_PMOVZXBW:
    case ZYDIS_MNEMONIC_VPMOVZXBW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepu8_epi16("));
      break;

    case ZYDIS_MNEMONIC_PMOVZXBD:
    case ZYDIS_MNEMONIC_VPMOVZXBD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepu8_epi32("));
      break;

    case ZYDIS_MNEMONIC_PMOVZXBQ:
    case ZYDIS_MNEMONIC_VPMOVZXBQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepu8_epi64("));
      break;

    case ZYDIS_MNEMONIC_VCVTPH2PS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtph_ps("));
      break;

    case ZYDIS_MNEMONIC_VCVTNEPS2BF16:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtneps_pbh("));
      break;

    case ZYDIS_MNEMONIC_CVTPD2DQ:
    case ZYDIS_MNEMONIC_VCVTPD2DQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtpd_epi32("));
      break;

    case ZYDIS_MNEMONIC_CVTPD2PI:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtpd_pi32("));
      break;

    case ZYDIS_MNEMONIC_CVTPD2PS:
    case ZYDIS_MNEMONIC_VCVTPD2PS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtpd_ps("));
      break;

    case ZYDIS_MNEMONIC_CVTPI2PD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtpi32_pd("));
      break;

    case ZYDIS_MNEMONIC_CVTPS2DQ:
    case ZYDIS_MNEMONIC_VCVTPS2DQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtps_epi32("));
      break;

    case ZYDIS_MNEMONIC_CVTPS2PD:
    case ZYDIS_MNEMONIC_VCVTPS2PD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtps_pd("));
      break;

    case ZYDIS_MNEMONIC_VCVTPS2PH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtps_ph("));
      break;

    case ZYDIS_MNEMONIC_CVTSD2SI:
    case ZYDIS_MNEMONIC_VCVTSD2SI:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsd_si("));
      break;

    case ZYDIS_MNEMONIC_CVTSD2SS:
    case ZYDIS_MNEMONIC_VCVTSD2SS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsd_ss("));
      break;

    case ZYDIS_MNEMONIC_CVTSI2SD:
    case ZYDIS_MNEMONIC_VCVTSI2SD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsi_sd("));
      break;

    case ZYDIS_MNEMONIC_CVTSS2SD:
    case ZYDIS_MNEMONIC_VCVTSS2SD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtss_sd("));
      break;

    case ZYDIS_MNEMONIC_CVTTPS2PI:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttps_pi("));
      break;

    case ZYDIS_MNEMONIC_CVTTPD2DQ:
    case ZYDIS_MNEMONIC_VCVTTPD2DQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttpd_epi32("));
      break;

    case ZYDIS_MNEMONIC_CVTTPD2PI:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttpd_pi32("));
      break;

    case ZYDIS_MNEMONIC_CVTTPS2DQ:
    case ZYDIS_MNEMONIC_VCVTTPS2DQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttps_epi32("));
      break;

    case ZYDIS_MNEMONIC_CVTTSD2SI:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttsd_si("));
      break;

    case ZYDIS_MNEMONIC_DIVPD:
    case ZYDIS_MNEMONIC_VDIVPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_div_pd("));
      break;

    case ZYDIS_MNEMONIC_DIVPS:
    case ZYDIS_MNEMONIC_VDIVPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_div_ps("));
      break;

    case ZYDIS_MNEMONIC_DIVSD:
    case ZYDIS_MNEMONIC_VDIVSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_div_sd("));
      break;

    case ZYDIS_MNEMONIC_DIVSS:
    case ZYDIS_MNEMONIC_VDIVSS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_div_ss("));
      break;

    case ZYDIS_MNEMONIC_DPPD:
    case ZYDIS_MNEMONIC_VDPPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_dp_pd("));
      break;

    case ZYDIS_MNEMONIC_DPPS:
    case ZYDIS_MNEMONIC_VDPPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_dp_ps("));
      break;

    case ZYDIS_MNEMONIC_VPDPWSSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_dpwssd_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPDPWSSDS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_dpwssds_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPDPBUSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_dpbusd_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPDPBUSDS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_dpbusds_epi32("));
      break;

    case ZYDIS_MNEMONIC_PEXTRB:
    case ZYDIS_MNEMONIC_VPEXTRB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_extract_epi8("));
      break;

    case ZYDIS_MNEMONIC_PEXTRW:
    case ZYDIS_MNEMONIC_VPEXTRW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_extract_epi16("));
      break;

    case ZYDIS_MNEMONIC_PEXTRD:
    case ZYDIS_MNEMONIC_VPEXTRD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_extract_epi32("));
      break;

    case ZYDIS_MNEMONIC_PEXTRQ:
    case ZYDIS_MNEMONIC_VPEXTRQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_extract_epi64("));
      break;

    case ZYDIS_MNEMONIC_EXTRACTPS:
    case ZYDIS_MNEMONIC_VEXTRACTPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_extract_ps("));
      break;

    case ZYDIS_MNEMONIC_VEXTRACTF128:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_extract_f128("));
      break;

    case ZYDIS_MNEMONIC_VEXTRACTI128:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_extract_i128("));
      break;

    case ZYDIS_MNEMONIC_VFMADD132PD:
    case ZYDIS_MNEMONIC_VFMADD213PD:
    case ZYDIS_MNEMONIC_VFMADD231PD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmadd_pd("));
      break;
      
    case ZYDIS_MNEMONIC_VFMADD132PS:
    case ZYDIS_MNEMONIC_VFMADD213PS:
    case ZYDIS_MNEMONIC_VFMADD231PS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmadd_ps("));
      break;

    case ZYDIS_MNEMONIC_VFMADD132SD:
    case ZYDIS_MNEMONIC_VFMADD213SD:
    case ZYDIS_MNEMONIC_VFMADD231SD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmadd_sd("));
      break;
      
    case ZYDIS_MNEMONIC_VFMADD132SS:
    case ZYDIS_MNEMONIC_VFMADD213SS:
    case ZYDIS_MNEMONIC_VFMADD231SS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmadd_ss("));
      break;

    case ZYDIS_MNEMONIC_VFMADDSUB132PD:
    case ZYDIS_MNEMONIC_VFMADDSUB213PD:
    case ZYDIS_MNEMONIC_VFMADDSUB231PD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmaddsub_pd("));
      break;

    case ZYDIS_MNEMONIC_VFMADDSUB132PS:
    case ZYDIS_MNEMONIC_VFMADDSUB213PS:
    case ZYDIS_MNEMONIC_VFMADDSUB231PS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmaddsub_ps("));
      break;

    case ZYDIS_MNEMONIC_VFMSUB132PD:
    case ZYDIS_MNEMONIC_VFMSUB213PD:
    case ZYDIS_MNEMONIC_VFMSUB231PD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmsub_pd("));
      break;

    case ZYDIS_MNEMONIC_VFMSUB132PS:
    case ZYDIS_MNEMONIC_VFMSUB213PS:
    case ZYDIS_MNEMONIC_VFMSUB231PS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmsub_ps("));
      break;

    case ZYDIS_MNEMONIC_VFMSUB132SD:
    case ZYDIS_MNEMONIC_VFMSUB213SD:
    case ZYDIS_MNEMONIC_VFMSUB231SD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmsub_sd("));
      break;

    case ZYDIS_MNEMONIC_VFMSUB132SS:
    case ZYDIS_MNEMONIC_VFMSUB213SS:
    case ZYDIS_MNEMONIC_VFMSUB231SS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmsub_ss("));
      break;

    case ZYDIS_MNEMONIC_VFMSUBADD132PD:
    case ZYDIS_MNEMONIC_VFMSUBADD213PD:
    case ZYDIS_MNEMONIC_VFMSUBADD231PD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmsubadd_pd("));
      break;

    case ZYDIS_MNEMONIC_VFMSUBADD132PS:
    case ZYDIS_MNEMONIC_VFMSUBADD213PS:
    case ZYDIS_MNEMONIC_VFMSUBADD231PS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmsubadd_ps("));
      break;

    case ZYDIS_MNEMONIC_VFNMADD132PD:
    case ZYDIS_MNEMONIC_VFNMADD213PD:
    case ZYDIS_MNEMONIC_VFNMADD231PD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fnmadd_pd("));
      break;

    case ZYDIS_MNEMONIC_VFNMADD132PS:
    case ZYDIS_MNEMONIC_VFNMADD213PS:
    case ZYDIS_MNEMONIC_VFNMADD231PS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fnmadd_ps("));
      break;

    case ZYDIS_MNEMONIC_VFNMADD132SD:
    case ZYDIS_MNEMONIC_VFNMADD213SD:
    case ZYDIS_MNEMONIC_VFNMADD231SD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fnmadd_sd("));
      break;

    case ZYDIS_MNEMONIC_VFNMADD132SS:
    case ZYDIS_MNEMONIC_VFNMADD213SS:
    case ZYDIS_MNEMONIC_VFNMADD231SS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fnmadd_ss("));
      break;

    case ZYDIS_MNEMONIC_VFNMSUB132PD:
    case ZYDIS_MNEMONIC_VFNMSUB213PD:
    case ZYDIS_MNEMONIC_VFNMSUB231PD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fnmsub_pd("));
      break;

    case ZYDIS_MNEMONIC_VFNMSUB132PS:
    case ZYDIS_MNEMONIC_VFNMSUB213PS:
    case ZYDIS_MNEMONIC_VFNMSUB231PS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fnmsub_ps("));
      break;

    case ZYDIS_MNEMONIC_VFNMSUB132SD:
    case ZYDIS_MNEMONIC_VFNMSUB213SD:
    case ZYDIS_MNEMONIC_VFNMSUB231SD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fnmsub_sd("));
      break;

    case ZYDIS_MNEMONIC_VFNMSUB132SS:
    case ZYDIS_MNEMONIC_VFNMSUB213SS:
    case ZYDIS_MNEMONIC_VFNMSUB231SS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fnmsub_ss("));
      break;
      
    case ZYDIS_MNEMONIC_STMXCSR:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_getcsr("));
      break;

    case ZYDIS_MNEMONIC_PHADDW:
    case ZYDIS_MNEMONIC_VPHADDW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_hadd_epi16("));
      break;

    case ZYDIS_MNEMONIC_PHADDD:
    case ZYDIS_MNEMONIC_VPHADDD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_hadd_epi32("));
      break;

    case ZYDIS_MNEMONIC_HADDPD:
    case ZYDIS_MNEMONIC_VHADDPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_hadd_pd("));
      break;

    case ZYDIS_MNEMONIC_HADDPS:
    case ZYDIS_MNEMONIC_VHADDPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_hadd_ps("));
      break;

    case ZYDIS_MNEMONIC_PHADDSW:
    case ZYDIS_MNEMONIC_VPHADDSW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_hadds_epi16("));
      break;

    case ZYDIS_MNEMONIC_PHSUBW:
    case ZYDIS_MNEMONIC_VPHSUBW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_hsub_epi16("));
      break;

    case ZYDIS_MNEMONIC_PHSUBD:
    case ZYDIS_MNEMONIC_VPHSUBD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_hsub_epi32("));
      break;

    case ZYDIS_MNEMONIC_HSUBPD:
    case ZYDIS_MNEMONIC_VHSUBPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_hsub_pd("));
      break;

    case ZYDIS_MNEMONIC_HSUBPS:
    case ZYDIS_MNEMONIC_VHSUBPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_hsub_ps("));
      break;

    case ZYDIS_MNEMONIC_PHSUBSW:
    case ZYDIS_MNEMONIC_VPHSUBSW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_hsubs_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPGATHERDD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i32gather_epi32("));
      addressParam = true;
      break;

    case ZYDIS_MNEMONIC_VPGATHERDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i32gather_epi64("));
      addressParam = true;
      break;

    case ZYDIS_MNEMONIC_VGATHERDPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i32gather_pd("));
      addressParam = true;
      break;

    case ZYDIS_MNEMONIC_VGATHERDPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i32gather_ps("));
      addressParam = true;
      break;
      
    case ZYDIS_MNEMONIC_VPGATHERQD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i64gather_epi32("));
      addressParam = true;
      break;

    case ZYDIS_MNEMONIC_VPGATHERQQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i64gather_epi64("));
      addressParam = true;
      break;

    case ZYDIS_MNEMONIC_VGATHERQPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i64gather_pd("));
      addressParam = true;
      break;

    case ZYDIS_MNEMONIC_VGATHERQPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i64gather_ps("));
      addressParam = true;
      break;

    case ZYDIS_MNEMONIC_PINSRB:
    case ZYDIS_MNEMONIC_VPINSRB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_insert_epi8("));
      break;

    case ZYDIS_MNEMONIC_PINSRW:
    case ZYDIS_MNEMONIC_VPINSRW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_insert_epi16("));
      break;

    case ZYDIS_MNEMONIC_PINSRD:
    case ZYDIS_MNEMONIC_VPINSRD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_insert_epi32("));
      break;

    case ZYDIS_MNEMONIC_PINSRQ:
    case ZYDIS_MNEMONIC_VPINSRQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_insert_epi64("));
      break;

    case ZYDIS_MNEMONIC_INSERTPS:
    case ZYDIS_MNEMONIC_VINSERTPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_insert_ps("));
      break;

    case ZYDIS_MNEMONIC_VINSERTF128:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_insert_f128("));
      break;

    case ZYDIS_MNEMONIC_VINSERTI128:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_insert_i128("));
      break;

    case ZYDIS_MNEMONIC_LFENCE:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_lfence("));
      break;

    case ZYDIS_MNEMONIC_MOVHPS:
      if (pOperands[0].type == ZYDIS_OPERAND_TYPE_MEMORY || pOperands[0].type == ZYDIS_OPERAND_TYPE_POINTER)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_storeh_pi("));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_loadh_pi("));
      break;

    case ZYDIS_MNEMONIC_MOVHPD:
      if (pOperands[0].type == ZYDIS_OPERAND_TYPE_MEMORY || pOperands[0].type == ZYDIS_OPERAND_TYPE_POINTER)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_storeh_pd("));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_loadh_pd("));
      break;

    case ZYDIS_MNEMONIC_VPMADD52HUQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_madd52hi_epu64("));
      break;

    case ZYDIS_MNEMONIC_VPMADD52LUQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_madd52lo_epu64("));
      break;

    case ZYDIS_MNEMONIC_PMADDUBSW:
    case ZYDIS_MNEMONIC_VPMADDUBSW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_maddubs_epi16("));
      break;

    case ZYDIS_MNEMONIC_PMAXSB:
    case ZYDIS_MNEMONIC_VPMAXSB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_max_epi8("));
      break;

    case ZYDIS_MNEMONIC_PMAXSW:
    case ZYDIS_MNEMONIC_VPMAXSW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_max_epi16("));
      break;

    case ZYDIS_MNEMONIC_PMAXSD:
    case ZYDIS_MNEMONIC_VPMAXSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_max_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPMAXSQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_max_epi64("));
      break;

    case ZYDIS_MNEMONIC_PMAXUB:
    case ZYDIS_MNEMONIC_VPMAXUB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_max_epu8("));
      break;

    case ZYDIS_MNEMONIC_PMAXUW:
    case ZYDIS_MNEMONIC_VPMAXUW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_max_epu16("));
      break;

    case ZYDIS_MNEMONIC_PMAXUD:
    case ZYDIS_MNEMONIC_VPMAXUD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_max_epu32("));
      break;

    case ZYDIS_MNEMONIC_VPMAXUQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_max_epu64("));
      break;

    case ZYDIS_MNEMONIC_MAXPD:
    case ZYDIS_MNEMONIC_VMAXPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_max_pd("));
      break;

    case ZYDIS_MNEMONIC_MAXPS:
    case ZYDIS_MNEMONIC_VMAXPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_max_ps("));
      break;

    case ZYDIS_MNEMONIC_MAXSD:
    case ZYDIS_MNEMONIC_VMAXSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_max_sd("));
      break;

    case ZYDIS_MNEMONIC_MAXSS:
    case ZYDIS_MNEMONIC_VMAXSS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_max_ss("));
      break;

    case ZYDIS_MNEMONIC_PMINSB:
    case ZYDIS_MNEMONIC_VPMINSB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_min_epi8("));
      break;

    case ZYDIS_MNEMONIC_PMINSW:
    case ZYDIS_MNEMONIC_VPMINSW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_min_epi16("));
      break;

    case ZYDIS_MNEMONIC_PMINSD:
    case ZYDIS_MNEMONIC_VPMINSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_min_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPMINSQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_min_epi64("));
      break;

    case ZYDIS_MNEMONIC_PMINUB:
    case ZYDIS_MNEMONIC_VPMINUB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_min_epu8("));
      break;

    case ZYDIS_MNEMONIC_PMINUW:
    case ZYDIS_MNEMONIC_VPMINUW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_min_epu16("));
      break;

    case ZYDIS_MNEMONIC_PMINUD:
    case ZYDIS_MNEMONIC_VPMINUD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_min_epu32("));
      break;

    case ZYDIS_MNEMONIC_VPMINUQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_min_epu64("));
      break;

    case ZYDIS_MNEMONIC_MINPD:
    case ZYDIS_MNEMONIC_VMINPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_min_pd("));
      break;

    case ZYDIS_MNEMONIC_MINPS:
    case ZYDIS_MNEMONIC_VMINPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_min_ps("));
      break;

    case ZYDIS_MNEMONIC_MINSD:
    case ZYDIS_MNEMONIC_VMINSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_min_sd("));
      break;

    case ZYDIS_MNEMONIC_MINSS:
    case ZYDIS_MNEMONIC_VMINSS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_min_ss("));
      break;

    case ZYDIS_MNEMONIC_PHMINPOSUW:
    case ZYDIS_MNEMONIC_VPHMINPOSUW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_minpos_epu16("));
      break;

    case ZYDIS_MNEMONIC_MOVDDUP:
    case ZYDIS_MNEMONIC_VMOVDDUP:
    {
      if (pOperands[1].type == ZYDIS_OPERAND_TYPE_MEMORY || pOperands[1].type == ZYDIS_OPERAND_TYPE_POINTER)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_loaddup_pd("));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_movedup_pd("));

      addressParam = true;

      break;
    }

    case ZYDIS_MNEMONIC_MOVSHDUP:
    case ZYDIS_MNEMONIC_VMOVSHDUP:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_movehdup_ps("));
      break;

    case ZYDIS_MNEMONIC_MOVHLPS:
    case ZYDIS_MNEMONIC_VMOVHLPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_movehl_ps("));
      break;

    case ZYDIS_MNEMONIC_MOVSLDUP:
    case ZYDIS_MNEMONIC_VMOVSLDUP:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_moveldup_ps("));
      break;

    case ZYDIS_MNEMONIC_MOVLHPS:
    case ZYDIS_MNEMONIC_VMOVLHPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_movelh_ps("));
      break;

    case ZYDIS_MNEMONIC_PMOVMSKB:
    case ZYDIS_MNEMONIC_VPMOVMSKB:
      maySelfReference = false;
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_movemask_epi8("));
      break;

    case ZYDIS_MNEMONIC_MOVMSKPD:
    case ZYDIS_MNEMONIC_VMOVMSKPD:
      maySelfReference = false;
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_movemask_pd("));
      break;

    case ZYDIS_MNEMONIC_MOVMSKPS:
    case ZYDIS_MNEMONIC_VMOVMSKPS:
      maySelfReference = false;
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_movemask_ps("));
      break;

    case ZYDIS_MNEMONIC_MPSADBW:
    case ZYDIS_MNEMONIC_VMPSADBW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mpsadbw_epu8("));
      break;

    case ZYDIS_MNEMONIC_PMULDQ:
    case ZYDIS_MNEMONIC_VPMULDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mul_epi32("));
      break;

    case ZYDIS_MNEMONIC_PMULUDQ:
    case ZYDIS_MNEMONIC_VPMULUDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mul_epu32("));
      break;

    case ZYDIS_MNEMONIC_MULPD:
    case ZYDIS_MNEMONIC_VMULPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mul_pd("));
      break;

    case ZYDIS_MNEMONIC_MULPS:
    case ZYDIS_MNEMONIC_VMULPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mul_ps("));
      break;

    case ZYDIS_MNEMONIC_MULSD:
    case ZYDIS_MNEMONIC_VMULSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mul_sd("));
      break;

    case ZYDIS_MNEMONIC_MULSS:
    case ZYDIS_MNEMONIC_VMULSS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mul_ss("));
      break;

    case ZYDIS_MNEMONIC_PMULHRSW:
    case ZYDIS_MNEMONIC_VPMULHRSW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mulhrs_epi16("));
      break;

    case ZYDIS_MNEMONIC_PMULLD:
    case ZYDIS_MNEMONIC_VPMULLD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mullo_epi32("));
      break;

    case ZYDIS_MNEMONIC_ORPD:
    case ZYDIS_MNEMONIC_VORPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_or_pd("));
      break;

    case ZYDIS_MNEMONIC_ORPS:
    case ZYDIS_MNEMONIC_VORPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_or_ps("));
      break;

    case ZYDIS_MNEMONIC_PAUSE:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_pause("));
      break;

    case ZYDIS_MNEMONIC_VPERMILPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_permute_pd("));
      break;

    case ZYDIS_MNEMONIC_VPERMILPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_permute_ps("));
      break;

    case ZYDIS_MNEMONIC_VPERM2F128:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_permute_2f128("));
      break;

    case ZYDIS_MNEMONIC_VPERM2I128:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_permute_2i128("));
      break;

    case ZYDIS_MNEMONIC_VPERMQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_permute4x64_epi64("));
      break;

    case ZYDIS_MNEMONIC_VPERMPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_permute4x64_pd("));
      break;

    case ZYDIS_MNEMONIC_VPERMPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_permutevar8x32_ps("));
      break;

    case ZYDIS_MNEMONIC_RCPPS:
    case ZYDIS_MNEMONIC_VRCPPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rcp_ps("));
      break;

    case ZYDIS_MNEMONIC_RCPSS:
    case ZYDIS_MNEMONIC_VRCPSS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rcp_ss("));
      break;

    case ZYDIS_MNEMONIC_RSQRTPS:
    case ZYDIS_MNEMONIC_VRSQRTPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rsqrt_ps("));
      break;

    case ZYDIS_MNEMONIC_RSQRTSS:
    case ZYDIS_MNEMONIC_VRSQRTSS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rsqrt_ss("));
      break;

    case ZYDIS_MNEMONIC_PSADBW:
    case ZYDIS_MNEMONIC_VPSADBW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sad_epu8("));
      break;

    case ZYDIS_MNEMONIC_SFENCE:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sfence("));
      break;

    case ZYDIS_MNEMONIC_PSHUFB:
    case ZYDIS_MNEMONIC_VPSHUFB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shuffle_epi8("));
      break;

    case ZYDIS_MNEMONIC_PSHUFW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shuffle_epi16("));
      break;

    case ZYDIS_MNEMONIC_PSHUFD:
    case ZYDIS_MNEMONIC_VPSHUFD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shuffle_epi32("));
      break;

    case ZYDIS_MNEMONIC_SHUFPS:
    case ZYDIS_MNEMONIC_VSHUFPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shuffle_ps("));
      break;

    case ZYDIS_MNEMONIC_SHUFPD:
    case ZYDIS_MNEMONIC_VSHUFPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shuffle_pd("));
      break;

    case ZYDIS_MNEMONIC_PSHUFHW:
    case ZYDIS_MNEMONIC_VPSHUFHW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shufflehi_epi16("));
      break;

    case ZYDIS_MNEMONIC_PSHUFLW:
    case ZYDIS_MNEMONIC_VPSHUFLW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shufflelo_epi16("));
      break;

    case ZYDIS_MNEMONIC_PSIGNB:
    case ZYDIS_MNEMONIC_VPSIGNB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sign_epi8("));
      break;

    case ZYDIS_MNEMONIC_PSIGNW:
    case ZYDIS_MNEMONIC_VPSIGNW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sign_epi16("));
      break;

    case ZYDIS_MNEMONIC_PSIGND:
    case ZYDIS_MNEMONIC_VPSIGND:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sign_epi32("));
      break;

    case ZYDIS_MNEMONIC_PSLLW:
    case ZYDIS_MNEMONIC_VPSLLW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sll_epi16("));
      break;

    case ZYDIS_MNEMONIC_PSLLD:
    case ZYDIS_MNEMONIC_VPSLLD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sll_epi32("));
      break;

    case ZYDIS_MNEMONIC_PSLLQ:
    case ZYDIS_MNEMONIC_VPSLLQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sll_epi64("));
      break;

    case ZYDIS_MNEMONIC_VPSLLVD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sllv_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPSLLVQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sllv_epi64("));
      break;

    case ZYDIS_MNEMONIC_SQRTPD:
    case ZYDIS_MNEMONIC_VSQRTPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sqrt_pd("));
      break;

    case ZYDIS_MNEMONIC_SQRTPS:
    case ZYDIS_MNEMONIC_VSQRTPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sqrt_ps("));
      break;

    case ZYDIS_MNEMONIC_SQRTSD:
    case ZYDIS_MNEMONIC_VSQRTSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sqrt_sd("));
      break;

    case ZYDIS_MNEMONIC_SQRTSS:
    case ZYDIS_MNEMONIC_VSQRTSS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sqrt_ss("));
      break;

    case ZYDIS_MNEMONIC_PSRAW:
    case ZYDIS_MNEMONIC_VPSRAW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sra_epi16("));
      break;

    case ZYDIS_MNEMONIC_PSRAD:
    case ZYDIS_MNEMONIC_VPSRAD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sra_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPSRAQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sra_epi64("));
      break;

    case ZYDIS_MNEMONIC_VPSRAVW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_srav_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPSRAVD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_srav_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPSRAVQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_srav_epi64("));
      break;

    case ZYDIS_MNEMONIC_PSRLW:
    case ZYDIS_MNEMONIC_VPSRLW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_srl_epi16("));
      break;

    case ZYDIS_MNEMONIC_PSRLD:
    case ZYDIS_MNEMONIC_VPSRLD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_srl_epi32("));
      break;

    case ZYDIS_MNEMONIC_PSRLQ:
    case ZYDIS_MNEMONIC_VPSRLQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_srl_epi64("));
      break;

    case ZYDIS_MNEMONIC_VPSRLVW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_srlv_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPSRLVD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_srlv_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPSRLVQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_srlv_epi64("));
      break;

    case ZYDIS_MNEMONIC_PSUBB:
    case ZYDIS_MNEMONIC_VPSUBB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sub_epi8("));
      break;

    case ZYDIS_MNEMONIC_PSUBW:
    case ZYDIS_MNEMONIC_VPSUBW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sub_epi16("));
      break;

    case ZYDIS_MNEMONIC_PSUBD:
    case ZYDIS_MNEMONIC_VPSUBD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sub_epi32("));
      break;

    case ZYDIS_MNEMONIC_PSUBQ:
    case ZYDIS_MNEMONIC_VPSUBQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sub_epi64("));
      break;

    case ZYDIS_MNEMONIC_SUBPD:
    case ZYDIS_MNEMONIC_VSUBPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sub_pd("));
      break;

    case ZYDIS_MNEMONIC_SUBPS:
    case ZYDIS_MNEMONIC_VSUBPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sub_ps("));
      break;

    case ZYDIS_MNEMONIC_SUBSD:
    case ZYDIS_MNEMONIC_VSUBSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sub_sd("));
      break;

    case ZYDIS_MNEMONIC_SUBSS:
    case ZYDIS_MNEMONIC_VSUBSS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sub_ss("));
      break;

    case ZYDIS_MNEMONIC_PSUBSB:
    case ZYDIS_MNEMONIC_VPSUBSB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_subs_epi8("));
      break;

    case ZYDIS_MNEMONIC_PSUBSW:
    case ZYDIS_MNEMONIC_VPSUBSW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_subs_epi16("));
      break;

    case ZYDIS_MNEMONIC_PTEST:
    case ZYDIS_MNEMONIC_VPTEST:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_test("));
      break;

    case ZYDIS_MNEMONIC_VTESTPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_test_pd("));
      break;

    case ZYDIS_MNEMONIC_VTESTPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_test_ps("));
      break;

    case ZYDIS_MNEMONIC_UCOMISD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_ucomi_sd("));
      break;

    case ZYDIS_MNEMONIC_UCOMISS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_ucomi_ss("));
      break;

    case ZYDIS_MNEMONIC_PUNPCKHBW:
    case ZYDIS_MNEMONIC_VPUNPCKHBW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_unpackhi_epi8("));
      break;

    case ZYDIS_MNEMONIC_PUNPCKHWD:
    case ZYDIS_MNEMONIC_VPUNPCKHWD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_unpackhi_epi16("));
      break;

    case ZYDIS_MNEMONIC_PUNPCKHDQ:
    case ZYDIS_MNEMONIC_VPUNPCKHDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_unpackhi_epi32("));
      break;

    case ZYDIS_MNEMONIC_PUNPCKHQDQ:
    case ZYDIS_MNEMONIC_VPUNPCKHQDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_unpackhi_epi64("));
      break;

    case ZYDIS_MNEMONIC_UNPCKHPD:
    case ZYDIS_MNEMONIC_VUNPCKHPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_unpackhi_pd("));
      break;

    case ZYDIS_MNEMONIC_UNPCKHPS:
    case ZYDIS_MNEMONIC_VUNPCKHPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_unpackhi_ps("));
      break;

    case ZYDIS_MNEMONIC_PUNPCKLBW:
    case ZYDIS_MNEMONIC_VPUNPCKLBW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_unpacklo_epi8("));
      break;

    case ZYDIS_MNEMONIC_PUNPCKLWD:
    case ZYDIS_MNEMONIC_VPUNPCKLWD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_unpacklo_epi16("));
      break;

    case ZYDIS_MNEMONIC_PUNPCKLDQ:
    case ZYDIS_MNEMONIC_VPUNPCKLDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_unpacklo_epi32("));
      break;

    case ZYDIS_MNEMONIC_PUNPCKLQDQ:
    case ZYDIS_MNEMONIC_VPUNPCKLQDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_unpacklo_epi64("));
      break;

    case ZYDIS_MNEMONIC_UNPCKLPD:
    case ZYDIS_MNEMONIC_VUNPCKLPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_unpacklo_pd("));
      break;

    case ZYDIS_MNEMONIC_UNPCKLPS:
    case ZYDIS_MNEMONIC_VUNPCKLPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_unpacklo_ps("));
      break;

    case ZYDIS_MNEMONIC_PXOR:
    case ZYDIS_MNEMONIC_VPXOR:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_xor_si("));
      break;

    case ZYDIS_MNEMONIC_XORPS:
    case ZYDIS_MNEMONIC_VXORPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_xor_ps("));
      break;

    case ZYDIS_MNEMONIC_XORPD:
    case ZYDIS_MNEMONIC_VXORPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_xor_pd("));
      break;

    case ZYDIS_MNEMONIC_VZEROALL:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_zeroall("));
      break;

    case ZYDIS_MNEMONIC_VZEROUPPER:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_zeroupper("));
      break;

    case ZYDIS_MNEMONIC_VP2INTERSECTD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_2intersect_epi32("));
      break;

    case ZYDIS_MNEMONIC_VP2INTERSECTQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_2intersect_epi64("));
      break;

    case ZYDIS_MNEMONIC_VP4DPWSSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_4dpwssd_epi32("));
      break;

    case ZYDIS_MNEMONIC_VP4DPWSSDS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_4dpwssds_epi32("));
      break;

    case ZYDIS_MNEMONIC_V4FMADDPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_4fmadd_ps("));
      break;

    case ZYDIS_MNEMONIC_V4FMADDSS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_4fmadd_ss("));
      break;

    case ZYDIS_MNEMONIC_V4FNMADDPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_4fnmadd_ps("));
      break;

    case ZYDIS_MNEMONIC_V4FNMADDSS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_4fnmadd_ss("));
      break;

    case ZYDIS_MNEMONIC_VPABSQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_abs_epi64("));
      break;

    case ZYDIS_MNEMONIC_VADDPH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_add_ph("));
      break;

    case ZYDIS_MNEMONIC_VADDSH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_add_sh("));
      break;

    case ZYDIS_MNEMONIC_PADDUSW:
    case ZYDIS_MNEMONIC_VPADDUSW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_adds_epu16("));
      break;

    case ZYDIS_MNEMONIC_PADDUSB:
    case ZYDIS_MNEMONIC_VPADDUSB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_adds_epu8("));
      break;

    case ZYDIS_MNEMONIC_VALIGND:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_alignr_epi32("));
      break;

    case ZYDIS_MNEMONIC_VALIGNQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_alignr_epi64("));
      break;

    case ZYDIS_MNEMONIC_VPSHUFBITQMB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_bitshuffle_epi64_mask("));
      break;

    case ZYDIS_MNEMONIC_VPBLENDMB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mask_blend_epi8("));
      break;

    case ZYDIS_MNEMONIC_VPBLENDMW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mask_blend_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPBLENDMD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mask_blend_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPBLENDMQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mask_blend_epi64("));
      break;

    case ZYDIS_MNEMONIC_VBLENDMPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mask_blend_ps("));
      break;

    case ZYDIS_MNEMONIC_VBLENDMPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mask_blend_pd("));
      break;

    case ZYDIS_MNEMONIC_VPCMPB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmp_epi8_mask("));
      break;

    case ZYDIS_MNEMONIC_VPCMPW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmp_epi16_mask("));
      break;

    case ZYDIS_MNEMONIC_VPCMPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmp_epi32_mask("));
      break;

    case ZYDIS_MNEMONIC_VPCMPQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmp_epi64_mask("));
      break;

    case ZYDIS_MNEMONIC_VPCMPUB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmp_epu8_mask("));
      break;

    case ZYDIS_MNEMONIC_VPCMPUW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmp_epu16_mask("));
      break;

    case ZYDIS_MNEMONIC_VPCMPUD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmp_epu32_mask("));
      break;

    case ZYDIS_MNEMONIC_VPCMPUQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmp_epu64_mask("));
      break;

    case ZYDIS_MNEMONIC_VCMPPH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmp_ph_mask("));
      break;

    case ZYDIS_MNEMONIC_VFCMULCPH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmul_pch("));
      break;

    case ZYDIS_MNEMONIC_VFCMULCSH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmul_sch("));
      break;

    case ZYDIS_MNEMONIC_VPCOMPRESSB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mask_compress_epi8("));
      break;

    case ZYDIS_MNEMONIC_VPCOMPRESSW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mask_compress_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPCOMPRESSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mask_compress_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPCOMPRESSQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mask_compress_epi64("));
      break;

    case ZYDIS_MNEMONIC_VCOMPRESSPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mask_compress_pd("));
      break;

    case ZYDIS_MNEMONIC_VCOMPRESSPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mask_compress_ps("));
      break;

    case ZYDIS_MNEMONIC_VPCONFLICTD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_conflict_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPCONFLICTQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_conflict_epi64("));
      break;

    case ZYDIS_MNEMONIC_VCVTW2PH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepi16_ph("));
      break;

    case ZYDIS_MNEMONIC_VCVTDQ2PH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepi32_ph("));
      break;

    case ZYDIS_MNEMONIC_VCVTQQ2PH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepi64_ph("));
      break;

    case ZYDIS_MNEMONIC_VCVTPD2PH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtpd_ph("));
      break;

    case ZYDIS_MNEMONIC_VCVTUW2PH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepu16_ph("));
      break;

    case ZYDIS_MNEMONIC_VCVTUDQ2PH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepu32_ph("));
      break;

    case ZYDIS_MNEMONIC_VCVTUQQ2PH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepu64_ph("));
      break;

    case ZYDIS_MNEMONIC_VCVTQQ2PS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepi64_ps("));
      break;

    case ZYDIS_MNEMONIC_VCVTQQ2PD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepi64_pd("));
      break;

    case ZYDIS_MNEMONIC_VCVTPH2PD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtph_pd("));
      break;

    case ZYDIS_MNEMONIC_VCVTPH2W:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtph_epi16("));
      break;

    case ZYDIS_MNEMONIC_VCVTPH2DQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtph_epi32("));
      break;

    case ZYDIS_MNEMONIC_VCVTPH2QQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtph_epi64("));
      break;

    case ZYDIS_MNEMONIC_VCVTPH2UW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtph_epu16("));
      break;

    case ZYDIS_MNEMONIC_VCVTPH2UDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtph_epu32("));
      break;

    case ZYDIS_MNEMONIC_VCVTPH2UQQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtph_epu64("));
      break;

    case ZYDIS_MNEMONIC_VCVTPD2QQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtpd_epi64("));
      break;

    case ZYDIS_MNEMONIC_VCVTPS2QQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtps_epi64("));
      break;

    case ZYDIS_MNEMONIC_VCVTUDQ2PS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepu32_ps("));
      break;

    case ZYDIS_MNEMONIC_VCVTUQQ2PS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepu64_ps("));
      break;

    case ZYDIS_MNEMONIC_VCVTPS2UDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtps_epu32("));
      break;

    case ZYDIS_MNEMONIC_VCVTPS2UQQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtps_epu64("));
      break;

    case ZYDIS_MNEMONIC_VCVTUDQ2PD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepu32_pd("));
      break;

    case ZYDIS_MNEMONIC_VCVTUQQ2PD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepu64_pd("));
      break;

    case ZYDIS_MNEMONIC_VCVTPD2UDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtpd_epu32("));
      break;

    case ZYDIS_MNEMONIC_VCVTPD2UQQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtpd_epu64("));
      break;

    case ZYDIS_MNEMONIC_VCVTSI2SH:
      if (pInstruction->operand_count > 2 && pOperands[2].element_size == 4)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvti32_sh("));
      else if (pInstruction->operand_count > 2 && pOperands[2].element_size == 8)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvti64_sh("));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvti_sh("));
      break;

    case ZYDIS_MNEMONIC_VCVTUSI2SH:
      if (pInstruction->operand_count > 2 && pOperands[2].element_size == 4)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtu32_sh("));
      else if (pInstruction->operand_count > 2 && pOperands[2].element_size == 8)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtu64_sh("));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtu_sh("));
      break;

    case ZYDIS_MNEMONIC_VCVTSS2SH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtss_sh("));
      break;

    case ZYDIS_MNEMONIC_VCVTSD2SH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsd_sh("));
      break;

    case ZYDIS_MNEMONIC_VCVTSH2SI:
      if (pInstruction->operand_count > 0 && pOperands[0].element_size == 4)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsh_i32("));
      else if (pInstruction->operand_count > 0 && pOperands[0].element_size == 8)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsh_i64("));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsh_i("));
      break;

    case ZYDIS_MNEMONIC_VCVTSH2USI:
      if (pInstruction->operand_count > 0 && pOperands[0].element_size == 4)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsh_u32("));
      else if (pInstruction->operand_count > 0 && pOperands[0].element_size == 8)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsh_u64("));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsh_u("));
      break;

    case ZYDIS_MNEMONIC_VCVTSH2SS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsh_ss("));
      break;

    case ZYDIS_MNEMONIC_VCVTSH2SD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsh_sd("));
      break;

    case ZYDIS_MNEMONIC_VPMOVQB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepi64_epi8("));
      break;

    case ZYDIS_MNEMONIC_VPMOVDB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepi32_epi8("));
      break;

    case ZYDIS_MNEMONIC_VPMOVWB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepi16_epi8("));
      break;

    case ZYDIS_MNEMONIC_VPMOVQW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepi64_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPMOVDW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepi32_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPMOVQD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtepi64_epi32("));
      break;

    case ZYDIS_MNEMONIC_VCVTNE2PS2BF16:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtne2ps_pbh("));
      break;

    case ZYDIS_MNEMONIC_VCVTSD2USI:
      if (pInstruction->operand_count > 0 && pOperands[0].element_size == 4)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsd_u32("));
      else if (pInstruction->operand_count > 0 && pOperands[0].element_size == 8)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsd_u64("));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsd_u("));
      break;

    case ZYDIS_MNEMONIC_VCVTSS2USI:
      if (pInstruction->operand_count > 0 && pOperands[0].element_size == 4)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtss_u32("));
      else if (pInstruction->operand_count > 0 && pOperands[0].element_size == 8)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtss_u64("));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtss_u("));
      break;

    case ZYDIS_MNEMONIC_VCVTUSI2SD:
      if (pInstruction->operand_count > 2 && pOperands[2].element_size == 4)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtu32_sd("));
      else if (pInstruction->operand_count > 2 && pOperands[2].element_size == 8)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtu64_sd("));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtu_sd("));
      break;

    case ZYDIS_MNEMONIC_VCVTUSI2SS:
      if (pInstruction->operand_count > 2 && pOperands[2].element_size == 4)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtu32_ss("));
      else if (pInstruction->operand_count > 2 && pOperands[2].element_size == 8)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtu64_ss("));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtu_ss("));
      break;

    case ZYDIS_MNEMONIC_VPMOVSWB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsepi16_epi8("));
      break;

    case ZYDIS_MNEMONIC_VPMOVSDB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsepi32_epi8("));
      break;

    case ZYDIS_MNEMONIC_VPMOVSQB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsepi64_epi8("));
      break;

    case ZYDIS_MNEMONIC_VPMOVSDW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsepi32_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPMOVSQW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsepi64_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPMOVSQD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtsepi64_epi32("));
      break;
      
    case ZYDIS_MNEMONIC_VCVTTSD2SI:
      if (pInstruction->operand_count > 0 && pOperands[0].element_size == 4)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttsd_i32("));
      else if (pInstruction->operand_count > 0 && pOperands[0].element_size == 8)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttsd_i64("));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttsd_si("));
      break;

    case ZYDIS_MNEMONIC_VCVTTSD2USI:
      if (pInstruction->operand_count > 0 && pOperands[0].element_size == 4)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttsd_u32("));
      else if (pInstruction->operand_count > 0 && pOperands[0].element_size == 8)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttsd_u64("));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttsd_u("));
      break;

    case ZYDIS_MNEMONIC_CVTTSS2SI:
    case ZYDIS_MNEMONIC_VCVTTSS2SI:
      if (pInstruction->operand_count > 0 && pOperands[0].element_size == 4)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttss_si32("));
      else if (pInstruction->operand_count > 0 && pOperands[0].element_size == 8)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttss_si64("));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttss_si("));
      break;

    case ZYDIS_MNEMONIC_VCVTTSS2USI:
      if (pInstruction->operand_count > 0 && pOperands[0].element_size == 4)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttss_u32("));
      else if (pInstruction->operand_count > 0 && pOperands[0].element_size == 8)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttss_u64("));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttss_u("));
      break;

    case ZYDIS_MNEMONIC_VCVTTSH2SI:
      if (pInstruction->operand_count > 0 && pOperands[0].element_size == 4)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttsh_si32("));
      else if (pInstruction->operand_count > 0 && pOperands[0].element_size == 8)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttsh_si64("));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttsh_si("));
      break;

    case ZYDIS_MNEMONIC_VCVTTSH2USI:
      if (pInstruction->operand_count > 0 && pOperands[0].element_size == 4)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttsh_u32("));
      else if (pInstruction->operand_count > 0 && pOperands[0].element_size == 8)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttsh_u64("));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttsh_u("));
      break;

    case ZYDIS_MNEMONIC_VCVTTPH2QQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttph_epi64("));
      break;

    case ZYDIS_MNEMONIC_VCVTTPS2QQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttps_epi64("));
      break;

    case ZYDIS_MNEMONIC_VCVTTPD2QQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttpd_epi64("));
      break;

    case ZYDIS_MNEMONIC_VCVTTPH2DQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttph_epi32("));
      break;

    case ZYDIS_MNEMONIC_VCVTTPH2W:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttph_epi16("));
      break;

    case ZYDIS_MNEMONIC_VCVTTPH2UQQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttph_epu64("));
      break;

    case ZYDIS_MNEMONIC_VCVTTPS2UQQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttps_epu64("));
      break;

    case ZYDIS_MNEMONIC_VCVTTPD2UQQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttpd_epu64("));
      break;

    case ZYDIS_MNEMONIC_VCVTTPD2UDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttpd_epu64("));
      break;

    case ZYDIS_MNEMONIC_VCVTTPS2UDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttps_epu64("));
      break;

    case ZYDIS_MNEMONIC_VCVTTPH2UDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttph_epu32("));
      break;

    case ZYDIS_MNEMONIC_VCVTTPH2UW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttph_epu16("));
      break;

    case ZYDIS_MNEMONIC_VPMOVUSWB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtusepi16_epi8("));
      break;

    case ZYDIS_MNEMONIC_VPMOVUSDB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtusepi32_epi8("));
      break;

    case ZYDIS_MNEMONIC_VPMOVUSQB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtusepi64_epi8("));
      break;

    case ZYDIS_MNEMONIC_VPMOVUSDW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtusepi32_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPMOVUSQW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtusepi64_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPMOVUSQD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtusepi64_epi32("));
      break;

    case ZYDIS_MNEMONIC_VCVTPH2PSX:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtxph_ps("));
      break;

    case ZYDIS_MNEMONIC_VCVTPS2PHX:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvtxps_ph("));
      break;

    case ZYDIS_MNEMONIC_VDBPSADBW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_dbsad_epu8("));
      break;

    case ZYDIS_MNEMONIC_VDIVPH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_div_ph("));
      break;

    case ZYDIS_MNEMONIC_VDIVSH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_div_sh("));
      break;

    case ZYDIS_MNEMONIC_VDPBF16PS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_dpbf16_ps("));
      break;

    case ZYDIS_MNEMONIC_VEXP2PD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_exp2a23_pd("));
      break;

    case ZYDIS_MNEMONIC_VEXP2PS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_exp2a23_ps("));
      break;

    case ZYDIS_MNEMONIC_VPEXPANDB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mask_expand_epi8("));
      break;

    case ZYDIS_MNEMONIC_VPEXPANDW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mask_expand_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPEXPANDD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mask_expand_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPEXPANDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mask_expand_epi64("));
      break;
      
    case ZYDIS_MNEMONIC_VEXPANDPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mask_expand_ps("));
      break;

    case ZYDIS_MNEMONIC_VEXPANDPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mask_expand_pd("));
      break;

    case ZYDIS_MNEMONIC_VEXTRACTF32X4:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_extractf32x4_ps("));
      break;

    case ZYDIS_MNEMONIC_VEXTRACTF32X8:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_extractf32x8_ps("));
      break;

    case ZYDIS_MNEMONIC_VEXTRACTF64X2:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_extractf64x2_pd("));
      break;

    case ZYDIS_MNEMONIC_VEXTRACTF64X4:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_extractf64x4_pd("));
      break;

    case ZYDIS_MNEMONIC_VEXTRACTI32X4:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_extracti32x4_epi32("));
      break;

    case ZYDIS_MNEMONIC_VEXTRACTI32X8:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_extracti32x8_epi32("));
      break;

    case ZYDIS_MNEMONIC_VEXTRACTI64X2:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_extracti64x2_epi64("));
      break;

    case ZYDIS_MNEMONIC_VEXTRACTI64X4:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_extracti64x4_epi64("));
      break;

    case ZYDIS_MNEMONIC_VFCMADDCPH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fcmadd_pch("));
      break;

    case ZYDIS_MNEMONIC_VFCMADDCSH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fcmadd_sch("));
      break;

    case ZYDIS_MNEMONIC_VFIXUPIMMPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fixupimm_pd("));
      break;

    case ZYDIS_MNEMONIC_VFIXUPIMMPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fixupimm_ps("));
      break;

    case ZYDIS_MNEMONIC_VFIXUPIMMSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fixupimm_sd("));
      break;

    case ZYDIS_MNEMONIC_VFIXUPIMMSS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fixupimm_ss("));
      break;

    case ZYDIS_MNEMONIC_VFMADDCPH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmadd_pch("));
      break;

    case ZYDIS_MNEMONIC_VFMADDCSH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmadd_sch("));
      break;

    case ZYDIS_MNEMONIC_VFMADD132PH:
    case ZYDIS_MNEMONIC_VFMADD213PH:
    case ZYDIS_MNEMONIC_VFMADD231PH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmadd_ph("));
      break;

    case ZYDIS_MNEMONIC_VFMADD132SH:
    case ZYDIS_MNEMONIC_VFMADD213SH:
    case ZYDIS_MNEMONIC_VFMADD231SH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmadd_sh("));
      break;

    case ZYDIS_MNEMONIC_VFMADDSUB132PH:
    case ZYDIS_MNEMONIC_VFMADDSUB213PH:
    case ZYDIS_MNEMONIC_VFMADDSUB231PH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmaddsub_ph("));
      break;

    case ZYDIS_MNEMONIC_VFMSUB132PH:
    case ZYDIS_MNEMONIC_VFMSUB213PH:
    case ZYDIS_MNEMONIC_VFMSUB231PH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmsub_ph("));
      break;

    case ZYDIS_MNEMONIC_VFMSUB132SH:
    case ZYDIS_MNEMONIC_VFMSUB213SH:
    case ZYDIS_MNEMONIC_VFMSUB231SH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmsub_sh("));
      break;

    case ZYDIS_MNEMONIC_VFMSUBADD132PH:
    case ZYDIS_MNEMONIC_VFMSUBADD213PH:
    case ZYDIS_MNEMONIC_VFMSUBADD231PH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmsubadd_ph("));
      break;

    case ZYDIS_MNEMONIC_VFMULCPH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmul_pch("));
      break;

    case ZYDIS_MNEMONIC_VFMULCSH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fmul_sch("));
      break;

    case ZYDIS_MNEMONIC_VFNMADD132PH:
    case ZYDIS_MNEMONIC_VFNMADD213PH:
    case ZYDIS_MNEMONIC_VFNMADD231PH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fnmadd_ph("));
      break;

    case ZYDIS_MNEMONIC_VFNMADD132SH:
    case ZYDIS_MNEMONIC_VFNMADD213SH:
    case ZYDIS_MNEMONIC_VFNMADD231SH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fnmadd_sh("));
      break;

    case ZYDIS_MNEMONIC_VFNMSUB132PH:
    case ZYDIS_MNEMONIC_VFNMSUB213PH:
    case ZYDIS_MNEMONIC_VFNMSUB231PH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fnmsub_ph("));
      break;

    case ZYDIS_MNEMONIC_VFNMSUB132SH:
    case ZYDIS_MNEMONIC_VFNMSUB213SH:
    case ZYDIS_MNEMONIC_VFNMSUB231SH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fnmsub_sh("));
      break;

    case ZYDIS_MNEMONIC_VFPCLASSPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fpclass_pd_mask("));
      break;

    case ZYDIS_MNEMONIC_VFPCLASSPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fpclass_ps_mask("));
      break;

    case ZYDIS_MNEMONIC_VFPCLASSPH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_fpclass_ph_mask("));
      break;

    case ZYDIS_MNEMONIC_VGETEXPPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_getexp_pd("));
      break;

    case ZYDIS_MNEMONIC_VGETEXPPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_getexp_ps("));
      break;

    case ZYDIS_MNEMONIC_VGETEXPPH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_getexp_ph("));
      break;

    case ZYDIS_MNEMONIC_VGETEXPSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_getexp_sd("));
      break;

    case ZYDIS_MNEMONIC_VGETEXPSS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_getexp_ss("));
      break;

    case ZYDIS_MNEMONIC_VGETEXPSH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_getexp_sh("));
      break;

    case ZYDIS_MNEMONIC_VGETMANTPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_getmant_pd("));
      break;

    case ZYDIS_MNEMONIC_VGETMANTPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_getmant_ps("));
      break;

    case ZYDIS_MNEMONIC_VGETMANTPH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_getmant_ph("));
      break;

    case ZYDIS_MNEMONIC_VGETMANTSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_getmant_sd("));
      break;

    case ZYDIS_MNEMONIC_VGETMANTSS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_getmant_ss("));
      break;

    case ZYDIS_MNEMONIC_VGETMANTSH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_getmant_sh("));
      break;

    case ZYDIS_MNEMONIC_VPSCATTERDD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i32scatter_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPSCATTERDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i32scatter_epi64("));
      break;

    case ZYDIS_MNEMONIC_VPSCATTERQD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i64scatter_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPSCATTERQQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i64scatter_epi64("));
      break;

    case ZYDIS_MNEMONIC_VSCATTERDPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i32scatter_ps("));
      break;

    case ZYDIS_MNEMONIC_VSCATTERDPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i32scatter_pd("));
      break;

    case ZYDIS_MNEMONIC_VSCATTERQPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i64scatter_ps("));
      break;

    case ZYDIS_MNEMONIC_VSCATTERQPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i64scatter_pd("));
      break;

    case ZYDIS_MNEMONIC_VINSERTF32X4:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_insertf32x4("));
      break;

    case ZYDIS_MNEMONIC_VINSERTF32X8:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_insertf32x8("));
      break;

    case ZYDIS_MNEMONIC_VINSERTF64X2:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_insertf64x2("));
      break;

    case ZYDIS_MNEMONIC_VINSERTF64X4:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_insertf64x4("));
      break;

    case ZYDIS_MNEMONIC_VINSERTI32X4:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_inserti32x4("));
      break;

    case ZYDIS_MNEMONIC_VINSERTI32X8:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_inserti32x8("));
      break;

    case ZYDIS_MNEMONIC_VINSERTI64X2:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_inserti64x2("));
      break;

    case ZYDIS_MNEMONIC_VINSERTI64X4:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_inserti64x4("));
      break;

    case ZYDIS_MNEMONIC_KADDB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kadd_mask8("));
      break;

    case ZYDIS_MNEMONIC_KADDW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kadd_mask16("));
      break;

    case ZYDIS_MNEMONIC_KADDD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kadd_mask32("));
      break;

    case ZYDIS_MNEMONIC_KADDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kadd_mask64("));
      break;

    case ZYDIS_MNEMONIC_KANDB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kand_mask8("));
      break;

    case ZYDIS_MNEMONIC_KANDW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kand_mask16("));
      break;

    case ZYDIS_MNEMONIC_KANDD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kand_mask32("));
      break;

    case ZYDIS_MNEMONIC_KANDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kand_mask64("));
      break;

    case ZYDIS_MNEMONIC_KANDNB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kandn_mask8("));
      break;

    case ZYDIS_MNEMONIC_KANDNW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kandn_mask16("));
      break;

    case ZYDIS_MNEMONIC_KANDND:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kandn_mask32("));
      break;

    case ZYDIS_MNEMONIC_KANDNQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kandn_mask64("));
      break;

    case ZYDIS_MNEMONIC_KNOTB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_knot_mask8("));
      break;

    case ZYDIS_MNEMONIC_KNOTW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_knot_mask16("));
      break;

    case ZYDIS_MNEMONIC_KNOTD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_knot_mask32("));
      break;

    case ZYDIS_MNEMONIC_KNOTQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_knot_mask64("));
      break;
      
    case ZYDIS_MNEMONIC_KORB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kor_mask8("));
      break;

    case ZYDIS_MNEMONIC_KORW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kor_mask16("));
      break;

    case ZYDIS_MNEMONIC_KORD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kor_mask32("));
      break;

    case ZYDIS_MNEMONIC_KORQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kor_mask64("));
      break;

    case ZYDIS_MNEMONIC_KUNPCKBW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_kunpackepi8_epi16("));
      break;

    case ZYDIS_MNEMONIC_KUNPCKWD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_kunpackepi16_epi32("));
      break;

    case ZYDIS_MNEMONIC_KUNPCKDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_kunpackepi32_epi64("));
      break;

    case ZYDIS_MNEMONIC_KXNORB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kxnor_mask8("));
      break;

    case ZYDIS_MNEMONIC_KXNORW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kxnor_mask16("));
      break;

    case ZYDIS_MNEMONIC_KXNORD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kxnor_mask32("));
      break;

    case ZYDIS_MNEMONIC_KXNORQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_kxnor_mask64("));
      break;

    case ZYDIS_MNEMONIC_VPLZCNTD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_lzcnt_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPLZCNTQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_lzcnt_epi64("));
      break;

    case ZYDIS_MNEMONIC_VMAXPH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_max_ph("));
      break;

    case ZYDIS_MNEMONIC_VMAXSH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_max_sh("));
      break;

    case ZYDIS_MNEMONIC_VMINPH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_min_ph("));
      break;

    case ZYDIS_MNEMONIC_VMINSH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_min_sh("));
      break;

    case ZYDIS_MNEMONIC_VPMOVB2M:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_movepi8_mask("));
      break;

    case ZYDIS_MNEMONIC_VPMOVW2M:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_movepi16_mask("));
      break;

    case ZYDIS_MNEMONIC_VPMOVD2M:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_movepi32_mask("));
      break;

    case ZYDIS_MNEMONIC_VPMOVQ2M:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_movepi64_mask("));
      break;

    case ZYDIS_MNEMONIC_VPMOVM2B:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_movm_epi8("));
      break;

    case ZYDIS_MNEMONIC_VPMOVM2W:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_movm_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPMOVM2D:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_movm_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPMOVM2Q:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_movm_epi64("));
      break;
      
    case ZYDIS_MNEMONIC_VMULPH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mul_ph("));
      break;

    case ZYDIS_MNEMONIC_VMULSH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mul_sh("));
      break;

    case ZYDIS_MNEMONIC_VSUBPH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sub_ph("));
      break;

    case ZYDIS_MNEMONIC_VSUBSH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sub_sh("));
      break;

    case ZYDIS_MNEMONIC_VCMPSH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cmp_sh("));
      break;

    case ZYDIS_MNEMONIC_VPMULHUW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mulhi_epu16("));
      break;

    case ZYDIS_MNEMONIC_VPMULHUD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mulhi_epu32("));
      break;

    case ZYDIS_MNEMONIC_VPMULLQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_mullo_epi64("));
      break;

    case ZYDIS_MNEMONIC_VPMULTISHIFTQB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_multishift_epi64_epi8("));
      break;

    case ZYDIS_MNEMONIC_VPERMT2B:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_permutex2var_epi8("));
      break;

    case ZYDIS_MNEMONIC_VPERMT2W:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_permutex2var_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPERMT2D:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_permutex2var_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPERMT2Q:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_permutex2var_epi64("));
      break;

    case ZYDIS_MNEMONIC_VPERMT2PS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_permutex2var_ps("));
      break;

    case ZYDIS_MNEMONIC_VPERMT2PD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_permutex2var_pd("));
      break;

    case ZYDIS_MNEMONIC_VPERMB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_permutexvar_epi8("));
      break;

    case ZYDIS_MNEMONIC_VPERMW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_permutexvar_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPERMD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_permutevar_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPOPCNTB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_popcnt_epi8("));
      break;

    case ZYDIS_MNEMONIC_VPOPCNTW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_popcnt_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPOPCNTD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_popcnt_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPOPCNTQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_popcnt_epi64("));
      break;

    case ZYDIS_MNEMONIC_VRANGEPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_range_pd("));
      break;

    case ZYDIS_MNEMONIC_VRANGEPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_range_ps("));
      break;

    case ZYDIS_MNEMONIC_VRANGESD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_range_sd("));
      break;

    case ZYDIS_MNEMONIC_VRANGESS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_range_ss("));
      break;

    case ZYDIS_MNEMONIC_VRCPPH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rcp_ph("));
      break;

    case ZYDIS_MNEMONIC_VRCPSH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rcp_sh("));
      break;

    case ZYDIS_MNEMONIC_VRCP14PD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rcp14_pd("));
      break;

    case ZYDIS_MNEMONIC_VRCP14PS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rcp14_ps("));
      break;

    case ZYDIS_MNEMONIC_VRCP14SD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rcp14_sd("));
      break;

    case ZYDIS_MNEMONIC_VRCP14SS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rcp14_ss("));
      break;

    case ZYDIS_MNEMONIC_VRCP28PD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rcp28_pd("));
      break;

    case ZYDIS_MNEMONIC_VRCP28PS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rcp28_ps("));
      break;

    case ZYDIS_MNEMONIC_VRCP28SD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rcp28_sd("));
      break;

    case ZYDIS_MNEMONIC_VRCP28SS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rcp28_ss("));
      break;

    case ZYDIS_MNEMONIC_VREDUCEPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_reduce_pd("));
      break;

    case ZYDIS_MNEMONIC_VREDUCEPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_reduce_ps("));
      break;

    case ZYDIS_MNEMONIC_VREDUCEPH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_reduce_ph("));
      break;

    case ZYDIS_MNEMONIC_VREDUCESD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_reduce_sd("));
      break;

    case ZYDIS_MNEMONIC_VREDUCESS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_reduce_ss("));
      break;

    case ZYDIS_MNEMONIC_VREDUCESH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_reduce_sh("));
      break;

    case ZYDIS_MNEMONIC_VPROLD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rol_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPROLQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rol_epi64("));
      break;
      
    case ZYDIS_MNEMONIC_VPROLVD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rolv_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPROLVQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rolv_epi64("));
      break;

    case ZYDIS_MNEMONIC_VPRORD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_ror_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPRORQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_ror_epi64("));
      break;

    case ZYDIS_MNEMONIC_VPRORVD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rorv_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPRORVQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rorv_epi64("));
      break;

    case ZYDIS_MNEMONIC_VRNDSCALEPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_roundscale_pd("));
      break;

    case ZYDIS_MNEMONIC_VRNDSCALEPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_roundscale_ps("));
      break;

    case ZYDIS_MNEMONIC_VRNDSCALEPH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_roundscale_ph("));
      break;

    case ZYDIS_MNEMONIC_VRNDSCALESD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_roundscale_sd("));
      break;

    case ZYDIS_MNEMONIC_VRNDSCALESS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_roundscale_ss("));
      break;

    case ZYDIS_MNEMONIC_VRNDSCALESH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_roundscale_sh("));
      break;

    case ZYDIS_MNEMONIC_VRSQRTPH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rsqrt_ph("));
      break;

    case ZYDIS_MNEMONIC_VRSQRTSH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rsqrt_sh("));
      break;

    case ZYDIS_MNEMONIC_VRSQRT14PD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rsqrt14_pd("));
      break;

    case ZYDIS_MNEMONIC_VRSQRT14PS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rsqrt14_ps("));
      break;

    case ZYDIS_MNEMONIC_VRSQRT14SD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rsqrt14_sd("));
      break;

    case ZYDIS_MNEMONIC_VRSQRT14SS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rsqrt14_ss("));
      break;

    case ZYDIS_MNEMONIC_VRSQRT28PD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rsqrt28_pd("));
      break;

    case ZYDIS_MNEMONIC_VRSQRT28PS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rsqrt28_ps("));
      break;

    case ZYDIS_MNEMONIC_VRSQRT28SD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rsqrt28_sd("));
      break;

    case ZYDIS_MNEMONIC_VRSQRT28SS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_rsqrt28_ss("));
      break;

    case ZYDIS_MNEMONIC_VSCALEFPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_scalef_pd("));
      break;

    case ZYDIS_MNEMONIC_VSCALEFPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_scalef_ps("));
      break;

    case ZYDIS_MNEMONIC_VSCALEFPH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_scalef_ph("));
      break;

    case ZYDIS_MNEMONIC_VSCALEFSD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_scalef_sd("));
      break;

    case ZYDIS_MNEMONIC_VSCALEFSS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_scalef_ss("));
      break;

    case ZYDIS_MNEMONIC_VSCALEFSH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_scalef_sh("));
      break;

    case ZYDIS_MNEMONIC_VPXORQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_xor_epi64("));
      break;

    case ZYDIS_MNEMONIC_VPXORD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_xor_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPSHLB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shl_epi8("));
      break;

    case ZYDIS_MNEMONIC_VPSHLW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shl_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPSHLD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shl_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPSHLQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shl_epi64("));
      break;
      
    case ZYDIS_MNEMONIC_VPSHLDW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shldi_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPSHLDD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shldi_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPSHLDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shldi_epi64("));
      break;

    case ZYDIS_MNEMONIC_VPSHLDVW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shldv_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPSHLDVD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shldv_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPSHLDVQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shldv_epi64("));
      break;

    case ZYDIS_MNEMONIC_VPSHRDW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shrdi_epi16("));
      break;

    case ZYDIS_MNEMONIC_VPSHRDD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shrdi_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPSHRDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shrdi_epi64("));
      break;

    case ZYDIS_MNEMONIC_VPSHRDVW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shrdv_epi16("));
      break;
      
    case ZYDIS_MNEMONIC_VPSHRDVD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shrdv_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPSHRDVQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shrdv_epi64("));
      break;
      
    case ZYDIS_MNEMONIC_VSHUFF32X4:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shuffle_f32x4("));
      break;

    case ZYDIS_MNEMONIC_VSHUFF64X2:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shuffle_f64x2("));
      break;

    case ZYDIS_MNEMONIC_VSHUFI32X4:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shuffle_i32x4("));
      break;

    case ZYDIS_MNEMONIC_VSHUFI64X2:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_shuffle_i64x2("));
      break;

    case ZYDIS_MNEMONIC_VPSLLVW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sllv_epi16("));
      break;

    case ZYDIS_MNEMONIC_VSQRTPH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sqrt_ph("));
      break;

    case ZYDIS_MNEMONIC_VSQRTSH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_sqrt_sh("));
      break;

    case ZYDIS_MNEMONIC_VPSUBUSB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_subs_epu8("));
      break;

    case ZYDIS_MNEMONIC_VPSUBUSW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_subs_epu16("));
      break;

    case ZYDIS_MNEMONIC_VPTERNLOGD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_ternarylogic_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPTERNLOGQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_ternarylogic_epi64("));
      break;
      
    case ZYDIS_MNEMONIC_VPTESTMB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_test_epi8_mask("));
      break;

    case ZYDIS_MNEMONIC_VPTESTMW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_test_epi16_mask("));
      break;

    case ZYDIS_MNEMONIC_VPTESTMD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_test_epi32_mask("));
      break;

    case ZYDIS_MNEMONIC_VPTESTMQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_test_epi64_mask("));
      break;
      
    case ZYDIS_MNEMONIC_VPTESTNMB:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_testn_epi8_mask("));
      break;

    case ZYDIS_MNEMONIC_VPTESTNMW:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_testn_epi16_mask("));
      break;

    case ZYDIS_MNEMONIC_VPTESTNMD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_testn_epi32_mask("));
      break;

    case ZYDIS_MNEMONIC_VPTESTNMQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_testn_epi64_mask("));
      break;

    case ZYDIS_MNEMONIC_VUCOMISH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_ucomi_sh("));
      break;

    default:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_??_("));
      break;
    }

    const size_t startOperandIndex = pInstruction->operand_count <= 1 || (pInstruction->operand_count == 2 && maySelfReference) ? 0 : 1;

    for (size_t operandIndex = startOperandIndex; operandIndex < pInstruction->operand_count; operandIndex++)
    {
      if (operandIndex > startOperandIndex)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ", "));

      ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[operandIndex], virtualAddress, pInfo, !addressParam));
    }

    switch (pInstruction->mnemonic)
    {
    case ZYDIS_MNEMONIC_PSLLDQ:
    case ZYDIS_MNEMONIC_VPSLLDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " * 8); // byte shift left in 128 bit lanes"));
      return true;

    case ZYDIS_MNEMONIC_PSRLDQ:
    case ZYDIS_MNEMONIC_VPSRLDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " * 8); // byte shift right in 128 bit lanes"));
      return true;

    case ZYDIS_MNEMONIC_VPCOMPRESSB:
    case ZYDIS_MNEMONIC_VPCOMPRESSW:
    case ZYDIS_MNEMONIC_VPCOMPRESSD:
    case ZYDIS_MNEMONIC_VPCOMPRESSQ:
    case ZYDIS_MNEMONIC_VCOMPRESSPD:
    case ZYDIS_MNEMONIC_VCOMPRESSPS:
    case ZYDIS_MNEMONIC_VPMOVQB:
    case ZYDIS_MNEMONIC_VPMOVDB:
    case ZYDIS_MNEMONIC_VPMOVWB:
    case ZYDIS_MNEMONIC_VPMOVQW:
    case ZYDIS_MNEMONIC_VPMOVDW:
    case ZYDIS_MNEMONIC_VPMOVQD:
    case ZYDIS_MNEMONIC_VPMOVSWB:
    case ZYDIS_MNEMONIC_VPMOVSDB:
    case ZYDIS_MNEMONIC_VPMOVSQB:
    case ZYDIS_MNEMONIC_VPMOVSDW:
    case ZYDIS_MNEMONIC_VPMOVSQW:
    case ZYDIS_MNEMONIC_VPMOVSQD:
      if (pOperands[0].type == ZYDIS_OPERAND_TYPE_MEMORY || pOperands[0].type == ZYDIS_OPERAND_TYPE_POINTER)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "); // with unaligned store"));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ");"));
      return true;

    case ZYDIS_MNEMONIC_VPEXPANDB:
    case ZYDIS_MNEMONIC_VPEXPANDW:
    case ZYDIS_MNEMONIC_VPEXPANDD:
    case ZYDIS_MNEMONIC_VPEXPANDQ:
      if (pInstruction->operand_count > 0 && (pOperands[pInstruction->operand_count - 1].type == ZYDIS_OPERAND_TYPE_MEMORY || pOperands[pInstruction->operand_count - 1].type == ZYDIS_OPERAND_TYPE_POINTER))
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "); // with unaligned load"));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ");"));
      return true;

    case ZYDIS_MNEMONIC_VFMADD132PD:
    case ZYDIS_MNEMONIC_VFMADD132PS:
    case ZYDIS_MNEMONIC_VFMADD132SD:
    case ZYDIS_MNEMONIC_VFMADD132SS:
    case ZYDIS_MNEMONIC_VFMADDSUB132PD:
    case ZYDIS_MNEMONIC_VFMADDSUB132PS:
    case ZYDIS_MNEMONIC_VFMSUB132PD:
    case ZYDIS_MNEMONIC_VFMSUB132PS:
    case ZYDIS_MNEMONIC_VFMSUB132SD:
    case ZYDIS_MNEMONIC_VFMSUB132SS:
    case ZYDIS_MNEMONIC_VFMSUBADD132PD:
    case ZYDIS_MNEMONIC_VFMSUBADD132PS:
    case ZYDIS_MNEMONIC_VFNMADD132PD:
    case ZYDIS_MNEMONIC_VFNMADD132PS:
    case ZYDIS_MNEMONIC_VFNMADD132SD:
    case ZYDIS_MNEMONIC_VFNMADD132SS:
    case ZYDIS_MNEMONIC_VFNMSUB132PD:
    case ZYDIS_MNEMONIC_VFNMSUB132PS:
    case ZYDIS_MNEMONIC_VFNMSUB132SD:
    case ZYDIS_MNEMONIC_VFNMSUB132SS:
    case ZYDIS_MNEMONIC_VFMADD132PH:
    case ZYDIS_MNEMONIC_VFMADD132SH:
    case ZYDIS_MNEMONIC_VFMADDSUB132PH:
    case ZYDIS_MNEMONIC_VFMSUB132PH:
    case ZYDIS_MNEMONIC_VFMSUB132SH:
    case ZYDIS_MNEMONIC_VFMSUBADD132PH:
    case ZYDIS_MNEMONIC_VFNMADD132PH:
    case ZYDIS_MNEMONIC_VFNMADD132SH:
    case ZYDIS_MNEMONIC_VFNMSUB132PH:
    case ZYDIS_MNEMONIC_VFNMSUB132SH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "); // part 1 / 3"));
      return true;

    case ZYDIS_MNEMONIC_VFMADD213PD:
    case ZYDIS_MNEMONIC_VFMADD213PS:
    case ZYDIS_MNEMONIC_VFMADD213SD:
    case ZYDIS_MNEMONIC_VFMADD213SS:
    case ZYDIS_MNEMONIC_VFMADDSUB213PD:
    case ZYDIS_MNEMONIC_VFMADDSUB213PS:
    case ZYDIS_MNEMONIC_VFMSUB213PD:
    case ZYDIS_MNEMONIC_VFMSUB213PS:
    case ZYDIS_MNEMONIC_VFMSUB213SD:
    case ZYDIS_MNEMONIC_VFMSUB213SS:
    case ZYDIS_MNEMONIC_VFMSUBADD213PD:
    case ZYDIS_MNEMONIC_VFMSUBADD213PS:
    case ZYDIS_MNEMONIC_VFNMADD213PD:
    case ZYDIS_MNEMONIC_VFNMADD213PS:
    case ZYDIS_MNEMONIC_VFNMADD213SD:
    case ZYDIS_MNEMONIC_VFNMADD213SS:
    case ZYDIS_MNEMONIC_VFNMSUB213PD:
    case ZYDIS_MNEMONIC_VFNMSUB213PS:
    case ZYDIS_MNEMONIC_VFNMSUB213SD:
    case ZYDIS_MNEMONIC_VFNMSUB213SS:
    case ZYDIS_MNEMONIC_VFMADD213PH:
    case ZYDIS_MNEMONIC_VFMADD213SH:
    case ZYDIS_MNEMONIC_VFMADDSUB213PH:
    case ZYDIS_MNEMONIC_VFMSUB213PH:
    case ZYDIS_MNEMONIC_VFMSUB213SH:
    case ZYDIS_MNEMONIC_VFMSUBADD213PH:
    case ZYDIS_MNEMONIC_VFNMADD213PH:
    case ZYDIS_MNEMONIC_VFNMADD213SH:
    case ZYDIS_MNEMONIC_VFNMSUB213PH:
    case ZYDIS_MNEMONIC_VFNMSUB213SH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "); // part 2 / 3"));
      return true;

    case ZYDIS_MNEMONIC_VFMADD231PD:
    case ZYDIS_MNEMONIC_VFMADD231PS:
    case ZYDIS_MNEMONIC_VFMADD231SD:
    case ZYDIS_MNEMONIC_VFMADD231SS:
    case ZYDIS_MNEMONIC_VFMADDSUB231PD:
    case ZYDIS_MNEMONIC_VFMADDSUB231PS:
    case ZYDIS_MNEMONIC_VFMSUB231PD:
    case ZYDIS_MNEMONIC_VFMSUB231PS:
    case ZYDIS_MNEMONIC_VFMSUB231SD:
    case ZYDIS_MNEMONIC_VFMSUB231SS:
    case ZYDIS_MNEMONIC_VFMSUBADD231PD:
    case ZYDIS_MNEMONIC_VFMSUBADD231PS:
    case ZYDIS_MNEMONIC_VFNMADD231PD:
    case ZYDIS_MNEMONIC_VFNMADD231PS:
    case ZYDIS_MNEMONIC_VFNMADD231SD:
    case ZYDIS_MNEMONIC_VFNMADD231SS:
    case ZYDIS_MNEMONIC_VFNMSUB231PD:
    case ZYDIS_MNEMONIC_VFNMSUB231PS:
    case ZYDIS_MNEMONIC_VFNMSUB231SD:
    case ZYDIS_MNEMONIC_VFNMSUB231SS:
    case ZYDIS_MNEMONIC_VFMADD231PH:
    case ZYDIS_MNEMONIC_VFMADD231SH:
    case ZYDIS_MNEMONIC_VFMADDSUB231PH:
    case ZYDIS_MNEMONIC_VFMSUB231PH:
    case ZYDIS_MNEMONIC_VFMSUB231SH:
    case ZYDIS_MNEMONIC_VFMSUBADD231PH:
    case ZYDIS_MNEMONIC_VFNMADD231PH:
    case ZYDIS_MNEMONIC_VFNMADD231SH:
    case ZYDIS_MNEMONIC_VFNMSUB231PH:
    case ZYDIS_MNEMONIC_VFNMSUB231SH:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "); // part 3 / 3"));
      return true;

    default:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ")"));
      break;
    }

    break;
  }

  default:
    *pHasTranslation = false;
    return false;
  }

  ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ";"));

  return true;
}

////////////////////////////////////////////////////////////////////////////////

struct ZydecLinearContextFormatInfo
{
  ZydecLinearContext *pContext = nullptr;
  ZydecFormattingInfo *pOriginalInfo = nullptr;
  size_t assignedRegisterCount = 0;
  ZydisRegister assignedRegister[8];
  uint32_t assignedRegisterValue[8];
};

void zydec_LinearContext_AfterCall(void *pUserData)
{
  ZydecLinearContextFormatInfo *pInfo = static_cast<ZydecLinearContextFormatInfo *>(pUserData);

  switch (pInfo->pOriginalInfo->afterCallRegisterRetentionMode)
  {
  case ZydecFormattingInfo::AfterCallRegisterRetentionMode::Windows:
  {
    for (size_t i = 0; i < ZYDIS_REGISTER_MAX_VALUE; i++)
    {
      switch (i)
      {
      case ZYDIS_REGISTER_RBX:
      case ZYDIS_REGISTER_RBP:
      case ZYDIS_REGISTER_RDI:
      case ZYDIS_REGISTER_RSI:
      case ZYDIS_REGISTER_RSP:
      case ZYDIS_REGISTER_R12:
      case ZYDIS_REGISTER_R13:
      case ZYDIS_REGISTER_R14:
      case ZYDIS_REGISTER_R15:
      case ZYDIS_REGISTER_XMM6:
      case ZYDIS_REGISTER_XMM7:
      case ZYDIS_REGISTER_XMM8:
      case ZYDIS_REGISTER_XMM9:
      case ZYDIS_REGISTER_XMM10:
      case ZYDIS_REGISTER_XMM11:
      case ZYDIS_REGISTER_XMM12:
      case ZYDIS_REGISTER_XMM13:
      case ZYDIS_REGISTER_XMM14:
      case ZYDIS_REGISTER_XMM15:
        break;

      default:
        pInfo->pContext->regInfo[i] = 0;
        break;
      }
    }

    break;
  }

  default:
  case ZydecFormattingInfo::AfterCallRegisterRetentionMode::Linux:
  {
    for (size_t i = 0; i < ZYDIS_REGISTER_MAX_VALUE; i++)
    {
      switch (i)
      {
      case ZYDIS_REGISTER_RBX:
      case ZYDIS_REGISTER_RSP:
      case ZYDIS_REGISTER_RBP:
      case ZYDIS_REGISTER_R12:
      case ZYDIS_REGISTER_R13:
      case ZYDIS_REGISTER_R14:
      case ZYDIS_REGISTER_R15:
        break;

      default:
        pInfo->pContext->regInfo[i] = 0;
        break;
      }
    }

    break;
  }
  }
}

uint32_t zydec_LinearContext_NextRegisterName(ZydecLinearContext *pContext)
{
  bool firstRun = true;
  uint32_t ret;

  while (true)
  {
    const uint64_t oldState = pContext->hashState;
    pContext->hashState = oldState * 6364136223846793005ULL | 1;

    const uint32_t xorshifted = (uint32_t)(((oldState >> 18) ^ oldState) >> 27);
    const uint32_t rot = (uint32_t)(oldState >> 59);

    ret = (xorshifted >> rot) | (xorshifted << (uint32_t)((-(int32_t)rot) & 31));

    if (!firstRun || ret != 0)
      break;

    firstRun = false;
  }
  
  return ret;
}

bool zydec_LinearContext_WriteRegisterName(char **pBufferPos, size_t *pRemainingSize, const ZydisRegister reg, const uint32_t registerName)
{
  if (!zydec_WriteRegisterRaw(pBufferPos, pRemainingSize, reg))
    return false;

  if (registerName != 0)
  {
    if (!zydec_WriteRaw(pBufferPos, pRemainingSize, "_"))
      return false;

    static const char syllables[256][3] = {
      "ba", "ca", "da", "fa", "ga", "ha", "ja", "ka", "la", "ma", "na", "pa", "qa", "ra", "sa", "ta", "va", "wa", "xa", "ya", "za",
      "be", "ce", "de", "fe", "ge", "he", "je", "ke", "le", "me", "ne", "pe", "qe", "re", "se", "te", "ve", "we", "xe", "ye", "ze",
      "bi", "ci", "di", "fi", "gi", "hi", "ji", "ki", "li", "mi", "ni", "pi", "qi", "ri", "si", "ti", "vi", "wi", "xi", "yi", "zi",
      "bo", "co", "do", "fo", "go", "ho", "jo", "ko", "lo", "mo", "no", "po", "qo", "ro", "so", "to", "vo", "wo", "xo", "yo", "zo",
      "bu", "cu", "du", "fu", "gu", "hu", "ju", "ku", "lu", "mu", "nu", "pu", "qu", "ru", "su", "tu", "vu", "wu", "xu", "yu", "zu",
      "Ba", "Ca", "Da", "Fa", "Ga", "Ha", "Ja", "Ka", "La", "Ma", "Na", "Pa", "Qa", "Ra", "Sa", "Ta", "Va", "Wa", "Xa", "Ya", "Za",
      "Be", "Ce", "De", "Fe", "Ge", "He", "Je", "Ke", "Le", "Me", "Ne", "Pe", "Qe", "Re", "Se", "Te", "Ve", "We", "Xe", "Ye", "Ze",
      "Bi", "Ci", "Di", "Fi", "Gi", "Hi", "Ji", "Ki", "Li", "Mi", "Ni", "Pi", "Qi", "Ri", "Si", "Ti", "Vi", "Wi", "Xi", "Yi", "Zi",
      "Bo", "Co", "Do", "Fo", "Go", "Ho", "Jo", "Ko", "Lo", "Mo", "No", "Po", "Qo", "Ro", "So", "To", "Vo", "Wo", "Xo", "Yo", "Zo",
      "Bu", "Cu", "Du", "Fu", "Gu", "Hu", "Ju", "Ku", "Lu", "Mu", "Nu", "Pu", "Qu", "Ru", "Su", "Tu", "Vu", "Wu", "Xu", "Yu", "Zu",
      "0a", "1a", "2a", "3a", "4a", "5a", "6a", "7a", "8a", "9a",
      /*"0e",*/ "1e", "2e", "3e", "4e", "5e", "6e", "7e", "8e", "9e",
      /*"0i",*/ "1i", "2i", "3i", "4i", "5i", "6i", "7i", "8i", "9i",
      /*"0o",*/ "1o", "2o", "3o", "4o", "5o", "6o", "7o", "8o", "9o",
      /*"0u",*/ "1u", "2u", "3u", "4u", "5u", "6u", "7u", "8u", "9u",
    };

    uint32_t val = registerName;

    for (size_t i = 0; i < sizeof(uint32_t); i += sizeof(uint8_t))
    {
      const uint8_t seg = (uint8_t)(val & 0xFF);

      if (!zydec_WriteRaw(pBufferPos, pRemainingSize, syllables[seg]))
        return false;

      val >>= 8;
    }
  }

  return true;
}

bool zydec_LinearContext_WriteRegister(char **pBufferPos, size_t *pRemainingSize, const ZydisRegister reg, void *pUserData)
{
  ZydecLinearContextFormatInfo *pInfo = static_cast<ZydecLinearContextFormatInfo *>(pUserData);

  return zydec_LinearContext_WriteRegisterName(pBufferPos, pRemainingSize, reg, pInfo->pContext->regInfo[reg]);
}

bool zydec_LinearContext_WriteResultRegister(char **pBufferPos, size_t *pRemainingSize, const ZydisRegister reg, void *pUserData)
{
  ZydecLinearContextFormatInfo *pInfo = static_cast<ZydecLinearContextFormatInfo *>(pUserData);

  const uint32_t newName = zydec_LinearContext_NextRegisterName(pInfo->pContext);
  const bool result = zydec_LinearContext_WriteRegisterName(pBufferPos, pRemainingSize, reg, newName);

  pInfo->assignedRegister[pInfo->assignedRegisterCount] = reg;
  pInfo->assignedRegisterValue[pInfo->assignedRegisterCount] = newName;
  pInfo->assignedRegisterCount++;

  return result;
}

bool zydec_TranslateInstructionWithLinearContext(ZydecLinearContext *pContext, const ZydisDecodedInstruction *pInstruction, const ZydisDecodedOperand *pOperands, const size_t operandCount, const size_t virtualAddress, char *buffer, const size_t bufferCapacity, bool *pHasTranslation, ZydecFormattingInfo *pInfo)
{
  ZydecLinearContextFormatInfo formatContextInfo;
  formatContextInfo.pContext = pContext;
  formatContextInfo.pOriginalInfo = pInfo;

  ZydecFormattingInfo newInfo = *pInfo;
  newInfo.simplifyValueSelfModification = false;
  newInfo.pRegUserData = newInfo.pCallUserData = &formatContextInfo;
  newInfo.pWriteRegister = zydec_LinearContext_WriteRegister;
  newInfo.pWriteResultRegister = zydec_LinearContext_WriteResultRegister;
  newInfo.pAfterCall = zydec_LinearContext_AfterCall;

  const bool result = zydec_TranslateInstructionWithoutContext(pInstruction, pOperands, operandCount, virtualAddress, buffer, bufferCapacity, pHasTranslation, &newInfo);

  for (size_t i = 0; i < formatContextInfo.assignedRegisterCount; i++)
    pContext->regInfo[formatContextInfo.assignedRegister[i]] = formatContextInfo.assignedRegisterValue[i];

  return result;
}

////////////////////////////////////////////////////////////////////////////////

static const char RegisterNameLut[][32] = {

    "",

    // General purpose registers  8-bit
    "al",
    "cl",
    "dl",
    "bl",
    "ah",
    "ch",
    "dh",
    "bh",
    "spl",
    "bpl",
    "sil",
    "dil",
    "r8b",
    "r9b",
    "r10b",
    "r11b",
    "r12b",
    "r13b",
    "r14b",
    "r15b",

    // General purpose registers 16-bit
    "ax",
    "cx",
    "dx",
    "bx",
    "sp",
    "bp",
    "si",
    "di",
    "r8w",
    "r9w",
    "r10w",
    "r11w",
    "r12w",
    "r13w",
    "r14w",
    "r15w",

    // General purpose registers 32-bit
    "eax",
    "ecx",
    "edx",
    "ebx",
    "esp",
    "ebp",
    "esi",
    "edi",
    "r8d",
    "r9d",
    "r10d",
    "r11d",
    "r12d",
    "r13d",
    "r14d",
    "r15d",

    // General purpose registers 64-bit
    "a",
    "c",
    "d",
    "b",
    "stack_pointer",
    "bp",
    "si",
    "di",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",

    // Floating point legacy registers
    "s0",
    "s1",
    "s2",
    "s3",
    "s4",
    "s5",
    "s6",
    "s7",
    "x87control",
    "x87status",
    "x87tag",

    // Floating point multimedia registers
    "mm0",
    "mm1",
    "mm2",
    "mm3",
    "mm4",
    "mm5",
    "mm6",
    "mm7",

    // Floating point vector registers 128-bit
    "x0",
    "x1",
    "x2",
    "x3",
    "x4",
    "x5",
    "x6",
    "x7",
    "x8",
    "x9",
    "x10",
    "x11",
    "x12",
    "x13",
    "x14",
    "x15",
    "x16",
    "x17",
    "x18",
    "x19",
    "x20",
    "x21",
    "x22",
    "x23",
    "x24",
    "x25",
    "x26",
    "x27",
    "x28",
    "x29",
    "x30",
    "x31",

    // Floating point vector registers 256-bit
    "y0",
    "y1",
    "y2",
    "y3",
    "y4",
    "y5",
    "y6",
    "y7",
    "y8",
    "y9",
    "y10",
    "y11",
    "y12",
    "y13",
    "y14",
    "y15",
    "y16",
    "y17",
    "y18",
    "y19",
    "y20",
    "y21",
    "y22",
    "y23",
    "y24",
    "y25",
    "y26",
    "y27",
    "y28",
    "y29",
    "y30",
    "y31",

    // Floating point vector registers 512-bit
    "z0",
    "z1",
    "z2",
    "z3",
    "z4",
    "z5",
    "z6",
    "z7",
    "z8",
    "z9",
    "z10",
    "z11",
    "z12",
    "z13",
    "z14",
    "z15",
    "z16",
    "z17",
    "z18",
    "z19",
    "z20",
    "z21",
    "z22",
    "z23",
    "z24",
    "z25",
    "z26",
    "z27",
    "z28",
    "z29",
    "z30",
    "z31",

    // Matrix registers
    "t0",
    "t1",
    "t2",
    "t3",
    "t4",
    "t5",
    "t6",
    "t7",

    // Flags registers
    "flags",
    "eflags",
    "rflags",

    // Instruction-pointer registers
    "ip",
    "eip",
    "instruction_pointer",

    // Segment registers
    "extra_segment",
    "code_segment",
    "stack_segment",
    "data_segment",
    "f_segment",
    "g_segment",

    // Table registers
    "table_gdtr",
    "table_ldtr",
    "table_idtr",
    "table_tr",

    // Test registers
    "test_tr0",
    "test_tr1",
    "test_tr2",
    "test_tr3",
    "test_tr4",
    "test_tr5",
    "test_tr6",
    "test_tr7",

    // Control registers
    "control_cr0",
    "control_cr1",
    "control_cr2",
    "control_cr3",
    "control_cr4",
    "control_cr5",
    "control_cr6",
    "control_cr7",
    "control_cr8",
    "control_cr9",
    "control_cr10",
    "control_cr11",
    "control_cr12",
    "control_cr13",
    "control_cr14",
    "control_cr15",

    // Debug registers
    "debug_dr0",
    "debug_dr1",
    "debug_dr2",
    "debug_dr3",
    "debug_dr4",
    "debug_dr5",
    "debug_dr6",
    "debug_dr7",
    "debug_dr8",
    "debug_dr9",
    "debug_dr10",
    "debug_dr11",
    "debug_dr12",
    "debug_dr13",
    "debug_dr14",
    "debug_dr15",

    // Mask registers
    "mask_k0",
    "mask_k1",
    "mask_k2",
    "mask_k3",
    "mask_k4",
    "mask_k5",
    "mask_k6",
    "mask_k7",

    // Bound registers
    "bound_bnd0",
    "bound_bnd1",
    "bound_bnd2",
    "bound_bnd3",
    "bound_bndcfg",
    "bound_bndstatus",

    // Uncategorized
    "mxcsr",
    "pkru",
    "xcr0",
    "uif",
};

////////////////////////////////////////////////////////////////////////////////

const char *zydec_ResolveRegisterPrefix(const ZydisRegister reg)
{
  switch (reg)
  {
  case ZYDIS_REGISTER_AL:
  case ZYDIS_REGISTER_CL:
  case ZYDIS_REGISTER_DL:
  case ZYDIS_REGISTER_BL:
  case ZYDIS_REGISTER_SPL:
  case ZYDIS_REGISTER_BPL:
  case ZYDIS_REGISTER_SIL:
  case ZYDIS_REGISTER_DIL:
  case ZYDIS_REGISTER_R8B:
  case ZYDIS_REGISTER_R9B:
  case ZYDIS_REGISTER_R10B:
  case ZYDIS_REGISTER_R11B:
  case ZYDIS_REGISTER_R12B:
  case ZYDIS_REGISTER_R13B:
  case ZYDIS_REGISTER_R14B:
  case ZYDIS_REGISTER_R15B:
    return "(i8)";

  case ZYDIS_REGISTER_AH:
  case ZYDIS_REGISTER_CH:
  case ZYDIS_REGISTER_DH:
  case ZYDIS_REGISTER_BH:
    return "(i8)(";

  case ZYDIS_REGISTER_AX:
  case ZYDIS_REGISTER_CX:
  case ZYDIS_REGISTER_DX:
  case ZYDIS_REGISTER_BX:
  case ZYDIS_REGISTER_SP:
  case ZYDIS_REGISTER_BP:
  case ZYDIS_REGISTER_SI:
  case ZYDIS_REGISTER_DI:
  case ZYDIS_REGISTER_R8W:
  case ZYDIS_REGISTER_R9W:
  case ZYDIS_REGISTER_R10W:
  case ZYDIS_REGISTER_R11W:
  case ZYDIS_REGISTER_R12W:
  case ZYDIS_REGISTER_R13W:
  case ZYDIS_REGISTER_R14W:
  case ZYDIS_REGISTER_R15W:
  case ZYDIS_REGISTER_FLAGS:
  case ZYDIS_REGISTER_IP:
    return "(i16)";

  case ZYDIS_REGISTER_EAX:
  case ZYDIS_REGISTER_ECX:
  case ZYDIS_REGISTER_EDX:
  case ZYDIS_REGISTER_EBX:
  case ZYDIS_REGISTER_ESP:
  case ZYDIS_REGISTER_EBP:
  case ZYDIS_REGISTER_ESI:
  case ZYDIS_REGISTER_EDI:
  case ZYDIS_REGISTER_R8D:
  case ZYDIS_REGISTER_R9D:
  case ZYDIS_REGISTER_R10D:
  case ZYDIS_REGISTER_R11D:
  case ZYDIS_REGISTER_R12D:
  case ZYDIS_REGISTER_R13D:
  case ZYDIS_REGISTER_R14D:
  case ZYDIS_REGISTER_R15D:
  case ZYDIS_REGISTER_EFLAGS:
  case ZYDIS_REGISTER_EIP:
    return "(i32)";

  case ZYDIS_REGISTER_RAX:
  case ZYDIS_REGISTER_RCX:
  case ZYDIS_REGISTER_RDX:
  case ZYDIS_REGISTER_RBX:
  case ZYDIS_REGISTER_RSP:
  case ZYDIS_REGISTER_RBP:
  case ZYDIS_REGISTER_RSI:
  case ZYDIS_REGISTER_RDI:
  case ZYDIS_REGISTER_R8:
  case ZYDIS_REGISTER_R9:
  case ZYDIS_REGISTER_R10:
  case ZYDIS_REGISTER_R11:
  case ZYDIS_REGISTER_R12:
  case ZYDIS_REGISTER_R13:
  case ZYDIS_REGISTER_R14:
  case ZYDIS_REGISTER_R15:
  case ZYDIS_REGISTER_RFLAGS:
  case ZYDIS_REGISTER_RIP:
    return "(i64)";

  case ZYDIS_REGISTER_ST0:
  case ZYDIS_REGISTER_ST1:
  case ZYDIS_REGISTER_ST2:
  case ZYDIS_REGISTER_ST3:
  case ZYDIS_REGISTER_ST4:
  case ZYDIS_REGISTER_ST5:
  case ZYDIS_REGISTER_ST6:
  case ZYDIS_REGISTER_ST7:
  case ZYDIS_REGISTER_MM0:
  case ZYDIS_REGISTER_MM1:
  case ZYDIS_REGISTER_MM2:
  case ZYDIS_REGISTER_MM3:
  case ZYDIS_REGISTER_MM4:
  case ZYDIS_REGISTER_MM5:
  case ZYDIS_REGISTER_MM6:
  case ZYDIS_REGISTER_MM7:
    return "(float)";

  case ZYDIS_REGISTER_XMM0:
  case ZYDIS_REGISTER_XMM1:
  case ZYDIS_REGISTER_XMM2:
  case ZYDIS_REGISTER_XMM3:
  case ZYDIS_REGISTER_XMM4:
  case ZYDIS_REGISTER_XMM5:
  case ZYDIS_REGISTER_XMM6:
  case ZYDIS_REGISTER_XMM7:
  case ZYDIS_REGISTER_XMM8:
  case ZYDIS_REGISTER_XMM9:
  case ZYDIS_REGISTER_XMM10:
  case ZYDIS_REGISTER_XMM11:
  case ZYDIS_REGISTER_XMM12:
  case ZYDIS_REGISTER_XMM13:
  case ZYDIS_REGISTER_XMM14:
  case ZYDIS_REGISTER_XMM15:
  case ZYDIS_REGISTER_XMM16:
  case ZYDIS_REGISTER_XMM17:
  case ZYDIS_REGISTER_XMM18:
  case ZYDIS_REGISTER_XMM19:
  case ZYDIS_REGISTER_XMM20:
  case ZYDIS_REGISTER_XMM21:
  case ZYDIS_REGISTER_XMM22:
  case ZYDIS_REGISTER_XMM23:
  case ZYDIS_REGISTER_XMM24:
  case ZYDIS_REGISTER_XMM25:
  case ZYDIS_REGISTER_XMM26:
  case ZYDIS_REGISTER_XMM27:
  case ZYDIS_REGISTER_XMM28:
  case ZYDIS_REGISTER_XMM29:
  case ZYDIS_REGISTER_XMM30:
  case ZYDIS_REGISTER_XMM31:
    return "(m128)";

  case ZYDIS_REGISTER_YMM0:
  case ZYDIS_REGISTER_YMM1:
  case ZYDIS_REGISTER_YMM2:
  case ZYDIS_REGISTER_YMM3:
  case ZYDIS_REGISTER_YMM4:
  case ZYDIS_REGISTER_YMM5:
  case ZYDIS_REGISTER_YMM6:
  case ZYDIS_REGISTER_YMM7:
  case ZYDIS_REGISTER_YMM8:
  case ZYDIS_REGISTER_YMM9:
  case ZYDIS_REGISTER_YMM10:
  case ZYDIS_REGISTER_YMM11:
  case ZYDIS_REGISTER_YMM12:
  case ZYDIS_REGISTER_YMM13:
  case ZYDIS_REGISTER_YMM14:
  case ZYDIS_REGISTER_YMM15:
  case ZYDIS_REGISTER_YMM16:
  case ZYDIS_REGISTER_YMM17:
  case ZYDIS_REGISTER_YMM18:
  case ZYDIS_REGISTER_YMM19:
  case ZYDIS_REGISTER_YMM20:
  case ZYDIS_REGISTER_YMM21:
  case ZYDIS_REGISTER_YMM22:
  case ZYDIS_REGISTER_YMM23:
  case ZYDIS_REGISTER_YMM24:
  case ZYDIS_REGISTER_YMM25:
  case ZYDIS_REGISTER_YMM26:
  case ZYDIS_REGISTER_YMM27:
  case ZYDIS_REGISTER_YMM28:
  case ZYDIS_REGISTER_YMM29:
  case ZYDIS_REGISTER_YMM30:
  case ZYDIS_REGISTER_YMM31:
    return "(m256)";

  case ZYDIS_REGISTER_ZMM0:
  case ZYDIS_REGISTER_ZMM1:
  case ZYDIS_REGISTER_ZMM2:
  case ZYDIS_REGISTER_ZMM3:
  case ZYDIS_REGISTER_ZMM4:
  case ZYDIS_REGISTER_ZMM5:
  case ZYDIS_REGISTER_ZMM6:
  case ZYDIS_REGISTER_ZMM7:
  case ZYDIS_REGISTER_ZMM8:
  case ZYDIS_REGISTER_ZMM9:
  case ZYDIS_REGISTER_ZMM10:
  case ZYDIS_REGISTER_ZMM11:
  case ZYDIS_REGISTER_ZMM12:
  case ZYDIS_REGISTER_ZMM13:
  case ZYDIS_REGISTER_ZMM14:
  case ZYDIS_REGISTER_ZMM15:
  case ZYDIS_REGISTER_ZMM16:
  case ZYDIS_REGISTER_ZMM17:
  case ZYDIS_REGISTER_ZMM18:
  case ZYDIS_REGISTER_ZMM19:
  case ZYDIS_REGISTER_ZMM20:
  case ZYDIS_REGISTER_ZMM21:
  case ZYDIS_REGISTER_ZMM22:
  case ZYDIS_REGISTER_ZMM23:
  case ZYDIS_REGISTER_ZMM24:
  case ZYDIS_REGISTER_ZMM25:
  case ZYDIS_REGISTER_ZMM26:
  case ZYDIS_REGISTER_ZMM27:
  case ZYDIS_REGISTER_ZMM28:
  case ZYDIS_REGISTER_ZMM29:
  case ZYDIS_REGISTER_ZMM30:
  case ZYDIS_REGISTER_ZMM31:
    return "(m512)";

  case ZYDIS_REGISTER_TMM0:
  case ZYDIS_REGISTER_TMM1:
  case ZYDIS_REGISTER_TMM2:
  case ZYDIS_REGISTER_TMM3:
  case ZYDIS_REGISTER_TMM4:
  case ZYDIS_REGISTER_TMM5:
  case ZYDIS_REGISTER_TMM6:
  case ZYDIS_REGISTER_TMM7:
    return "(matrix_tile)";

  default:
    return nullptr;
  }
}

const char *zydec_ResolveRegisterPostfix(const ZydisRegister reg)
{
  switch (reg)
  {
  case ZYDIS_REGISTER_AH:
  case ZYDIS_REGISTER_CH:
  case ZYDIS_REGISTER_DH:
  case ZYDIS_REGISTER_BH:
    return " >> 8)";

  default:
    return nullptr;
  }
}

////////////////////////////////////////////////////////////////////////////////

ZydisRegister zydec_ResolveBaseRegister(const ZydisRegister reg)
{
  switch (reg)
  {
  case ZYDIS_REGISTER_AL:
  case ZYDIS_REGISTER_AH:
  case ZYDIS_REGISTER_AX:
  case ZYDIS_REGISTER_EAX:
  case ZYDIS_REGISTER_RAX:
    return ZYDIS_REGISTER_RAX;

  case ZYDIS_REGISTER_CL:
  case ZYDIS_REGISTER_CH:
  case ZYDIS_REGISTER_CX:
  case ZYDIS_REGISTER_ECX:
  case ZYDIS_REGISTER_RCX:
    return ZYDIS_REGISTER_RCX;

  case ZYDIS_REGISTER_DL:
  case ZYDIS_REGISTER_DH:
  case ZYDIS_REGISTER_DX:
  case ZYDIS_REGISTER_EDX:
  case ZYDIS_REGISTER_RDX:
    return ZYDIS_REGISTER_RDX;

  case ZYDIS_REGISTER_BL:
  case ZYDIS_REGISTER_BH:
  case ZYDIS_REGISTER_BX:
  case ZYDIS_REGISTER_EBX:
  case ZYDIS_REGISTER_RBX:
    return ZYDIS_REGISTER_RBX;

  case ZYDIS_REGISTER_SPL:
  case ZYDIS_REGISTER_SP:
  case ZYDIS_REGISTER_ESP:
  case ZYDIS_REGISTER_RSP:
    return ZYDIS_REGISTER_RSP;

  case ZYDIS_REGISTER_BPL:
  case ZYDIS_REGISTER_BP:
  case ZYDIS_REGISTER_EBP:
  case ZYDIS_REGISTER_RBP:
    return ZYDIS_REGISTER_RBP;

  case ZYDIS_REGISTER_SIL:
  case ZYDIS_REGISTER_SI:
  case ZYDIS_REGISTER_ESI:
  case ZYDIS_REGISTER_RSI:
    return ZYDIS_REGISTER_RSI;

  case ZYDIS_REGISTER_DIL:
  case ZYDIS_REGISTER_DI:
  case ZYDIS_REGISTER_EDI:
  case ZYDIS_REGISTER_RDI:
    return ZYDIS_REGISTER_RDI;

  case ZYDIS_REGISTER_R8B:
  case ZYDIS_REGISTER_R8W:
  case ZYDIS_REGISTER_R8D:
  case ZYDIS_REGISTER_R8:
    return ZYDIS_REGISTER_R8;

  case ZYDIS_REGISTER_R9B:
  case ZYDIS_REGISTER_R9W:
  case ZYDIS_REGISTER_R9D:
  case ZYDIS_REGISTER_R9:
    return ZYDIS_REGISTER_R9;

  case ZYDIS_REGISTER_R10B:
  case ZYDIS_REGISTER_R10W:
  case ZYDIS_REGISTER_R10D:
  case ZYDIS_REGISTER_R10:
    return ZYDIS_REGISTER_R10;

  case ZYDIS_REGISTER_R11B:
  case ZYDIS_REGISTER_R11W:
  case ZYDIS_REGISTER_R11D:
  case ZYDIS_REGISTER_R11:
    return ZYDIS_REGISTER_R11;

  case ZYDIS_REGISTER_R12B:
  case ZYDIS_REGISTER_R12W:
  case ZYDIS_REGISTER_R12D:
  case ZYDIS_REGISTER_R12:
    return ZYDIS_REGISTER_R12;

  case ZYDIS_REGISTER_R13B:
  case ZYDIS_REGISTER_R13W:
  case ZYDIS_REGISTER_R13D:
  case ZYDIS_REGISTER_R13:
    return ZYDIS_REGISTER_R13;

  case ZYDIS_REGISTER_R14B:
  case ZYDIS_REGISTER_R14W:
  case ZYDIS_REGISTER_R14D:
  case ZYDIS_REGISTER_R14:
    return ZYDIS_REGISTER_R14;

  case ZYDIS_REGISTER_R15B:
  case ZYDIS_REGISTER_R15W:
  case ZYDIS_REGISTER_R15D:
  case ZYDIS_REGISTER_R15:
    return ZYDIS_REGISTER_R15;

  case ZYDIS_REGISTER_FLAGS:
  case ZYDIS_REGISTER_EFLAGS:
  case ZYDIS_REGISTER_RFLAGS:
    return ZYDIS_REGISTER_RFLAGS;

  case ZYDIS_REGISTER_IP:
  case ZYDIS_REGISTER_EIP:
  case ZYDIS_REGISTER_RIP:
    return ZYDIS_REGISTER_RIP;

  default:
    return reg;
  }
}

////////////////////////////////////////////////////////////////////////////////

bool zydec_WriteUInt(char **pBufferPos, size_t *pRemainingSize, const uint64_t value)
{
  if (value == 0)
    return zydec_WriteRaw(pBufferPos, pRemainingSize, "0");

  char buffer[20];
  buffer[sizeof(buffer) - 1] = '\0';
  char *bufFromEnd = buffer + sizeof(buffer) - 2;
  uint64_t tmp = value;

  while (tmp >= 10)
  {
    *bufFromEnd = (char)('0' + (tmp % 10));
    bufFromEnd--;
    tmp /= 10;
  }

  if (tmp != 0)
    *bufFromEnd = (char)('0' + (tmp % 10));
  else
    bufFromEnd++;

  return zydec_WriteRaw(pBufferPos, pRemainingSize, bufFromEnd);
}

bool zydec_WriteHex(char **pBufferPos, size_t *pRemainingSize, const uint64_t value)
{
  if (value == 0)
    return zydec_WriteRaw(pBufferPos, pRemainingSize, "0x0");

  char buffer[2 + 2 * 8 + 1];
  buffer[sizeof(buffer) - 1] = '\0';
  char *bufFromEnd = buffer + sizeof(buffer) - 2;
  uint64_t tmp = value;

  const char lut[] = "0123456789ABCDEF";

  while (tmp >= 0xF)
  {
    *bufFromEnd = lut[tmp & 0xF];
    bufFromEnd--;
    tmp >>= 4;
  }

  if (tmp != 0)
  {
    *bufFromEnd = lut[tmp & 0xF];
    bufFromEnd--;
  }

  *bufFromEnd = 'x';
  bufFromEnd--;
  *bufFromEnd = '0';

  return zydec_WriteRaw(pBufferPos, pRemainingSize, bufFromEnd);
}

bool zydec_WriteInt(char **pBufferPos, size_t *pRemainingSize, const int64_t value)
{
  if (value < 0)
  {
    ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, "-"));
    return zydec_WriteUInt(pBufferPos, pRemainingSize, (uint64_t)-value);
  }
  else
  {
    return zydec_WriteUInt(pBufferPos, pRemainingSize, (uint64_t)value);
  }
}

bool zydec_WriteResultOperand(char **pBufferPos, size_t *pRemainingSize, const ZydisDecodedOperand *pOperand, const size_t virtualAddress, ZydecFormattingInfo *pInfo, const ZydecOperandFlags flags /* = zof_none */)
{
  return zydec_WriteOperand(pBufferPos, pRemainingSize, pOperand, virtualAddress, pInfo, flags, true);
}

bool zydec_WriteOperand(char **pBufferPos, size_t *pRemainingSize, const ZydisDecodedOperand *pOperand, const size_t virtualAddress, ZydecFormattingInfo *pInfo, const ZydecOperandFlags flags /* = zof_none */, const bool isNewResult /* = false */)
{
  switch (pOperand->type)
  {
  case ZYDIS_OPERAND_TYPE_REGISTER:
  {
    ERROR_CHECK(zydec_WriteRegister(pBufferPos, pRemainingSize, pOperand->reg.value, pInfo, isNewResult));
    break;
  }

  case ZYDIS_OPERAND_TYPE_MEMORY:
  {
    ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, (pOperand->mem.type == ZYDIS_MEMOP_TYPE_AGEN || !!(flags & zof_noAddressDeref)) ? "(" : "*("));

    switch (pOperand->mem.type)
    {
    case ZYDIS_MEMOP_TYPE_MEM:
    case ZYDIS_MEMOP_TYPE_VSIB:
    {
      ERROR_CHECK(zydec_WriteRegister(pBufferPos, pRemainingSize, pOperand->mem.segment, pInfo, false));
      ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, ": "));

      if (pOperand->mem.base == ZYDIS_REGISTER_RIP && (pOperand->mem.disp.has_displacement || pOperand->mem.index == ZYDIS_REGISTER_NONE))
      {
        uint64_t ptr = virtualAddress;

        if (pOperand->mem.disp.has_displacement)
          ptr += pOperand->mem.disp.value;

        char friendlyName[1024];
        size_t friendlyNameOffset = 0;

        if (pInfo->pResolveAddressToFriendlyName != nullptr && pInfo->pResolveAddressToFriendlyName(ptr, friendlyName, sizeof(friendlyName), &friendlyNameOffset, pInfo->pUserData))
        {
          if (friendlyNameOffset != 0)
            zydec_WriteRaw(pBufferPos, pRemainingSize, "(");

          zydec_WriteRaw(pBufferPos, pRemainingSize, friendlyName);

          if (friendlyNameOffset != 0)
          {
            zydec_WriteRaw(pBufferPos, pRemainingSize, " + ");
            ERROR_CHECK(zydec_WriteHex(pBufferPos, pRemainingSize, friendlyNameOffset));
            zydec_WriteRaw(pBufferPos, pRemainingSize, ")");
          }
        }
        else
        {
          ERROR_CHECK(zydec_WriteHex(pBufferPos, pRemainingSize, ptr));
        }
      }
      else
      {
        if (pOperand->mem.base != ZYDIS_REGISTER_NONE)
          ERROR_CHECK(zydec_WriteRegister(pBufferPos, pRemainingSize, pOperand->mem.base, pInfo, false));

        if (pOperand->mem.disp.has_displacement && pOperand->mem.disp.value != 0)
        {
          if (pOperand->mem.base != ZYDIS_REGISTER_NONE)
            ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, " "));

          ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, "+ "));
          ERROR_CHECK(zydec_WriteInt(pBufferPos, pRemainingSize, pOperand->mem.disp.value));
        }
        else if (pOperand->mem.index != ZYDIS_REGISTER_NONE)
        {
          if (pOperand->mem.base != ZYDIS_REGISTER_NONE)
            ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, " "));

          ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, "+ "));

          if (pOperand->mem.scale != 1)
            ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, "("));

          ERROR_CHECK(zydec_WriteRegister(pBufferPos, pRemainingSize, pOperand->mem.index, pInfo, false));

          if (pOperand->mem.scale != 1)
          {
            ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, " * "));
            ERROR_CHECK(zydec_WriteUInt(pBufferPos, pRemainingSize, pOperand->mem.scale));
            ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, ")"));
          }
        }
      }

      ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, ")"));

      break;
    }

    case ZYDIS_MEMOP_TYPE_MIB:
    case ZYDIS_MEMOP_TYPE_AGEN:
    {
      ERROR_CHECK(zydec_WriteRegister(pBufferPos, pRemainingSize, pOperand->mem.segment, pInfo, false));
      ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, ": "));

      if (pOperand->mem.base == ZYDIS_REGISTER_RIP)
      {
        uint64_t ptr = virtualAddress;

        if (pOperand->mem.disp.has_displacement)
          ptr += pOperand->mem.disp.value;

        char friendlyName[1024];
        size_t friendlyNameOffset = 0;

        if (pInfo->pResolveAddressToFriendlyName != nullptr && pInfo->pResolveAddressToFriendlyName(ptr, friendlyName, sizeof(friendlyName), &friendlyNameOffset, pInfo->pUserData))
        {
          if (friendlyNameOffset != 0)
            zydec_WriteRaw(pBufferPos, pRemainingSize, "(");

          zydec_WriteRaw(pBufferPos, pRemainingSize, friendlyName);

          if (friendlyNameOffset != 0)
          {
            zydec_WriteRaw(pBufferPos, pRemainingSize, " + ");
            ERROR_CHECK(zydec_WriteHex(pBufferPos, pRemainingSize, friendlyNameOffset));
            zydec_WriteRaw(pBufferPos, pRemainingSize, ")");
          }
        }
        else
        {
          ERROR_CHECK(zydec_WriteHex(pBufferPos, pRemainingSize, ptr));
        }
      }
      else
      {
        if (pOperand->mem.base != ZYDIS_REGISTER_NONE)
          ERROR_CHECK(zydec_WriteRegister(pBufferPos, pRemainingSize, pOperand->mem.base, pInfo, false));

        if (pOperand->mem.disp.has_displacement && pOperand->mem.disp.value != 0)
        {
          if (pOperand->mem.base != ZYDIS_REGISTER_NONE)
            ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, " "));

          ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, "+ "));
          ERROR_CHECK(zydec_WriteInt(pBufferPos, pRemainingSize, pOperand->mem.disp.value));
        }
        else if (pOperand->mem.index != ZYDIS_REGISTER_NONE)
        {
          if (pOperand->mem.base != ZYDIS_REGISTER_NONE)
            ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, " "));

          ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, "+ "));

          if (pOperand->mem.scale != 1)
            ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, "("));

          ERROR_CHECK(zydec_WriteRegister(pBufferPos, pRemainingSize, pOperand->mem.index, pInfo, false));

          if (pOperand->mem.scale != 1)
          {
            ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, " * "));
            ERROR_CHECK(zydec_WriteUInt(pBufferPos, pRemainingSize, pOperand->mem.scale));
            ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, ")"));
          }
        }

        ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, ")"));
      }

      break;
    }

    default:
      return false;
    }

    break;
  }

  case ZYDIS_OPERAND_TYPE_IMMEDIATE:
  {
    if (pOperand->imm.is_relative)
    {
      char friendlyName[1024];
      size_t friendlyNameOffset = 0;

      if (pInfo->pResolveAddressToFriendlyName != nullptr && pInfo->pResolveAddressToFriendlyName(virtualAddress + pOperand->imm.value.u, friendlyName, sizeof(friendlyName), &friendlyNameOffset, pInfo->pUserData))
      {
        if (friendlyNameOffset != 0)
          zydec_WriteRaw(pBufferPos, pRemainingSize, "(");

        zydec_WriteRaw(pBufferPos, pRemainingSize, friendlyName);

        if (friendlyNameOffset != 0)
        {
          zydec_WriteRaw(pBufferPos, pRemainingSize, " + ");
          ERROR_CHECK(zydec_WriteHex(pBufferPos, pRemainingSize, friendlyNameOffset));
          zydec_WriteRaw(pBufferPos, pRemainingSize, ")");
        }
      }
      else
      {
        ERROR_CHECK(zydec_WriteHex(pBufferPos, pRemainingSize, virtualAddress + pOperand->imm.value.u));
      }
    }
    else
    {
      if (pOperand->imm.is_signed)
        ERROR_CHECK(zydec_WriteInt(pBufferPos, pRemainingSize, pOperand->imm.value.s));
      else
        ERROR_CHECK(zydec_WriteUInt(pBufferPos, pRemainingSize, pOperand->imm.value.u));
    }

    break;
  }

  default:
    return false;
  }

  return true;
}

bool zydec_WriteRegisterRaw(char **pBufferPos, size_t *pRemainingSize, const ZydisRegister reg)
{
  if (reg >= sizeof(RegisterNameLut) / sizeof(RegisterNameLut[0]))
    return false;

  ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, RegisterNameLut[reg]));

  return true;
}

bool zydec_WriteRegister(char **pBufferPos, size_t *pRemainingSize, const ZydisRegister reg, ZydecFormattingInfo *pInfo, const bool isNewResult)
{
  const char *pre = zydec_ResolveRegisterPrefix(reg);
  const char *post = zydec_ResolveRegisterPostfix(reg);
  const ZydisRegister baseReg = zydec_ResolveBaseRegister(reg);

  if (pre != nullptr && !zydec_WriteRaw(pBufferPos, pRemainingSize, pre))
    return false;

  if (pInfo == nullptr || (isNewResult && pInfo->pWriteResultRegister == nullptr) || (!isNewResult && pInfo->pWriteRegister == nullptr))
    if (!zydec_WriteRegisterRaw(pBufferPos, pRemainingSize, baseReg))
      return false;

  if (isNewResult)
  {
    if (!pInfo->pWriteResultRegister(pBufferPos, pRemainingSize, baseReg, pInfo->pRegUserData))
      return false;
  }
  else
  {
    if (!pInfo->pWriteRegister(pBufferPos, pRemainingSize, baseReg, pInfo->pRegUserData))
      return false;
  }

  if (post != nullptr && !zydec_WriteRaw(pBufferPos, pRemainingSize, post))
    return false;

  return true;
}

bool zydec_WriteRaw(char **pBufferPos, size_t *pRemainingSize, const char *text)
{
  const size_t length = strlen(text);

  if (length > *pRemainingSize)
    return false;

  memcpy(*pBufferPos, text, length + 1);

  (*pRemainingSize) -= length;
  (*pBufferPos) += length;

  return true;
}
