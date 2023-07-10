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

bool zydec_WriteRaw(char **pBufferPos, size_t *pRemainingSize, const char *text);
bool zydec_WriteOperand(char **pBufferPos, size_t *pRemainingSize, const ZydisDecodedOperand *pOperand, const size_t virtualAddress);
bool zydec_WriteRegister(char **pBufferPos, size_t *pRemainingSize, const ZydisRegister reg);
bool zydec_WriteHex(char **pBufferPos, size_t *pRemainingSize, const uint64_t value);
bool zydec_WriteUInt(char **pBufferPos, size_t *pRemainingSize, const uint64_t value);
bool zydec_WriteInt(char **pBufferPos, size_t *pRemainingSize, const int64_t value);

////////////////////////////////////////////////////////////////////////////////

#define ERROR_CHECK(a) do { if (!(a)) return false; } while (false)

////////////////////////////////////////////////////////////////////////////////

bool zydec_TranslateInstructionWithoutContext(const ZydisDecodedInstruction *pInstruction, const ZydisDecodedOperand *pOperands, const size_t operandCount, const size_t virtualAddress, char *buffer, const size_t bufferCapacity, bool *pHasTranslation)
{
  if (pInstruction == nullptr || pOperands == nullptr || operandCount == 0 || buffer == nullptr || bufferCapacity == 0 || pHasTranslation == nullptr)
    return false;

  char *bufferPos = buffer;
  size_t remainingSize = bufferCapacity - 1;

  *pHasTranslation = true;
  bufferPos[0] = '\0';

  switch (pInstruction->mnemonic)
  {
  case ZYDIS_MNEMONIC_MOV:
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[1], virtualAddress));
    break;

  case ZYDIS_MNEMONIC_LEA:
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = &"));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[1], virtualAddress));
    break;

  case ZYDIS_MNEMONIC_TEST:
  case ZYDIS_MNEMONIC_CMP:
  {
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "compare("));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ", "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[1], virtualAddress));

    if (pInstruction->mnemonic == ZYDIS_MNEMONIC_TEST)
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ") // set carry_flag, parity_flag, zero_flag"));
    else if (pInstruction->mnemonic == ZYDIS_MNEMONIC_CMP)
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ") // set carry_flag, overflow_flag, signed_flag, zero_flag, aux_carry_flag and parity_flag"));
    else
      return false;

    return true;
  }

  case ZYDIS_MNEMONIC_CALL:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "("));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ")()")); // TODO: Add callback for function names.
    break;

  case ZYDIS_MNEMONIC_JMP:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    break;

  case ZYDIS_MNEMONIC_JB:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (carry_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if below"));
    return true;

  case ZYDIS_MNEMONIC_JBE:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (carry_flag || zero_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if below or equal"));
    return true;

  case ZYDIS_MNEMONIC_JCXZ:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if ((u16)c == 0) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    break;

  case ZYDIS_MNEMONIC_JECXZ:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if ((u32)c == 0) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    break;

  case ZYDIS_MNEMONIC_JL:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (sign_flag != overflow_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if less"));
    return true;

  case ZYDIS_MNEMONIC_JLE:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (zero_flag || sign_flag != overflow_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if less or equal"));
    return true;

  case ZYDIS_MNEMONIC_JNB:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (!carry_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if not below"));
    return true;

  case ZYDIS_MNEMONIC_JNBE:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (!carry_flag && !zero_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if not below or equal"));
    return true;

  case ZYDIS_MNEMONIC_JNL:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (sign_flag && overflow_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if not less"));
    return true;

  case ZYDIS_MNEMONIC_JNLE:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (!zero_flag && sign_flag == overflow_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if not less or equal"));
    return true;

  case ZYDIS_MNEMONIC_JNO:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (!overflow_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    break;

  case ZYDIS_MNEMONIC_JNP:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (!parity_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    break;

  case ZYDIS_MNEMONIC_JNS:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (!sign_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    break;

  case ZYDIS_MNEMONIC_JNZ:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (!zero_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if not zero / not equal"));
    return true;

  case ZYDIS_MNEMONIC_JO:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (overflow_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    break;

  case ZYDIS_MNEMONIC_JP:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (parity_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    break;

  case ZYDIS_MNEMONIC_JS:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (sign_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    break;

  case ZYDIS_MNEMONIC_JZ:
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "if (zero_flag) goto "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "; // if zero / equal"));
    return true;

  case ZYDIS_MNEMONIC_SUB:
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " -= "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[1], virtualAddress));
    break;

  case ZYDIS_MNEMONIC_ADD:
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " += "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[1], virtualAddress));
    break;

  case ZYDIS_MNEMONIC_AND:
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " &= "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[1], virtualAddress));
    break;

  case ZYDIS_MNEMONIC_OR:
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " |= "));
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[1], virtualAddress));
    break;

  case ZYDIS_MNEMONIC_MOVAPS:
  case ZYDIS_MNEMONIC_MOVAPD:
  case ZYDIS_MNEMONIC_VMOVDQA:
  case ZYDIS_MNEMONIC_VMOVDQA32:
  case ZYDIS_MNEMONIC_VMOVDQA64:
  {
    bool isReg2RegMove = false;

    if (pOperands[0].type == ZYDIS_OPERAND_TYPE_MEMORY || pOperands[0].type == ZYDIS_OPERAND_TYPE_POINTER)
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_aligned_store"));
    else if (pOperands[1].type == ZYDIS_OPERAND_TYPE_MEMORY || pOperands[1].type == ZYDIS_OPERAND_TYPE_POINTER)
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_aligned_load"));
    else
      isReg2RegMove = true;

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

      case ZYDIS_MNEMONIC_VMOVDQA:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_si("));
        break;

      case ZYDIS_MNEMONIC_VMOVDQA32:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_epi32("));
        break;

      case ZYDIS_MNEMONIC_VMOVDQA64:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_epi64("));
        break;

      default:
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "("));
        break;
      }
    }

    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));

    if (isReg2RegMove)
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));
    else
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ", "));

    for (size_t operandIndex = 1; operandIndex < pInstruction->operand_count; operandIndex++)
    {
      if (operandIndex > 1)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ", "));

      ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[operandIndex], virtualAddress));
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
  case ZYDIS_MNEMONIC_VMOVQ:
  case ZYDIS_MNEMONIC_VMOVD:
  case ZYDIS_MNEMONIC_VMOVSS:
  case ZYDIS_MNEMONIC_VMOVSD:
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

    if (pOperands[0].type == ZYDIS_OPERAND_TYPE_MEMORY || pOperands[0].type == ZYDIS_OPERAND_TYPE_POINTER)
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_unaligned_store"));
    else if (pOperands[1].type == ZYDIS_OPERAND_TYPE_MEMORY || pOperands[1].type == ZYDIS_OPERAND_TYPE_POINTER)
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_unaligned_load"));
    else if (pInstruction->operand_count == 2)
      isReg2RegMove = true;
    else
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_move"));

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

    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));

    if (isReg2RegMove)
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));
    else
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ", "));

    for (size_t operandIndex = 1; operandIndex < pInstruction->operand_count; operandIndex++)
    {
      if (operandIndex > 1)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ", "));

      ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[operandIndex], virtualAddress));
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
  case ZYDIS_MNEMONIC_CVTTSS2SI:
  case ZYDIS_MNEMONIC_VCVTTSS2SI:
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
  {
    ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[0], virtualAddress));
    ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, " = "));

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

    case ZYDIS_MNEMONIC_CVTTSS2SI:
    case ZYDIS_MNEMONIC_VCVTTSS2SI:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_cvttss_si("));
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
      break;

    case ZYDIS_MNEMONIC_VPGATHERDQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i32gather_epi64("));
      break;

    case ZYDIS_MNEMONIC_VGATHERDPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i32gather_pd("));
      break;

    case ZYDIS_MNEMONIC_VGATHERDPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i32gather_ps("));
      break;
      
    case ZYDIS_MNEMONIC_VPGATHERQD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i64gather_epi32("));
      break;

    case ZYDIS_MNEMONIC_VPGATHERQQ:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i64gather_epi64("));
      break;

    case ZYDIS_MNEMONIC_VGATHERQPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i64gather_pd("));
      break;

    case ZYDIS_MNEMONIC_VGATHERQPS:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_i64gather_ps("));
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
      if (pOperands[1].type == ZYDIS_OPERAND_TYPE_MEMORY || pOperands[1].type == ZYDIS_OPERAND_TYPE_POINTER)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_loaddup_pd("));
      else
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_movedup_pd("));
      break;

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
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_movemask_epi8("));
      break;

    case ZYDIS_MNEMONIC_MOVMSKPD:
    case ZYDIS_MNEMONIC_VMOVMSKPD:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_movemask_pd("));
      break;

    case ZYDIS_MNEMONIC_MOVMSKPS:
    case ZYDIS_MNEMONIC_VMOVMSKPS:
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

    default:
      ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, "_mm_??_("));
      break;
    }

    for (size_t operandIndex = 1; operandIndex < pInstruction->operand_count; operandIndex++)
    {
      if (operandIndex > 1)
        ERROR_CHECK(zydec_WriteRaw(&bufferPos, &remainingSize, ", "));

      ERROR_CHECK(zydec_WriteOperand(&bufferPos, &remainingSize, &pOperands[operandIndex], virtualAddress));
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

static const char RegisterNameLut[][32] = {

    "",

    // General purpose registers  8-bit
    "(i8)a",
    "(i8)c",
    "(i8)d",
    "(i8)b",
    "(i8)(a >> 8)",
    "(i8)(c >> 8)",
    "(i8)(d >> 8)",
    "(i8)(b >> 8)",
    "(i8)stack_pointer",
    "(i8)bp",
    "(i8)si",
    "(i8)di",
    "(i8)r8",
    "(i8)r9",
    "(i8)r10",
    "(i8)r11",
    "(i8)r12",
    "(i8)r13",
    "(i8)r14",
    "(i8)r15",

    // General purpose registers 16-bit
    "(i16)a",
    "(i16)c",
    "(i16)d",
    "(i16)b",
    "(i16)stack_pointer",
    "(i16)bp",
    "(i16)si",
    "(i16)di",
    "(i16)r8",
    "(i16)r9",
    "(i16)r10",
    "(i16)r11",
    "(i16)r12",
    "(i16)r13",
    "(i16)r14",
    "(i16)r15",

    // General purpose registers 32-bit
    "(i32)ax",
    "(i32)cx",
    "(i32)dx",
    "(i32)bx",
    "(i32)stack_pointer",
    "(i32)bp",
    "(i32)si",
    "(i32)di",
    "(i32)r8",
    "(i32)r9",
    "(i32)r10",
    "(i32)r11",
    "(i32)r12",
    "(i32)r13",
    "(i32)r14",
    "(i32)r15",

    // General purpose registers 64-bit
    "(i64)a",
    "(i64)c",
    "(i64)d",
    "(i64)b",
    "(i64)stack_pointer",
    "(i64)bp",
    "(i64)si",
    "(i64)di",
    "(i64)r8",
    "(i64)r9",
    "(i64)r10",
    "(i64)r11",
    "(i64)r12",
    "(i64)r13",
    "(i64)r14",
    "(i64)r15",

    // Floating point legacy registers
    "(float)s0",
    "(float)s1",
    "(float)s2",
    "(float)s3",
    "(float)s4",
    "(float)s5",
    "(float)s6",
    "(float)s7",
    "x87control",
    "x87status",
    "x87tag",

    // Floating point multimedia registers
    "(float)mm0",
    "(float)mm1",
    "(float)mm2",
    "(float)mm3",
    "(float)mm4",
    "(float)mm5",
    "(float)mm6",
    "(float)mm7",

    // Floating point vector registers 128-bit
    "(m128)x0",
    "(m128)x1",
    "(m128)x2",
    "(m128)x3",
    "(m128)x4",
    "(m128)x5",
    "(m128)x6",
    "(m128)x7",
    "(m128)x8",
    "(m128)x9",
    "(m128)x10",
    "(m128)x11",
    "(m128)x12",
    "(m128)x13",
    "(m128)x14",
    "(m128)x15",
    "(m128)x16",
    "(m128)x17",
    "(m128)x18",
    "(m128)x19",
    "(m128)x20",
    "(m128)x21",
    "(m128)x22",
    "(m128)x23",
    "(m128)x24",
    "(m128)x25",
    "(m128)x26",
    "(m128)x27",
    "(m128)x28",
    "(m128)x29",
    "(m128)x30",
    "(m128)x31",

    // Floating point vector registers 256-bit
    "(m256)y0",
    "(m256)y1",
    "(m256)y2",
    "(m256)y3",
    "(m256)y4",
    "(m256)y5",
    "(m256)y6",
    "(m256)y7",
    "(m256)y8",
    "(m256)y9",
    "(m256)y10",
    "(m256)y11",
    "(m256)y12",
    "(m256)y13",
    "(m256)y14",
    "(m256)y15",
    "(m256)y16",
    "(m256)y17",
    "(m256)y18",
    "(m256)y19",
    "(m256)y20",
    "(m256)y21",
    "(m256)y22",
    "(m256)y23",
    "(m256)y24",
    "(m256)y25",
    "(m256)y26",
    "(m256)y27",
    "(m256)y28",
    "(m256)y29",
    "(m256)y30",
    "(m256)y31",

    // Floating point vector registers 512-bit
    "(m512)z0",
    "(m512)z1",
    "(m512)z2",
    "(m512)z3",
    "(m512)z4",
    "(m512)z5",
    "(m512)z6",
    "(m512)z7",
    "(m512)z8",
    "(m512)z9",
    "(m512)z10",
    "(m512)z11",
    "(m512)z12",
    "(m512)z13",
    "(m512)z14",
    "(m512)z15",
    "(m512)z16",
    "(m512)z17",
    "(m512)z18",
    "(m512)z19",
    "(m512)z20",
    "(m512)z21",
    "(m512)z22",
    "(m512)z23",
    "(m512)z24",
    "(m512)z25",
    "(m512)z26",
    "(m512)z27",
    "(m512)z28",
    "(m512)z29",
    "(m512)z30",
    "(m512)z31",

    // Matrix registers
    "(matrix_tile)t0",
    "(matrix_tile)t1",
    "(matrix_tile)t2",
    "(matrix_tile)t3",
    "(matrix_tile)t4",
    "(matrix_tile)t5",
    "(matrix_tile)t6",
    "(matrix_tile)t7",

    // Flags registers
    "flags",
    "eflags",
    "rflags",

    // Instruction-pointer registers
    "(i16)instruction_pointer",
    "(i32)instruction_pointer",
    "(i64)instruction_pointer",

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

bool zydec_WriteOperand(char **pBufferPos, size_t *pRemainingSize, const ZydisDecodedOperand *pOperand, const size_t virtualAddress)
{
  switch (pOperand->type)
  {
  case ZYDIS_OPERAND_TYPE_REGISTER:
  {
    ERROR_CHECK(zydec_WriteRegister(pBufferPos, pRemainingSize, pOperand->reg.value));
    break;
  }

  case ZYDIS_OPERAND_TYPE_MEMORY:
  {
    ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, pOperand->mem.type == ZYDIS_MEMOP_TYPE_AGEN ? "(" : "*("));

    switch (pOperand->mem.type)
    {
    case ZYDIS_MEMOP_TYPE_MEM:
    case ZYDIS_MEMOP_TYPE_VSIB:
    {
      ERROR_CHECK(zydec_WriteRegister(pBufferPos, pRemainingSize, pOperand->mem.segment));
      ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, ": "));
      ERROR_CHECK(zydec_WriteRegister(pBufferPos, pRemainingSize, pOperand->mem.base));

      if (pOperand->mem.disp.has_displacement)
      {
        if (pOperand->mem.disp.value != 0)
        {
          ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, " + "));
          ERROR_CHECK(zydec_WriteInt(pBufferPos, pRemainingSize, pOperand->mem.disp.value));
        }
      }
      else if (pOperand->mem.index != ZYDIS_REGISTER_NONE)
      {
        ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, " + "));
        
        if (pOperand->mem.scale != 1)
          ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, "("));

        ERROR_CHECK(zydec_WriteRegister(pBufferPos, pRemainingSize, pOperand->mem.index));

        if (pOperand->mem.scale != 1)
        {
          ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, " * "));
          ERROR_CHECK(zydec_WriteUInt(pBufferPos, pRemainingSize, pOperand->mem.scale));
          ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, ")"));
        }
      }

      ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, ")"));

      break;
    }

    case ZYDIS_MEMOP_TYPE_MIB:
    case ZYDIS_MEMOP_TYPE_AGEN:
    {
      ERROR_CHECK(zydec_WriteRegister(pBufferPos, pRemainingSize, pOperand->mem.segment));
      ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, ": "));
      ERROR_CHECK(zydec_WriteRegister(pBufferPos, pRemainingSize, pOperand->mem.base));

      if (pOperand->mem.disp.has_displacement)
      {
        ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, " + "));
        ERROR_CHECK(zydec_WriteInt(pBufferPos, pRemainingSize, pOperand->mem.disp.value));
      }

      ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, ")"));

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
      ERROR_CHECK(zydec_WriteHex(pBufferPos, pRemainingSize, virtualAddress + pOperand->imm.value.u));
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

bool zydec_WriteRegister(char **pBufferPos, size_t *pRemainingSize, const ZydisRegister reg)
{
  if (reg >= sizeof(RegisterNameLut) / sizeof(RegisterNameLut[0]))
    return false;

  ERROR_CHECK(zydec_WriteRaw(pBufferPos, pRemainingSize, RegisterNameLut[reg]));

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
