# Zydec
## An instruction-level decompiler for x64

### What is Zydec?
Zydec is a tiny library that facilitates Instructions & Operands disassembled from Zydis to produce C-esque, more human-readable pseudo-code intended for quickly skimming sections of disassembly.
Zydec is especially targeted towards heavily vectorized code and attempts to resolve the generated assembly back into the original intrinsics.
It's mainly intended for usage with my profiler tool [silverpp](https://github.com/rainerzufalldererste/silverpp), where it helps when glancing over hot instruction disassembly.

### Example Output vs Disassembly
```
140000287 | (i64)di += 32;                                                                                 | add rdi, 0x20
14000028B | (i64)r9 = &(data_segment: (i64)r8);                                                            | lea r9, ds:[r8+rdx*2]
14000028F | (m256)y2 = _mm_cvtepu16_epi32((m256)y2, (m128)x1);                                             | vpmovzxwd ymm2, xmm1
140000294 | (m256)y1 = _mm_sllv_epi32((m256)y13, (m256)y0);                                                | vpsllvd ymm1, ymm13, ymm0
140000299 | (m256)y13 = _mm_or_si((m256)y1, (m256)y2);                                                     | vpor ymm13, ymm1, ymm2
14000029D | *(data_segment: (i64)c + 33920) = (i64)r9;                                                     | mov qword ptr ds:[rcx+0x8480], r9
1400002A4 | (m128)x4 = _mm_unaligned_load_si((data_segment: (i64)r9));                                     | vmovdqu xmm4, xmmword ptr ds:[r9]
1400002A9 | (i32)d = __popcnt((i32)r11);                                                                   | popcnt edx, r11d
1400002AE | (i32)d = (i32)d;                                                                               | mov edx, edx
1400002B0 | (i64)r8 = &(data_segment: (i64)r9);                                                            | lea r8, ds:[r9+rdx*2]
1400002B4 | (m128)x3 = _mm_shuffle_epi8((m128)x3, (m128)x6);                                               | vpshufb xmm3, xmm3, xmm6
1400002B9 | *(data_segment: (i64)c + 33920) = (i64)r8;                                                     | mov qword ptr ds:[rcx+0x8480], r8
1400002C0 | (i32)d = __popcnt((i32)r10);                                                                   | popcnt edx, r10d
1400002C5 | (i32)d = (i32)d;                                                                               | mov edx, edx
1400002C7 | (m128)x5 = _mm_unaligned_load_si((data_segment: (i64)r8));                                     | vmovdqu xmm5, xmmword ptr ds:[r8]
1400002CC | (m256)y2 = _mm_cvtepu16_epi32((m256)y2, (m128)x3);                                             | vpmovzxwd ymm2, xmm3
1400002D1 | (m256)y3 = _mm_unaligned_load_si((data_segment: 0x14028D228));                                 | vmovdqu ymm3, ymmword ptr ds:[0x000000014028D230]
1400002D9 | (i64)a = &(data_segment: (i64)r8);                                                             | lea rax, ds:[r8+rdx*2]
1400002DD | *(data_segment: (i64)c + 33920) = (i64)a;                                                      | mov qword ptr ds:[rcx+0x8480], rax
1400002E4 | (m256)y0 = _mm_and_si((m256)y10, (m256)y3);                                                    | vpand ymm0, ymm10, ymm3
1400002E8 | (m256)y1 = _mm_sllv_epi32((m256)y14, (m256)y0);                                                | vpsllvd ymm1, ymm14, ymm0
1400002ED | (m256)y14 = _mm_or_si((m256)y1, (m256)y2);                                                     | vpor ymm14, ymm1, ymm2
1400002F1 | (m256)y0 = _mm_and_si((m256)y11, (m256)y3);                                                    | vpand ymm0, ymm11, ymm3
1400002F5 | (m256)y1 = _mm_sllv_epi32((m256)y15, (m256)y0);                                                | vpsllvd ymm1, ymm15, ymm0
1400002FA | (m256)y15 = _mm_unaligned_load_si((data_segment: 0x14028D348));                                | vmovdqu ymm15, ymmword ptr ds:[0x000000014028D350]
140000302 | (m256)y0 = _mm_and_si((m256)y12, (m256)y3);                                                    | vpand ymm0, ymm12, ymm3
140000306 | (m128)x4 = _mm_shuffle_epi8((m128)x4, (m128)x7);                                               | vpshufb xmm4, xmm4, xmm7
14000030B | (m128)x5 = _mm_shuffle_epi8((m128)x5, (m128)x8);                                               | vpshufb xmm5, xmm5, xmm8
140000310 | (m256)y2 = _mm_cvtepu16_epi32((m256)y2, (m128)x4);                                             | vpmovzxwd ymm2, xmm4
140000315 | (m256)y11 = _mm_or_si((m256)y1, (m256)y2);                                                     | vpor ymm11, ymm1, ymm2
140000319 | (m256)y1 = _mm_unaligned_load_si((stack_segment: (i64)bp + 128));                              | vmovdqu ymm1, ymmword ptr ss:[rbp+0x80]
140000321 | (m256)y2 = _mm_cvtepu16_epi32((m256)y2, (m128)x5);                                             | vpmovzxwd ymm2, xmm5
140000326 | (m256)y1 = _mm_sllv_epi32((m256)y1, (m256)y0);                                                 | vpsllvd ymm1, ymm1, ymm0
14000032B | (m256)y0 = _mm_unaligned_load_si((data_segment: 0x14028D308));                                 | vmovdqu ymm0, ymmword ptr ds:[0x000000014028D310]
140000333 | (m256)y12 = _mm_or_si((m256)y1, (m256)y2);                                                     | vpor ymm12, ymm1, ymm2
140000337 | (m256)y2 = _mm_unaligned_load_si((data_segment: 0x14028D248));                                 | vmovdqu ymm2, ymmword ptr ds:[0x000000014028D250]
14000033F | compare((i64)di, (i64)r14) // set flags: carry, overflow, signed, zero, aux_carry and parity   | cmp rdi, r14
140000342 | if (carry_flag) goto 0x1400000CA; // if below                                                  | jb 0x00000001400000D0
140000348 | _mm_unaligned_store_si((stack_segment: (i64)bp), (m256)y13);                                   | vmovdqu ymmword ptr ss:[rbp], ymm13
14000034D | _mm_unaligned_store_si((stack_segment: (i64)bp + 32), (m256)y14);                              | vmovdqu ymmword ptr ss:[rbp+0x20], ymm14
140000352 | _mm_unaligned_store_si((stack_segment: (i64)bp + 64), (m256)y11);                              | vmovdqu ymmword ptr ss:[rbp+0x40], ymm11
140000357 | _mm_unaligned_store_si((stack_segment: (i64)bp + 96), (m256)y12);                              | vmovdqu ymmword ptr ss:[rbp+0x60], ymm12
14000035C | (i64)r8 = &(stack_segment: (i64)bp + 0);                                                       | lea r8, ss:[rbp]
140000360 | (i32)d = 4;                                                                                    | mov edx, 0x04
140000365 | (i64)r8 -= (i64)c;                                                                             | sub r8, rcx
140000368 |                                                                                                | nop dword ptr ds:[rax+rax*1], eax
140000370 | (m256)y0 = _mm_unaligned_load_si((data_segment: (i64)r8 + (i64)c));                            | vmovdqu ymm0, ymmword ptr ds:[r8+rcx*1]
140000376 | _mm_unaligned_store_si((data_segment: (i64)c), (m256)y0);                                      | vmovdqu ymmword ptr ds:[rcx], ymm0
14000037A | (i64)c = &(data_segment: (i64)c + 32);                                                         | lea rcx, ds:[rcx+0x20]
```
