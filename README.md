# Zydec
## An instruction-level decompiler for x64

### What is Zydec?
Zydec is a tiny library that facilitates Instructions & Operands disassembled from Zydis to produce C-esque, more human-readable pseudo-code intended for quickly skimming sections of disassembly.
Zydec is especially targeted towards heavily vectorized code and attempts to resolve the generated assembly back into the original intrinsics.
It's mainly intended for usage with my profiler tool [silverpp](https://github.com/rainerzufalldererste/silverpp), where it helps when glancing over hot instruction disassembly.

### Example Output vs Disassembly
```
140000299 | vpor ymm13, ymm1, ymm2                                | (m256)y13 = _mm_or_si((m256)y1, (m256)y2);
14000029D | mov qword ptr ds:[rcx+0x8480], r9                     | *(data_segment: (i64)c + 33920) = (i64)r9;
1400002A4 | vmovdqu xmm4, xmmword ptr ds:[r9]                     | _mm_unaligned_load_si((m128)x4, *(data_segment: (i64)r9));
1400002A9 | popcnt edx, r11d                                      | __popcnt((i32)d);
1400002AE | mov edx, edx                                          | (i32)d = (i32)d;
1400002B0 | lea r8, ds:[r9+rdx*2]                                 | (i64)r8 = &(data_segment: (i64)r9);
1400002B4 | vpshufb xmm3, xmm3, xmm6                              | (m128)x3 = _mm_shuffle_epi8((m128)x3, (m128)x6);
1400002B9 | mov qword ptr ds:[rcx+0x8480], r8                     | *(data_segment: (i64)c + 33920) = (i64)r8;
1400002C0 | popcnt edx, r10d                                      | __popcnt((i32)d);
1400002C5 | mov edx, edx                                          | (i32)d = (i32)d;
1400002C7 | vmovdqu xmm5, xmmword ptr ds:[r8]                     | _mm_unaligned_load_si((m128)x5, *(data_segment: (i64)r8));
1400002CC | vpmovzxwd ymm2, xmm3                                  | (m256)y2 = _mm_cvtepu16_epi32((m128)x3);
1400002D1 | vmovdqu ymm3, ymmword ptr ds:[0x000000014028D230]     | _mm_unaligned_load_si((m256)y3, *(data_segment: (i64)instruction_pointer + 2674519));
1400002D9 | lea rax, ds:[r8+rdx*2]                                | (i64)a = &(data_segment: (i64)r8);
1400002DD | mov qword ptr ds:[rcx+0x8480], rax                    | *(data_segment: (i64)c + 33920) = (i64)a;
1400002E4 | vpand ymm0, ymm10, ymm3                               | (m256)y0 = _mm_and_si((m256)y10, (m256)y3);
1400002E8 | vpsllvd ymm1, ymm14, ymm0                             | (m256)y1 = _mm_sllv_epi32((m256)y14, (m256)y0);
1400002ED | vpor ymm14, ymm1, ymm2                                | (m256)y14 = _mm_or_si((m256)y1, (m256)y2);
1400002F1 | vpand ymm0, ymm11, ymm3                               | (m256)y0 = _mm_and_si((m256)y11, (m256)y3);
1400002F5 | vpsllvd ymm1, ymm15, ymm0                             | (m256)y1 = _mm_sllv_epi32((m256)y15, (m256)y0);
1400002FA | vmovdqu ymm15, ymmword ptr ds:[0x000000014028D350]    | _mm_unaligned_load_si((m256)y15, *(data_segment: (i64)instruction_pointer + 2674766));
140000302 | vpand ymm0, ymm12, ymm3                               | (m256)y0 = _mm_and_si((m256)y12, (m256)y3);
140000306 | vpshufb xmm4, xmm4, xmm7                              | (m128)x4 = _mm_shuffle_epi8((m128)x4, (m128)x7);
14000030B | vpshufb xmm5, xmm5, xmm8                              | (m128)x5 = _mm_shuffle_epi8((m128)x5, (m128)x8);
140000310 | vpmovzxwd ymm2, xmm4                                  | (m256)y2 = _mm_cvtepu16_epi32((m128)x4);
140000315 | vpor ymm11, ymm1, ymm2                                | (m256)y11 = _mm_or_si((m256)y1, (m256)y2);
140000319 | vmovdqu ymm1, ymmword ptr ss:[rbp+0x80]               | _mm_unaligned_load_si((m256)y1, *(stack_segment: (i64)bp + 128));
140000321 | vpmovzxwd ymm2, xmm5                                  | (m256)y2 = _mm_cvtepu16_epi32((m128)x5);
140000326 | vpsllvd ymm1, ymm1, ymm0                              | (m256)y1 = _mm_sllv_epi32((m256)y1, (m256)y0);
14000032B | vmovdqu ymm0, ymmword ptr ds:[0x000000014028D310]     | _mm_unaligned_load_si((m256)y0, *(data_segment: (i64)instruction_pointer + 2674653));
140000333 | vpor ymm12, ymm1, ymm2                                | (m256)y12 = _mm_or_si((m256)y1, (m256)y2);
140000337 | vmovdqu ymm2, ymmword ptr ds:[0x000000014028D250]     | _mm_unaligned_load_si((m256)y2, *(data_segment: (i64)instruction_pointer + 2674449));
14000033F | cmp rdi, r14                                          | compare((i64)di, (i64)r14) // set carry_flag, overflow_flag, signed_flag, zero_flag, aux_carry_flag and parity_flag
140000342 | jb 0x00000001400000D0                                 | if (carry_flag) goto 0x1400000CA; // if below
140000348 | vmovdqu ymmword ptr ss:[rbp], ymm13                   | _mm_unaligned_store_si(*(stack_segment: (i64)bp), (m256)y13);
14000034D | vmovdqu ymmword ptr ss:[rbp+0x20], ymm14              | _mm_unaligned_store_si(*(stack_segment: (i64)bp + 32), (m256)y14);
140000352 | vmovdqu ymmword ptr ss:[rbp+0x40], ymm11              | _mm_unaligned_store_si(*(stack_segment: (i64)bp + 64), (m256)y11);
140000357 | vmovdqu ymmword ptr ss:[rbp+0x60], ymm12              | _mm_unaligned_store_si(*(stack_segment: (i64)bp + 96), (m256)y12);
14000035C | lea r8, ss:[rbp]                                      | (i64)r8 = &(stack_segment: (i64)bp + 0);
140000360 | mov edx, 0x04                                         | (i32)d = 4;
140000365 | sub r8, rcx                                           | (i64)r8 -= (i64)c;
140000368 | nop dword ptr ds:[rax+rax*1], eax                     |
140000370 | vmovdqu ymm0, ymmword ptr ds:[r8+rcx*1]               | _mm_unaligned_load_si((m256)y0, *(data_segment: (i64)r8 + (i64)c));
140000376 | vmovdqu ymmword ptr ds:[rcx], ymm0                    | _mm_unaligned_store_si(*(data_segment: (i64)c), (m256)y0);
14000037A | lea rcx, ds:[rcx+0x20]                                | (i64)c = &(data_segment: (i64)c + 32);
14000037E | sub rdx, 0x01                                         | (i64)d -= 1;
140000382 | jnz 0x0000000140000370                                | if (!zero_flag) goto 0x14000036E; // if not zero / not equal
140000384 | mov rax, rdi                                          | (i64)a = (i64)di;
140000387 | vzeroupper                                            | _mm_zeroupper();
14000038A | lea r11, ss:[rsp+0x180]                               | (i64)r11 = &(stack_segment: (i64)stack_pointer + 384);
140000392 | mov rbx, qword ptr ds:[r11+0x20]                      | (i64)b = *(data_segment: (i64)r11 + 32);
140000396 | mov rsi, qword ptr ds:[r11+0x28]                      | (i64)si = *(data_segment: (i64)r11 + 40);
14000039A | mov rdi, qword ptr ds:[r11+0x30]                      | (i64)di = *(data_segment: (i64)r11 + 48);
14000039E | movaps xmm6, xmmword ptr ds:[r11-0x10]                | _mm_aligned_load_ps((m128)x6, *(data_segment: (i64)r11 + -16));
```