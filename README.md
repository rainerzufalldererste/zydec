# Zydec
## An instruction-level decompiler for x64

### What is Zydec?
Zydec is a tiny library that facilitates Instructions & Operands disassembled from Zydis to produce C-esque, more human-readable pseudo-code intended for quickly skimming sections of disassembly.
Zydec is especially targeted towards heavily vectorized code and attempts to resolve the generated assembly back into the original intrinsics.
It's mainly intended for usage with my profiler tool [silverpp](https://github.com/rainerzufalldererste/silverpp), where it helps when glancing over hot instruction disassembly and included in my Online-Performance-Analysis Tool [optim8.org](https://optim8.org/).

### Example Output vs Disassembly
```cpp
// 140000287: add rdi, 0x20                                       
(i64)di_Add_Womi = (i64)di_Jef_huza + 32;

// 14000028B: lea r9, ds:[r8+rdx*2]                               
(i64)r9_Loc_XaKe = &(data_segment: (i64)r8_Loc_Vadu + ((i64)d_4ug_Qiwo * 2));

// 14000028F: vpmovzxwd ymm2, xmm1                                
(m256)y2_Cov_soma = _mm_cvtepu16_epi32((m256)y2_Mov_Xuve, (m128)x1_Shf_baXe);

// 140000294: vpsllvd ymm1, ymm13, ymm0                           
(m256)y1_Shl_Feqi = _mm_sllv_epi32((m256)y13_Add_Nigu, (m256)y0_And_gin_);

// 140000299: vpor ymm13, ymm1, ymm2                              
(m256)y13_o_r_goFi = _mm_or_si((m256)y1_Shl_Feqi, (m256)y2_Cov_soma);

// 14000029D: mov qword ptr ds:[rcx+0x8480], r9                   
*(data_segment: (i64)c + 33920) = (i64)r9_Loc_XaKe;

// 1400002A4: vmovdqu xmm4, xmmword ptr ds:[r9]                   
(m128)x4_Mov_g_So = _mm_unaligned_load_si((data_segment: (i64)r9_Loc_XaKe));

// 1400002A9: popcnt edx, r11d                                    
(i32)d_Pop_Feze = __popcnt((i32)r11_Mas_h_y_);

// 1400002AE: mov edx, edx                                        
(i32)d_Zuyixut_ = (i32)d_Pop_Feze;

// 1400002B0: lea r8, ds:[r9+rdx*2]                               
(i64)r8_Loc_Jai_ = &(data_segment: (i64)r9_Loc_XaKe + ((i64)d_Zuyixut_ * 2));

// 1400002B4: vpshufb xmm3, xmm3, xmm6                            
(m128)x3_Shf_TiRo = _mm_shuffle_epi8((m128)x3_Mov_DePu, (m128)x6_Mov_papi);

// 1400002B9: mov qword ptr ds:[rcx+0x8480], r8                   
*(data_segment: (i64)c + 33920) = (i64)r8_Loc_Jai_;

// 1400002C0: popcnt edx, r10d                                    
(i32)d_Pop_yogo = __popcnt((i32)r10_Mas_peJa);

// 1400002C5: mov edx, edx                                        
(i32)d_QaLaHoTo = (i32)d_Pop_yogo;

// 1400002C7: vmovdqu xmm5, xmmword ptr ds:[r8]                   
(m128)x5_Mov_peju = _mm_unaligned_load_si((data_segment: (i64)r8_Loc_Jai_));

// 1400002CC: vpmovzxwd ymm2, xmm3                                
(m256)y2_Cov_qe7o = _mm_cvtepu16_epi32((m256)y2_Cov_soma, (m128)x3_Shf_TiRo);

// 1400002D1: vmovdqu ymm3, ymmword ptr ds:[0x000000014028D230]   
(m256)y3_Mov_Nire = _mm_unaligned_load_si((data_segment: 0x14028D228));

// 1400002D9: lea rax, ds:[r8+rdx*2]                              
(i64)a_Loc_Na4o = &(data_segment: (i64)r8_Loc_Jai_ + ((i64)d_QaLaHoTo * 2));

// 1400002DD: mov qword ptr ds:[rcx+0x8480], rax                  
*(data_segment: (i64)c + 33920) = (i64)a_Loc_Na4o;

// 1400002E4: vpand ymm0, ymm10, ymm3                             
(m256)y0_And_Hihu = _mm_and_si((m256)y10_Cmp_seVu, (m256)y3_Mov_Nire);

// 1400002E8: vpsllvd ymm1, ymm14, ymm0                           
(m256)y1_Shl_jaWu = _mm_sllv_epi32((m256)y14_Add_x_yu, (m256)y0_And_Hihu);

// 1400002ED: vpor ymm14, ymm1, ymm2                              
(m256)y14_o_r_v_qa = _mm_or_si((m256)y1_Shl_jaWu, (m256)y2_Cov_qe7o);

// 1400002F1: vpand ymm0, ymm11, ymm3                             
(m256)y0_And_Li6i = _mm_and_si((m256)y11_Cmp_Abje, (m256)y3_Mov_Nire);

// 1400002F5: vpsllvd ymm1, ymm15, ymm0                           
(m256)y1_Shl_Cupa = _mm_sllv_epi32((m256)y15_Add_BeKe, (m256)y0_And_Li6i);

// 1400002FA: vmovdqu ymm15, ymmword ptr ds:[0x000000014028D350]  
(m256)y15_Mov_i_Sa = _mm_unaligned_load_si((data_segment: 0x14028D348));

// 140000302: vpand ymm0, ymm12, ymm3                             
(m256)y0_And_Yigi = _mm_and_si((m256)y12_Cmp_XaBi, (m256)y3_Mov_Nire);

// 140000306: vpshufb xmm4, xmm4, xmm7                            
(m128)x4_Shf_vuHi = _mm_shuffle_epi8((m128)x4_Mov_g_So, (m128)x7_Mov_yuta);

// 14000030B: vpshufb xmm5, xmm5, xmm8                            
(m128)x5_Shf_GaRi = _mm_shuffle_epi8((m128)x5_Mov_peju, (m128)x8_Mov_Hav_);

// 140000310: vpmovzxwd ymm2, xmm4                                
(m256)y2_Cov_pex_ = _mm_cvtepu16_epi32((m256)y2_Cov_qe7o, (m128)x4_Shf_vuHi);

// 140000315: vpor ymm11, ymm1, ymm2                              
(m256)y11_o_r_bui_ = _mm_or_si((m256)y1_Shl_Cupa, (m256)y2_Cov_pex_);

// 140000319: vmovdqu ymm1, ymmword ptr ss:[rbp+0x80]             
(m256)y1_Mov_keJe = _mm_unaligned_load_si((stack_segment: (i64)bp_And_quHu + 128));

// 140000321: vpmovzxwd ymm2, xmm5                                
(m256)y2_Cov_tipa = _mm_cvtepu16_epi32((m256)y2_Cov_pex_, (m128)x5_Shf_GaRi);

// 140000326: vpsllvd ymm1, ymm1, ymm0                            
(m256)y1_Shl_loQa = _mm_sllv_epi32((m256)y1_Mov_keJe, (m256)y0_And_Yigi);

// 14000032B: vmovdqu ymm0, ymmword ptr ds:[0x000000014028D310]   
(m256)y0_Mov_teBi = _mm_unaligned_load_si((data_segment: 0x14028D308));

// 140000333: vpor ymm12, ymm1, ymm2                              
(m256)y12_o_r_7ito = _mm_or_si((m256)y1_Shl_loQa, (m256)y2_Cov_tipa);

// 140000337: vmovdqu ymm2, ymmword ptr ds:[0x000000014028D250]   
(m256)y2_Mov_veBo = _mm_unaligned_load_si((data_segment: 0x14028D248));

// 14000033F: cmp rdi, r14                                        
compare((i64)di_Add_Womi, (i64)r14_ya4oVati); // set flags: carry, overflow, signed, zero, aux_carry and parity

// 140000342: jb 0x00000001400000D0                               
if (carry_flag) goto 0x1400000CA; // if below

// 140000348: vmovdqu ymmword ptr ss:[rbp], ymm13                 
_mm_unaligned_store_si((stack_segment: (i64)bp_And_quHu), (m256)y13_o_r_goFi);

// 14000034D: vmovdqu ymmword ptr ss:[rbp+0x20], ymm14            
_mm_unaligned_store_si((stack_segment: (i64)bp_And_quHu + 32), (m256)y14_o_r_v_qa);

// 140000352: vmovdqu ymmword ptr ss:[rbp+0x40], ymm11            
_mm_unaligned_store_si((stack_segment: (i64)bp_And_quHu + 64), (m256)y11_o_r_bui_);

// 140000357: vmovdqu ymmword ptr ss:[rbp+0x60], ymm12            
_mm_unaligned_store_si((stack_segment: (i64)bp_And_quHu + 96), (m256)y12_o_r_7ito);

// 14000035C: lea r8, ss:[rbp]                                    
(i64)r8_Loc_ceWi = &(stack_segment: (i64)bp_And_quHu);

// 140000360: mov edx, 0x04                                       
(i32)d_Mov_biFo = 4;

// 140000365: sub r8, rcx                                         
(i64)r8_And_Dama = (i64)r8_Loc_ceWi - (i64)c;

// 140000368: nop dword ptr ds:[rax+rax*1], eax                   
// nop

// 140000370: vmovdqu ymm0, ymmword ptr ds:[r8+rcx*1]             
(m256)y0_Mov_WaLo = _mm_unaligned_load_si((data_segment: (i64)r8_And_Dama + (i64)c));

// 140000376: vmovdqu ymmword ptr ds:[rcx], ymm0                  
_mm_unaligned_store_si((data_segment: (i64)c), (m256)y0_Mov_WaLo);

// 14000037A: lea rcx, ds:[rcx+0x20]                              
(i64)c_Loc_Cmxu = &(data_segment: (i64)c + 32);
```
