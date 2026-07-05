# gpufreq Findings

## Confirmed

- `__gpufreq_get_signed_opp_num_gpu` (`.text+0x1c78`) — no BL/BLR instruction targets this function in any RELA section. Zero callers.
- The probe function has a CSEL at `.text+0x7c74`: `csel w4, w11, w10, ne` where w10=0x2c (44) and w11=0x25 (37). Result: w4 = 37 or 44. At `.text+0x7c90`: `add w2, w4, #1` → w2 = 38 or 45.
- Static OPP table at file offset `0xbd10`, 45 entries × 24 bytes.

## Inferred (not confirmed)

- working_opp_count determines how many entries the working table copies from the signed table.
- Start index = signed_opp_num - working_opp_count. This formula was seen in a Ghidra trace but not independently verified.
- The /proc handler reads past working_opp_count — garbage entries 38-44 could be explained by this but root cause unknown.
- The flags that select 37 vs 44 at the CSEL involve BSS+0x120 and BSS+0x594. Their exact meaning is unknown.
