#pragma once
#include <array>

std::array x86RegistersMapping
{
	"None",         // 0   CV_REG_NONE
	"al",           // 1   CV_REG_AL
	"cl",           // 2   CV_REG_CL
	"dl",           // 3   CV_REG_DL
	"bl",           // 4   CV_REG_BL
	"ah",           // 5   CV_REG_AH
	"ch",           // 6   CV_REG_CH
	"dh",           // 7   CV_REG_DH
	"bh",           // 8   CV_REG_BH
	"ax",           // 9   CV_REG_AX
	"cx",           // 10  CV_REG_CX
	"dx",           // 11  CV_REG_DX
	"bx",           // 12  CV_REG_BX
	"sp",           // 13  CV_REG_SP
	"bp",           // 14  CV_REG_BP
	"si",           // 15  CV_REG_SI
	"di",           // 16  CV_REG_DI
	"eax",          // 17  CV_REG_EAX
	"ecx",          // 18  CV_REG_ECX
	"edx",          // 19  CV_REG_EDX
	"ebx",          // 20  CV_REG_EBX
	"esp",          // 21  CV_REG_ESP
	"ebp",          // 22  CV_REG_EBP
	"esi",          // 23  CV_REG_ESI
	"edi",          // 24  CV_REG_EDI
	"es",           // 25  CV_REG_ES
	"cs",           // 26  CV_REG_CS
	"ss",           // 27  CV_REG_SS
	"ds",           // 28  CV_REG_DS
	"fs",           // 29  CV_REG_FS
	"gs",           // 30  CV_REG_GS
	"IP",           // 31  CV_REG_IP
	"FLAGS",        // 32  CV_REG_FLAGS
	"EIP",          // 33  CV_REG_EIP
	"EFLAGS",       // 34  CV_REG_EFLAG
	"???",          // 35
	"???",          // 36
	"???",          // 37
	"???",          // 38
	"???",          // 39
	"TEMP",         // 40  CV_REG_TEMP
	"TEMPH"         // 41  CV_REG_TEMPH
	"QUOTE",        // 42  CV_REG_QUOTE
	"PCDR3",        // 43  CV_REG_PCDR3
	"PCDR4",        // 44  CV_REG_PCDR4
	"PCDR5",        // 45  CV_REG_PCDR5
	"PCDR6",        // 46  CV_REG_PCDR6
	"PCDR7",        // 47  CV_REG_PCDR7
	"???",          // 48
	"???",          // 49
	"???",          // 50
	"???",          // 51
	"???",          // 52
	"???",          // 53
	"???",          // 54
	"???",          // 55
	"???",          // 56
	"???",          // 57
	"???",          // 58
	"???",          // 59
	"???",          // 60
	"???",          // 61
	"???",          // 62
	"???",          // 63
	"???",          // 64
	"???",          // 65
	"???",          // 66
	"???",          // 67
	"???",          // 68
	"???",          // 69
	"???",          // 70
	"???",          // 71
	"???",          // 72
	"???",          // 73
	"???",          // 74
	"???",          // 75
	"???",          // 76
	"???",          // 77
	"???",          // 78
	"???",          // 79
	"cr0",          // 80  CV_REG_CR0
	"cr1",          // 81  CV_REG_CR1
	"cr2",          // 82  CV_REG_CR2
	"cr3",          // 83  CV_REG_CR3
	"cr4",          // 84  CV_REG_CR4
	"???",          // 85
	"???",          // 86
	"???",          // 87
	"???",          // 88
	"???",          // 89
	"dr0",          // 90  CV_REG_DR0
	"dr1",          // 91  CV_REG_DR1
	"dr2",          // 92  CV_REG_DR2
	"dr3",          // 93  CV_REG_DR3
	"dr4",          // 94  CV_REG_DR4
	"dr5",          // 95  CV_REG_DR5
	"dr6",          // 96  CV_REG_DR6
	"dr7",          // 97  CV_REG_DR7
	"???",          // 98
	"???",          // 99
	"???",          // 10
	"???",          // 101
	"???",          // 102
	"???",          // 103
	"???",          // 104
	"???",          // 105
	"???",          // 106
	"???",          // 107
	"???",          // 108
	"???",          // 109
	"GDTR",         // 110 CV_REG_GDTR
	"GDTL",         // 111 CV_REG_GDTL
	"IDTR",         // 112 CV_REG_IDTR
	"IDTL",         // 113 CV_REG_IDTL
	"LDTR",         // 114 CV_REG_LDTR
	"TR",           // 115 CV_REG_TR
	"???",          // 116
	"???",          // 117
	"???",          // 118
	"???",          // 119
	"???",          // 120
	"???",          // 121
	"???",          // 122
	"???",          // 123
	"???",          // 124
	"???",          // 125
	"???",          // 126
	"???",          // 127
	"st(0)",        // 128 CV_REG_ST0
	"st(1)",        // 129 CV_REG_ST1
	"st(2)",        // 130 CV_REG_ST2
	"st(3)",        // 131 CV_REG_ST3
	"st(4)",        // 132 CV_REG_ST4
	"st(5)",        // 133 CV_REG_ST5
	"st(6)",        // 134 CV_REG_ST6
	"st(7)",        // 135 CV_REG_ST7
	"CTRL",         // 136 CV_REG_CTRL
	"STAT",         // 137 CV_REG_STAT
	"TAG",          // 138 CV_REG_TAG
	"FPIP",         // 139 CV_REG_FPIP
	"FPCS",         // 140 CV_REG_FPCS
	"FPDO",         // 141 CV_REG_FPDO
	"FPDS",         // 142 CV_REG_FPDS
	"ISEM",         // 143 CV_REG_ISEM
	"FPEIP",        // 144 CV_REG_FPEIP
	"FPED0"         // 145 CV_REG_FPEDO
};

std::array x8664RegistersMapping
{
	"None",         // 0   CV_REG_NONE
	"al",           // 1   CV_AMD64_AL
	"cl",           // 2   CV_AMD64_CL
	"dl",           // 3   CV_AMD64_DL
	"bl",           // 4   CV_AMD64_BL
	"ah",           // 5   CV_AMD64_AH
	"ch",           // 6   CV_AMD64_CH
	"dh",           // 7   CV_AMD64_DH
	"bh",           // 8   CV_AMD64_BH
	"ax",           // 9   CV_AMD64_AX
	"cx",           // 10  CV_AMD64_CX
	"dx",           // 11  CV_AMD64_DX
	"bx",           // 12  CV_AMD64_BX
	"sp",           // 13  CV_AMD64_SP
	"bp",           // 14  CV_AMD64_BP
	"si",           // 15  CV_AMD64_SI
	"di",           // 16  CV_AMD64_DI
	"eax",          // 17  CV_AMD64_EAX
	"ecx",          // 18  CV_AMD64_ECX
	"edx",          // 19  CV_AMD64_EDX
	"ebx",          // 20  CV_AMD64_EBX
	"esp",          // 21  CV_AMD64_ESP
	"ebp",          // 22  CV_AMD64_EBP
	"esi",          // 23  CV_AMD64_ESI
	"edi",          // 24  CV_AMD64_EDI
	"es",           // 25  CV_AMD64_ES
	"cs",           // 26  CV_AMD64_CS
	"ss",           // 27  CV_AMD64_SS
	"ds",           // 28  CV_AMD64_DS
	"fs",           // 29  CV_AMD64_FS
	"gs",           // 30  CV_AMD64_GS
	"???",          // 31  Not filled up
	"flags",        // 32  CV_AMD64_FLAGS
	"rip",          // 33  CV_AMD64_RIP
	"eflags",       // 34  CV_AMD64_EFLAGS
	"???",          // 35
	"???",          // 36
	"???",          // 37
	"???",          // 38
	"???",          // 39
	"???",          // 40
	"???",          // 41
	"???",          // 42
	"???",          // 43
	"???",          // 44
	"???",          // 45
	"???",          // 46
	"???",          // 47
	"???",          // 48
	"???",          // 49
	"???",          // 50
	"???",          // 51
	"???",          // 52
	"???",          // 53
	"???",          // 54
	"???",          // 55
	"???",          // 56
	"???",          // 57
	"???",          // 58
	"???",          // 59
	"???",          // 60
	"???",          // 61
	"???",          // 62
	"???",          // 63
	"???",          // 64
	"???",          // 65
	"???",          // 66
	"???",          // 67
	"???",          // 68
	"???",          // 69
	"???",          // 70
	"???",          // 71
	"???",          // 72
	"???",          // 73
	"???",          // 74
	"???",          // 75
	"???",          // 76
	"???",          // 77
	"???",          // 78
	"???",          // 79
	"cr0",          // 80  CV_AMD64_CR0
	"cr1",          // 81  CV_AMD64_CR1
	"cr2",          // 82  CV_AMD64_CR2
	"cr3",          // 83  CV_AMD64_CR3
	"cr4",          // 84  CV_AMD64_CR4
	"???",          // 85
	"???",          // 86
	"???",          // 87
	"cr8",          // 88  CV_AMD64_CR8
	"???",          // 89
	"dr0",          // 90  CV_AMD64_DR0
	"dr1",          // 91  CV_AMD64_DR1
	"dr2",          // 92  CV_AMD64_DR2
	"dr3",          // 93  CV_AMD64_DR3
	"dr4",          // 94  CV_AMD64_DR4
	"dr5",          // 95  CV_AMD64_DR5
	"dr6",          // 96  CV_AMD64_DR6
	"dr7",          // 97  CV_AMD64_DR7
	"dr8",          // 98  CV_AMD64_DR8
	"dr9",          // 99  CV_AMD64_DR9
	"dr10",         // 100 CV_AMD64_DR10
	"dr11",         // 101 CV_AMD64_DR11
	"dr12",         // 102 CV_AMD64_DR12
	"dr13",         // 103 CV_AMD64_DR13
	"dr14",         // 104 CV_AMD64_DR14
	"dr15",         // 105 CV_AMD64_DR15
	"???",          // 106
	"???",          // 107
	"???",          // 108
	"???",          // 109
	"gdtr",         // 110 CV_AMD64_GDTR
	"gdt",         // 111 CV_AMD64_GDTL
	"idtr",         // 112 CV_AMD64_IDTR
	"idt",         // 113 CV_AMD64_IDTL
	"ldtr",         // 114 CV_AMD64_LDTR
	"tr",           // 115 CV_AMD64_TR
	"???",          // 116
	"???",          // 117
	"???",          // 118
	"???",          // 119
	"???",          // 120
	"???",          // 121
	"???",          // 122
	"???",          // 123
	"???",          // 124
	"???",          // 125
	"???",          // 126
	"???",          // 127
	"st(0)",        // 128 CV_AMD64_ST0
	"st(1)",        // 129 CV_AMD64_ST1
	"st(2)",        // 130 CV_AMD64_ST2
	"st(3)",        // 131 CV_AMD64_ST3
	"st(4)",        // 132 CV_AMD64_ST4
	"st(5)",        // 133 CV_AMD64_ST5
	"st(6)",        // 134 CV_AMD64_ST6
	"st(7)",        // 135 CV_AMD64_ST7
	"ctr",         // 136 CV_AMD64_CTRL
	"stat",         // 137 CV_AMD64_STAT
	"tag",          // 138 CV_AMD64_TAG
	"fpip",         // 139 CV_AMD64_FPIP
	"fpcs",         // 140 CV_AMD64_FPCS
	"fpdo",         // 141 CV_AMD64_FPDO
	"fpds",         // 142 CV_AMD64_FPDS
	"isem",         // 143 CV_AMD64_ISEM
	"fpeip",        // 144 CV_AMD64_FPEIP
	"fped0",        // 145 CV_AMD64_FPEDO
	"mm0",          // 146 CV_AMD64_MM0
	"mm1",          // 147 CV_AMD64_MM1
	"mm2",          // 148 CV_AMD64_MM2
	"mm3",          // 149 CV_AMD64_MM3
	"mm4",          // 150 CV_AMD64_MM4
	"mm5",          // 151 CV_AMD64_MM5
	"mm6",          // 152 CV_AMD64_MM6
	"mm7",          // 153 CV_AMD64_MM7
	"xmm0",         // 154 CV_AMD64_XMM0
	"xmm1",         // 155 CV_AMD64_XMM1
	"xmm2",         // 156 CV_AMD64_XMM2
	"xmm3",         // 157 CV_AMD64_XMM3
	"xmm4",         // 158 CV_AMD64_XMM4
	"xmm5",         // 159 CV_AMD64_XMM5
	"xmm6",         // 160 CV_AMD64_XMM6
	"xmm7",         // 161 CV_AMD64_XMM7
	"xmm0_0",       // 162 CV_AMD64_XMM0_0
	"xmm0_1",       // 163 CV_AMD64_XMM0_1
	"xmm0_2",       // 164 CV_AMD64_XMM0_2
	"xmm0_3",       // 165 CV_AMD64_XMM0_3
	"xmm1_0",       // 166 CV_AMD64_XMM1_0
	"xmm1_1",       // 167 CV_AMD64_XMM1_1
	"xmm1_2",       // 168 CV_AMD64_XMM1_2
	"xmm1_3",       // 169 CV_AMD64_XMM1_3
	"xmm2_0",       // 170 CV_AMD64_XMM2_0
	"xmm2_1",       // 171 CV_AMD64_XMM2_1
	"xmm2_2",       // 172 CV_AMD64_XMM2_2
	"xmm2_3",       // 173 CV_AMD64_XMM2_3
	"xmm3_0",       // 174 CV_AMD64_XMM3_0
	"xmm3_1",       // 175 CV_AMD64_XMM3_1
	"xmm3_2",       // 176 CV_AMD64_XMM3_2
	"xmm3_3",       // 177 CV_AMD64_XMM3_3
	"xmm4_0",       // 178 CV_AMD64_XMM4_0
	"xmm4_1",       // 179 CV_AMD64_XMM4_1
	"xmm4_2",       // 180 CV_AMD64_XMM4_2
	"xmm4_3",       // 181 CV_AMD64_XMM4_3
	"xmm5_0",       // 182 CV_AMD64_XMM5_0
	"xmm5_1",       // 183 CV_AMD64_XMM5_1
	"xmm5_2",       // 184 CV_AMD64_XMM5_2
	"xmm5_3",       // 185 CV_AMD64_XMM5_3
	"xmm6_0",       // 186 CV_AMD64_XMM6_0
	"xmm6_1",       // 187 CV_AMD64_XMM6_1
	"xmm6_2",       // 188 CV_AMD64_XMM6_2
	"xmm6_3",       // 189 CV_AMD64_XMM6_3
	"xmm7_0",       // 190 CV_AMD64_XMM7_0
	"xmm7_1",       // 191 CV_AMD64_XMM7_1
	"xmm7_2",       // 192 CV_AMD64_XMM7_2
	"xmm7_3",       // 193 CV_AMD64_XMM7_3
	"xmm0",        // 194 CV_AMD64_XMM0L
	"xmm1",        // 195 CV_AMD64_XMM1L
	"xmm2",        // 196 CV_AMD64_XMM2L
	"xmm3",        // 197 CV_AMD64_XMM3L
	"xmm4",        // 198 CV_AMD64_XMM4L
	"xmm5",        // 199 CV_AMD64_XMM5L
	"xmm6",        // 200 CV_AMD64_XMM6L
	"xmm7",        // 201 CV_AMD64_XMM7L
	"xmm0h",        // 202 CV_AMD64_XMM0H
	"xmm1h",        // 203 CV_AMD64_XMM1H
	"xmm2h",        // 204 CV_AMD64_XMM2H
	"xmm3h",        // 205 CV_AMD64_XMM3H
	"xmm4h",        // 206 CV_AMD64_XMM4H
	"xmm5h",        // 207 CV_AMD64_XMM5H
	"xmm6h",        // 208 CV_AMD64_XMM6H
	"xmm7h",        // 209 CV_AMD64_XMM7H
	"???",          // 210
	"mxcsr",        // 211 CV_AMD64_MXCSR
	"???",          // 212
	"???",          // 213
	"???",          // 214
	"???",          // 215
	"???",          // 216
	"???",          // 217
	"???",          // 218
	"???",          // 219
	"emm0",        // 220 CV_AMD64_EMM0L
	"emm1",        // 221 CV_AMD64_EMM1L
	"emm2",        // 222 CV_AMD64_EMM2L
	"emm3",        // 223 CV_AMD64_EMM3L
	"emm4",        // 224 CV_AMD64_EMM4L
	"emm5",        // 225 CV_AMD64_EMM5L
	"emm6",        // 226 CV_AMD64_EMM6L
	"emm7",        // 227 CV_AMD64_EMM7L
	"emm0h",        // 228 CV_AMD64_EMM0H
	"emm1h",        // 229 CV_AMD64_EMM1H
	"emm2h",        // 230 CV_AMD64_EMM2H
	"emm3h",        // 231 CV_AMD64_EMM3H
	"emm4h",        // 232 CV_AMD64_EMM4H
	"emm5h",        // 233 CV_AMD64_EMM5H
	"emm6h",        // 234 CV_AMD64_EMM6H
	"emm7h",        // 235 CV_AMD64_EMM7H
	"mm00",         // 236 CV_AMD64_MM00
	"mm01",         // 237 CV_AMD64_MM01
	"mm10",         // 238 CV_AMD64_MM10
	"mm11",         // 239 CV_AMD64_MM11
	"mm20",         // 240 CV_AMD64_MM20
	"mm21",         // 241 CV_AMD64_MM21
	"mm30",         // 242 CV_AMD64_MM30
	"mm31",         // 243 CV_AMD64_MM31
	"mm40",         // 244 CV_AMD64_MM40
	"mm41",         // 245 CV_AMD64_MM41
	"mm50",         // 246 CV_AMD64_MM50
	"mm51",         // 247 CV_AMD64_MM51
	"mm60",         // 248 CV_AMD64_MM60
	"mm61",         // 249 CV_AMD64_MM61
	"mm70",         // 250 CV_AMD64_MM70
	"mm71",         // 251 CV_AMD64_MM71
	"xmm8",         // 252 CV_AMD64_XMM8
	"xmm9",         // 253 CV_AMD64_XMM9
	"xmm10",        // 254 CV_AMD64_XMM10
	"xmm11",        // 255 CV_AMD64_XMM11
	"xmm12",        // 256 CV_AMD64_XMM12
	"xmm13",        // 257 CV_AMD64_XMM13
	"xmm14",        // 258 CV_AMD64_XMM14
	"xmm15",        // 259 CV_AMD64_XMM15
	"xmm8_0",       // 260 CV_AMD64_XMM8_0
	"xmm8_1",       // 261 CV_AMD64_XMM8_1
	"xmm8_2",       // 262 CV_AMD64_XMM8_2
	"xmm8_3",       // 263 CV_AMD64_XMM8_3
	"xmm9_0",       // 264 CV_AMD64_XMM9_0
	"xmm9_1",       // 265 CV_AMD64_XMM9_1
	"xmm9_2",       // 266 CV_AMD64_XMM9_2
	"xmm9_3",       // 267 CV_AMD64_XMM9_3
	"xmm10_0",      // 268 CV_AMD64_XMM10_0
	"xmm10_1",      // 269 CV_AMD64_XMM10_1
	"xmm10_2",      // 270 CV_AMD64_XMM10_2
	"xmm10_3",      // 271 CV_AMD64_XMM10_3
	"xmm11_0",      // 272 CV_AMD64_XMM11_0
	"xmm11_1",      // 273 CV_AMD64_XMM11_1
	"xmm11_2",      // 274 CV_AMD64_XMM11_2
	"xmm11_3",      // 275 CV_AMD64_XMM11_3
	"xmm12_0",      // 276 CV_AMD64_XMM12_0
	"xmm12_1",      // 277 CV_AMD64_XMM12_1
	"xmm12_2",      // 278 CV_AMD64_XMM12_2
	"xmm12_3",      // 279 CV_AMD64_XMM12_3
	"xmm13_0",      // 280 CV_AMD64_XMM13_0
	"xmm13_1",      // 281 CV_AMD64_XMM13_1
	"xmm13_2",      // 282 CV_AMD64_XMM13_2
	"xmm13_3",      // 283 CV_AMD64_XMM13_3
	"xmm14_0",      // 284 CV_AMD64_XMM14_0
	"xmm14_1",      // 285 CV_AMD64_XMM14_1
	"xmm14_2",      // 286 CV_AMD64_XMM14_2
	"xmm14_3",      // 287 CV_AMD64_XMM14_3
	"xmm15_0",      // 288 CV_AMD64_XMM15_0
	"xmm15_1",      // 289 CV_AMD64_XMM15_1
	"xmm15_2",      // 290 CV_AMD64_XMM15_2
	"xmm15_3",      // 291 CV_AMD64_XMM15_3
	"xmm8",        // 292 CV_AMD64_XMM8L
	"xmm9",        // 293 CV_AMD64_XMM9L
	"xmm10",       // 294 CV_AMD64_XMM10L
	"xmm11",       // 295 CV_AMD64_XMM11L
	"xmm12",       // 296 CV_AMD64_XMM12L
	"xmm13",       // 297 CV_AMD64_XMM13L
	"xmm14",       // 298 CV_AMD64_XMM14L
	"xmm15",       // 299 CV_AMD64_XMM15L
	"xmm8h",        // 300 CV_AMD64_XMM8H
	"xmm9h",        // 301 CV_AMD64_XMM9H
	"xmm10h",       // 302 CV_AMD64_XMM10H
	"xmm11h",       // 303 CV_AMD64_XMM11H
	"xmm12h",       // 304 CV_AMD64_XMM12H
	"xmm13h",       // 305 CV_AMD64_XMM13H
	"xmm14h",       // 306 CV_AMD64_XMM14H
	"xmm15h",       // 307 CV_AMD64_XMM15H
	"emm8",        // 308 CV_AMD64_EMM8L
	"emm9",        // 309 CV_AMD64_EMM9L
	"emm10",       // 310 CV_AMD64_EMM10L
	"emm11",       // 311 CV_AMD64_EMM11L
	"emm12",       // 312 CV_AMD64_EMM12L
	"emm13",       // 313 CV_AMD64_EMM13L
	"emm14",       // 314 CV_AMD64_EMM14L
	"emm15",       // 315 CV_AMD64_EMM15L
	"emm8h",        // 316 CV_AMD64_EMM8H
	"emm9h",        // 317 CV_AMD64_EMM9H
	"emm10h",       // 318 CV_AMD64_EMM10H
	"emm11h",       // 319 CV_AMD64_EMM11H
	"emm12h",       // 320 CV_AMD64_EMM12H
	"emm13h",       // 321 CV_AMD64_EMM13H
	"emm14h",       // 322 CV_AMD64_EMM14H
	"emm15h",       // 323 CV_AMD64_EMM15H
	"si",          // 324 CV_AMD64_SIL
	"di",          // 325 CV_AMD64_DIL
	"bp",          // 326 CV_AMD64_BPL
	"sp",          // 327 CV_AMD64_SPL
	"rax",          // 328 CV_AMD64_RAX
	"rbx",          // 329 CV_AMD64_RBX
	"rcx",          // 330 CV_AMD64_RCX
	"rdx",          // 331 CV_AMD64_RDX
	"rsi",          // 332 CV_AMD64_RSI
	"rdi",          // 333 CV_AMD64_RDI
	"rbp",          // 334 CV_AMD64_RBP
	"rsp",          // 335 CV_AMD64_RSP
	"r8",           // 336 CV_AMD64_R8
	"r9",           // 337 CV_AMD64_R9
	"r10",          // 338 CV_AMD64_R10
	"r11",          // 339 CV_AMD64_R11
	"r12",          // 340 CV_AMD64_R12
	"r13",          // 341 CV_AMD64_R13
	"r14",          // 342 CV_AMD64_R14
	"r15",          // 343 CV_AMD64_R15
	"r8b",          // 344 CV_AMD64_R8B
	"r9b",          // 345 CV_AMD64_R9B
	"r10b",         // 346 CV_AMD64_R10B
	"r11b",         // 347 CV_AMD64_R11B
	"r12b",         // 348 CV_AMD64_R12B
	"r13b",         // 349 CV_AMD64_R13B
	"r14b",         // 350 CV_AMD64_R14B
	"r15b",         // 351 CV_AMD64_R15B
	"r8w",          // 352 CV_AMD64_R8W
	"r9w",          // 353 CV_AMD64_R9W
	"r10w",         // 354 CV_AMD64_R10W
	"r11w",         // 355 CV_AMD64_R11W
	"r12w",         // 356 CV_AMD64_R12W
	"r13w",         // 357 CV_AMD64_R13W
	"r14w",         // 358 CV_AMD64_R14W
	"r15w",         // 359 CV_AMD64_R15W
	"r8d",          // 360 CV_AMD64_R8D
	"r9d",          // 361 CV_AMD64_R9D
	"r10d",         // 362 CV_AMD64_R10D
	"r11d",         // 363 CV_AMD64_R11D
	"r12d",         // 364 CV_AMD64_R12D
	"r13d",         // 365 CV_AMD64_R13D
	"r14d",         // 366 CV_AMD64_R14D
	"r15d"          // 367 CV_AMD64_R15D
};