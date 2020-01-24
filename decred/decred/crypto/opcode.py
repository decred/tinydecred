"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details
"""

# fmt: off
OP_0                   = 0x00 # 0
OP_FALSE               = 0x00 # 0 - AKA OP_0
OP_DATA_1              = 0x01 # 1
OP_DATA_2              = 0x02 # 2
OP_DATA_3              = 0x03 # 3
OP_DATA_4              = 0x04 # 4
OP_DATA_5              = 0x05 # 5
OP_DATA_6              = 0x06 # 6
OP_DATA_7              = 0x07 # 7
OP_DATA_8              = 0x08 # 8
OP_DATA_9              = 0x09 # 9
OP_DATA_10             = 0x0a # 10
OP_DATA_11             = 0x0b # 11
OP_DATA_12             = 0x0c # 12
OP_DATA_13             = 0x0d # 13
OP_DATA_14             = 0x0e # 14
OP_DATA_15             = 0x0f # 15
OP_DATA_16             = 0x10 # 16
OP_DATA_17             = 0x11 # 17
OP_DATA_18             = 0x12 # 18
OP_DATA_19             = 0x13 # 19
OP_DATA_20             = 0x14 # 20
OP_DATA_21             = 0x15 # 21
OP_DATA_22             = 0x16 # 22
OP_DATA_23             = 0x17 # 23
OP_DATA_24             = 0x18 # 24
OP_DATA_25             = 0x19 # 25
OP_DATA_26             = 0x1a # 26
OP_DATA_27             = 0x1b # 27
OP_DATA_28             = 0x1c # 28
OP_DATA_29             = 0x1d # 29
OP_DATA_30             = 0x1e # 30
OP_DATA_31             = 0x1f # 31
OP_DATA_32             = 0x20 # 32
OP_DATA_33             = 0x21 # 33
OP_DATA_34             = 0x22 # 34
OP_DATA_35             = 0x23 # 35
OP_DATA_36             = 0x24 # 36
OP_DATA_37             = 0x25 # 37
OP_DATA_38             = 0x26 # 38
OP_DATA_39             = 0x27 # 39
OP_DATA_40             = 0x28 # 40
OP_DATA_41             = 0x29 # 41
OP_DATA_42             = 0x2a # 42
OP_DATA_43             = 0x2b # 43
OP_DATA_44             = 0x2c # 44
OP_DATA_45             = 0x2d # 45
OP_DATA_46             = 0x2e # 46
OP_DATA_47             = 0x2f # 47
OP_DATA_48             = 0x30 # 48
OP_DATA_49             = 0x31 # 49
OP_DATA_50             = 0x32 # 50
OP_DATA_51             = 0x33 # 51
OP_DATA_52             = 0x34 # 52
OP_DATA_53             = 0x35 # 53
OP_DATA_54             = 0x36 # 54
OP_DATA_55             = 0x37 # 55
OP_DATA_56             = 0x38 # 56
OP_DATA_57             = 0x39 # 57
OP_DATA_58             = 0x3a # 58
OP_DATA_59             = 0x3b # 59
OP_DATA_60             = 0x3c # 60
OP_DATA_61             = 0x3d # 61
OP_DATA_62             = 0x3e # 62
OP_DATA_63             = 0x3f # 63
OP_DATA_64             = 0x40 # 64
OP_DATA_65             = 0x41 # 65
OP_DATA_66             = 0x42 # 66
OP_DATA_67             = 0x43 # 67
OP_DATA_68             = 0x44 # 68
OP_DATA_69             = 0x45 # 69
OP_DATA_70             = 0x46 # 70
OP_DATA_71             = 0x47 # 71
OP_DATA_72             = 0x48 # 72
OP_DATA_73             = 0x49 # 73
OP_DATA_74             = 0x4a # 74
OP_DATA_75             = 0x4b # 75
OP_PUSHDATA1           = 0x4c # 76
OP_PUSHDATA2           = 0x4d # 77
OP_PUSHDATA4           = 0x4e # 78
OP_1NEGATE             = 0x4f # 79
OP_RESERVED            = 0x50 # 80
OP_1                   = 0x51 # 81 - AKA OP_TRUE
OP_TRUE                = 0x51 # 81
OP_2                   = 0x52 # 82
OP_3                   = 0x53 # 83
OP_4                   = 0x54 # 84
OP_5                   = 0x55 # 85
OP_6                   = 0x56 # 86
OP_7                   = 0x57 # 87
OP_8                   = 0x58 # 88
OP_9                   = 0x59 # 89
OP_10                  = 0x5a # 90
OP_11                  = 0x5b # 91
OP_12                  = 0x5c # 92
OP_13                  = 0x5d # 93
OP_14                  = 0x5e # 94
OP_15                  = 0x5f # 95
OP_16                  = 0x60 # 96
OP_NOP                 = 0x61 # 97
OP_VER                 = 0x62 # 98
OP_IF                  = 0x63 # 99
OP_NOTIF               = 0x64 # 100
OP_VERIF               = 0x65 # 101
OP_VERNOTIF            = 0x66 # 102
OP_ELSE                = 0x67 # 103
OP_ENDIF               = 0x68 # 104
OP_VERIFY              = 0x69 # 105
OP_RETURN              = 0x6a # 106
OP_TOALTSTACK          = 0x6b # 107
OP_FROMALTSTACK        = 0x6c # 108
OP_2DROP               = 0x6d # 109
OP_2DUP                = 0x6e # 110
OP_3DUP                = 0x6f # 111
OP_2OVER               = 0x70 # 112
OP_2ROT                = 0x71 # 113
OP_2SWAP               = 0x72 # 114
OP_IFDUP               = 0x73 # 115
OP_DEPTH               = 0x74 # 116
OP_DROP                = 0x75 # 117
OP_DUP                 = 0x76 # 118
OP_NIP                 = 0x77 # 119
OP_OVER                = 0x78 # 120
OP_PICK                = 0x79 # 121
OP_ROLL                = 0x7a # 122
OP_ROT                 = 0x7b # 123
OP_SWAP                = 0x7c # 124
OP_TUCK                = 0x7d # 125
OP_CAT                 = 0x7e # 126
OP_SUBSTR              = 0x7f # 127
OP_LEFT                = 0x80 # 128
OP_RIGHT               = 0x81 # 129
OP_SIZE                = 0x82 # 130
OP_INVERT              = 0x83 # 131
OP_AND                 = 0x84 # 132
OP_OR                  = 0x85 # 133
OP_XOR                 = 0x86 # 134
OP_EQUAL               = 0x87 # 135
OP_EQUALVERIFY         = 0x88 # 136
OP_ROTR                = 0x89 # 137
OP_ROTL                = 0x8a # 138
OP_1ADD                = 0x8b # 139
OP_1SUB                = 0x8c # 140
OP_2MUL                = 0x8d # 141
OP_2DIV                = 0x8e # 142
OP_NEGATE              = 0x8f # 143
OP_ABS                 = 0x90 # 144
OP_NOT                 = 0x91 # 145
OP_0NOTEQUAL           = 0x92 # 146
OP_ADD                 = 0x93 # 147
OP_SUB                 = 0x94 # 148
OP_MUL                 = 0x95 # 149
OP_DIV                 = 0x96 # 150
OP_MOD                 = 0x97 # 151
OP_LSHIFT              = 0x98 # 152
OP_RSHIFT              = 0x99 # 153
OP_BOOLAND             = 0x9a # 154
OP_BOOLOR              = 0x9b # 155
OP_NUMEQUAL            = 0x9c # 156
OP_NUMEQUALVERIFY      = 0x9d # 157
OP_NUMNOTEQUAL         = 0x9e # 158
OP_LESSTHAN            = 0x9f # 159
OP_GREATERTHAN         = 0xa0 # 160
OP_LESSTHANOREQUAL     = 0xa1 # 161
OP_GREATERTHANOREQUAL  = 0xa2 # 162
OP_MIN                 = 0xa3 # 163
OP_MAX                 = 0xa4 # 164
OP_WITHIN              = 0xa5 # 165
OP_RIPEMD160           = 0xa6 # 166
OP_SHA1                = 0xa7 # 167
OP_BLAKE256            = 0xa8 # 168
OP_HASH160             = 0xa9 # 169
OP_HASH256             = 0xaa # 170
OP_CODESEPARATOR       = 0xab # 171
OP_CHECKSIG            = 0xac # 172
OP_CHECKSIGVERIFY      = 0xad # 173
OP_CHECKMULTISIG       = 0xae # 174
OP_CHECKMULTISIGVERIFY = 0xaf # 175
OP_NOP1                = 0xb0 # 176
OP_NOP2                = 0xb1 # 177
OP_CHECKLOCKTIMEVERIFY = 0xb1 # 177 - AKA OP_NOP2
OP_NOP3                = 0xb2 # 178
OP_CHECKSEQUENCEVERIFY = 0xb2 # 178 - AKA OP_NOP3
OP_NOP4                = 0xb3 # 179
OP_NOP5                = 0xb4 # 180
OP_NOP6                = 0xb5 # 181
OP_NOP7                = 0xb6 # 182
OP_NOP8                = 0xb7 # 183
OP_NOP9                = 0xb8 # 184
OP_NOP10               = 0xb9 # 185
OP_SSTX                = 0xba # 186 DECRED
OP_SSGEN               = 0xbb # 187 DECRED
OP_SSRTX               = 0xbc # 188 DECRED
OP_SSTXCHANGE          = 0xbd # 189 DECRED
OP_CHECKSIGALT         = 0xbe # 190 DECRED
OP_CHECKSIGALTVERIFY   = 0xbf # 191 DECRED
OP_SHA256              = 0xc0 # 192
OP_UNKNOWN193          = 0xc1 # 193
OP_UNKNOWN194          = 0xc2 # 194
OP_UNKNOWN195          = 0xc3 # 195
OP_UNKNOWN196          = 0xc4 # 196
OP_UNKNOWN197          = 0xc5 # 197
OP_UNKNOWN198          = 0xc6 # 198
OP_UNKNOWN199          = 0xc7 # 199
OP_UNKNOWN200          = 0xc8 # 200
OP_UNKNOWN201          = 0xc9 # 201
OP_UNKNOWN202          = 0xca # 202
OP_UNKNOWN203          = 0xcb # 203
OP_UNKNOWN204          = 0xcc # 204
OP_UNKNOWN205          = 0xcd # 205
OP_UNKNOWN206          = 0xce # 206
OP_UNKNOWN207          = 0xcf # 207
OP_UNKNOWN208          = 0xd0 # 208
OP_UNKNOWN209          = 0xd1 # 209
OP_UNKNOWN210          = 0xd2 # 210
OP_UNKNOWN211          = 0xd3 # 211
OP_UNKNOWN212          = 0xd4 # 212
OP_UNKNOWN213          = 0xd5 # 213
OP_UNKNOWN214          = 0xd6 # 214
OP_UNKNOWN215          = 0xd7 # 215
OP_UNKNOWN216          = 0xd8 # 216
OP_UNKNOWN217          = 0xd9 # 217
OP_UNKNOWN218          = 0xda # 218
OP_UNKNOWN219          = 0xdb # 219
OP_UNKNOWN220          = 0xdc # 220
OP_UNKNOWN221          = 0xdd # 221
OP_UNKNOWN222          = 0xde # 222
OP_UNKNOWN223          = 0xdf # 223
OP_UNKNOWN224          = 0xe0 # 224
OP_UNKNOWN225          = 0xe1 # 225
OP_UNKNOWN226          = 0xe2 # 226
OP_UNKNOWN227          = 0xe3 # 227
OP_UNKNOWN228          = 0xe4 # 228
OP_UNKNOWN229          = 0xe5 # 229
OP_UNKNOWN230          = 0xe6 # 230
OP_UNKNOWN231          = 0xe7 # 231
OP_UNKNOWN232          = 0xe8 # 232
OP_UNKNOWN233          = 0xe9 # 233
OP_UNKNOWN234          = 0xea # 234
OP_UNKNOWN235          = 0xeb # 235
OP_UNKNOWN236          = 0xec # 236
OP_UNKNOWN237          = 0xed # 237
OP_UNKNOWN238          = 0xee # 238
OP_UNKNOWN239          = 0xef # 239
OP_UNKNOWN240          = 0xf0 # 240
OP_UNKNOWN241          = 0xf1 # 241
OP_UNKNOWN242          = 0xf2 # 242
OP_UNKNOWN243          = 0xf3 # 243
OP_UNKNOWN244          = 0xf4 # 244
OP_UNKNOWN245          = 0xf5 # 245
OP_UNKNOWN246          = 0xf6 # 246
OP_UNKNOWN247          = 0xf7 # 247
OP_UNKNOWN248          = 0xf8 # 248
OP_INVALID249          = 0xf9 # 249 - bitcoin core internal
OP_SMALLINTEGER        = 0xfa # 250 - bitcoin core internal
OP_PUBKEYS             = 0xfb # 251 - bitcoin core internal
OP_UNKNOWN252          = 0xfc # 252
OP_PUBKEYHASH          = 0xfd # 253 - bitcoin core internal
OP_PUBKEY              = 0xfe # 254 - bitcoin core internal
OP_INVALIDOPCODE       = 0xff # 255 - bitcoin core internal


def noFunc(opcode, engine):
    raise NotImplementedError("opcode functions not implemented")


opcodeFalse = noFunc
opcodePushData = noFunc
opcode1Negate = noFunc
opcodeReserved = noFunc
opcodeN = noFunc
opcodeNop = noFunc
opcodeIf = noFunc
opcodeNotIf = noFunc
opcodeElse = noFunc
opcodeEndif = noFunc
opcodeVerify = noFunc
opcodeReturn = noFunc
opcodeCheckLockTimeVerify = noFunc
opcodeCheckSequenceVerify = noFunc
opcodeToAltStack = noFunc
opcodeFromAltStack = noFunc
opcode2Drop = noFunc
opcode2Dup = noFunc
opcode3Dup = noFunc
opcode2Over = noFunc
opcode2Rot = noFunc
opcode2Swap = noFunc
opcodeIfDup = noFunc
opcodeDepth = noFunc
opcodeDrop = noFunc
opcodeDup = noFunc
opcodeNip = noFunc
opcodeOver = noFunc
opcodePick = noFunc
opcodeRoll = noFunc
opcodeRot = noFunc
opcodeSwap = noFunc
opcodeTuck = noFunc
opcodeCat = noFunc
opcodeSubstr = noFunc
opcodeLeft = noFunc
opcodeRight = noFunc
opcodeSize = noFunc
opcodeInvert = noFunc
opcodeAnd = noFunc
opcodeOr = noFunc
opcodeXor = noFunc
opcodeEqual = noFunc
opcodeEqualVerify = noFunc
opcodeRotr = noFunc
opcodeRotl = noFunc
opcode1Add = noFunc
opcode1Sub = noFunc
opcodeNop = noFunc
opcodeNop = noFunc
opcodeNegate = noFunc
opcodeAbs = noFunc
opcodeNot = noFunc
opcode0NotEqual = noFunc
opcodeAdd = noFunc
opcodeSub = noFunc
opcodeMul = noFunc
opcodeDiv = noFunc
opcodeMod = noFunc
opcodeLShift = noFunc
opcodeRShift = noFunc
opcodeBoolAnd = noFunc
opcodeBoolOr = noFunc
opcodeNumEqual = noFunc
opcodeNumEqualVerify = noFunc
opcodeNumNotEqual = noFunc
opcodeLessThan = noFunc
opcodeGreaterThan = noFunc
opcodeLessThanOrEqual = noFunc
opcodeGreaterThanOrEqual = noFunc
opcodeMin = noFunc
opcodeMax = noFunc
opcodeWithin = noFunc
opcodeRipemd160 = noFunc
opcodeSha1 = noFunc
opcodeSha256 = noFunc
opcodeBlake256 = noFunc
opcodeHash160 = noFunc
opcodeHash256 = noFunc
Disabl = noFunc
opcodeCheckSig = noFunc
opcodeCheckSigVerify = noFunc
opcodeCheckMultiSig = noFunc
opcodeCheckMultiSigVerify = noFunc
opcodeCheckSigAlt = noFunc
opcodeCheckSigAltVerify = noFunc
opcodeInvalid = noFunc
opcodeDisabled = noFunc


class opcode:
    """
    An opcode defines the information related to a txscript opcode.  opfunc, if
    present, is the function to call to perform the opcode on the script.  The
    current script is passed in as a slice with the first member being the opcode
    itself.
    """

    def __init__(self, value, name, length, opfunc):
        self.value  = value   # byte
        self.name   = name    # string
        self.length = length  # int
        self.opfunc = opfunc  # func(*opcode, []byte, *Engine) error


# opcodeArray holds details about all possible opcodes such as how many bytes
# the opcode and any associated data should take, its human-readable name, and
# the handler function.
opcodeArray = {}

# Data push opcodes.
opcodeArray[OP_FALSE]     = opcode(OP_FALSE, "OP_0", 1, opcodeFalse)
opcodeArray[OP_DATA_1]    = opcode(OP_DATA_1, "OP_DATA_1", 2, opcodePushData)
opcodeArray[OP_DATA_2]    = opcode(OP_DATA_2, "OP_DATA_2", 3, opcodePushData)
opcodeArray[OP_DATA_3]    = opcode(OP_DATA_3, "OP_DATA_3", 4, opcodePushData)
opcodeArray[OP_DATA_4]    = opcode(OP_DATA_4, "OP_DATA_4", 5, opcodePushData)
opcodeArray[OP_DATA_5]    = opcode(OP_DATA_5, "OP_DATA_5", 6, opcodePushData)
opcodeArray[OP_DATA_6]    = opcode(OP_DATA_6, "OP_DATA_6", 7, opcodePushData)
opcodeArray[OP_DATA_7]    = opcode(OP_DATA_7, "OP_DATA_7", 8, opcodePushData)
opcodeArray[OP_DATA_8]    = opcode(OP_DATA_8, "OP_DATA_8", 9, opcodePushData)
opcodeArray[OP_DATA_9]    = opcode(OP_DATA_9, "OP_DATA_9", 10, opcodePushData)
opcodeArray[OP_DATA_10]   = opcode(OP_DATA_10, "OP_DATA_10", 11, opcodePushData)
opcodeArray[OP_DATA_11]   = opcode(OP_DATA_11, "OP_DATA_11", 12, opcodePushData)
opcodeArray[OP_DATA_12]   = opcode(OP_DATA_12, "OP_DATA_12", 13, opcodePushData)
opcodeArray[OP_DATA_13]   = opcode(OP_DATA_13, "OP_DATA_13", 14, opcodePushData)
opcodeArray[OP_DATA_14]   = opcode(OP_DATA_14, "OP_DATA_14", 15, opcodePushData)
opcodeArray[OP_DATA_15]   = opcode(OP_DATA_15, "OP_DATA_15", 16, opcodePushData)
opcodeArray[OP_DATA_16]   = opcode(OP_DATA_16, "OP_DATA_16", 17, opcodePushData)
opcodeArray[OP_DATA_17]   = opcode(OP_DATA_17, "OP_DATA_17", 18, opcodePushData)
opcodeArray[OP_DATA_18]   = opcode(OP_DATA_18, "OP_DATA_18", 19, opcodePushData)
opcodeArray[OP_DATA_19]   = opcode(OP_DATA_19, "OP_DATA_19", 20, opcodePushData)
opcodeArray[OP_DATA_20]   = opcode(OP_DATA_20, "OP_DATA_20", 21, opcodePushData)
opcodeArray[OP_DATA_21]   = opcode(OP_DATA_21, "OP_DATA_21", 22, opcodePushData)
opcodeArray[OP_DATA_22]   = opcode(OP_DATA_22, "OP_DATA_22", 23, opcodePushData)
opcodeArray[OP_DATA_23]   = opcode(OP_DATA_23, "OP_DATA_23", 24, opcodePushData)
opcodeArray[OP_DATA_24]   = opcode(OP_DATA_24, "OP_DATA_24", 25, opcodePushData)
opcodeArray[OP_DATA_25]   = opcode(OP_DATA_25, "OP_DATA_25", 26, opcodePushData)
opcodeArray[OP_DATA_26]   = opcode(OP_DATA_26, "OP_DATA_26", 27, opcodePushData)
opcodeArray[OP_DATA_27]   = opcode(OP_DATA_27, "OP_DATA_27", 28, opcodePushData)
opcodeArray[OP_DATA_28]   = opcode(OP_DATA_28, "OP_DATA_28", 29, opcodePushData)
opcodeArray[OP_DATA_29]   = opcode(OP_DATA_29, "OP_DATA_29", 30, opcodePushData)
opcodeArray[OP_DATA_30]   = opcode(OP_DATA_30, "OP_DATA_30", 31, opcodePushData)
opcodeArray[OP_DATA_31]   = opcode(OP_DATA_31, "OP_DATA_31", 32, opcodePushData)
opcodeArray[OP_DATA_32]   = opcode(OP_DATA_32, "OP_DATA_32", 33, opcodePushData)
opcodeArray[OP_DATA_33]   = opcode(OP_DATA_33, "OP_DATA_33", 34, opcodePushData)
opcodeArray[OP_DATA_34]   = opcode(OP_DATA_34, "OP_DATA_34", 35, opcodePushData)
opcodeArray[OP_DATA_35]   = opcode(OP_DATA_35, "OP_DATA_35", 36, opcodePushData)
opcodeArray[OP_DATA_36]   = opcode(OP_DATA_36, "OP_DATA_36", 37, opcodePushData)
opcodeArray[OP_DATA_37]   = opcode(OP_DATA_37, "OP_DATA_37", 38, opcodePushData)
opcodeArray[OP_DATA_38]   = opcode(OP_DATA_38, "OP_DATA_38", 39, opcodePushData)
opcodeArray[OP_DATA_39]   = opcode(OP_DATA_39, "OP_DATA_39", 40, opcodePushData)
opcodeArray[OP_DATA_40]   = opcode(OP_DATA_40, "OP_DATA_40", 41, opcodePushData)
opcodeArray[OP_DATA_41]   = opcode(OP_DATA_41, "OP_DATA_41", 42, opcodePushData)
opcodeArray[OP_DATA_42]   = opcode(OP_DATA_42, "OP_DATA_42", 43, opcodePushData)
opcodeArray[OP_DATA_43]   = opcode(OP_DATA_43, "OP_DATA_43", 44, opcodePushData)
opcodeArray[OP_DATA_44]   = opcode(OP_DATA_44, "OP_DATA_44", 45, opcodePushData)
opcodeArray[OP_DATA_45]   = opcode(OP_DATA_45, "OP_DATA_45", 46, opcodePushData)
opcodeArray[OP_DATA_46]   = opcode(OP_DATA_46, "OP_DATA_46", 47, opcodePushData)
opcodeArray[OP_DATA_47]   = opcode(OP_DATA_47, "OP_DATA_47", 48, opcodePushData)
opcodeArray[OP_DATA_48]   = opcode(OP_DATA_48, "OP_DATA_48", 49, opcodePushData)
opcodeArray[OP_DATA_49]   = opcode(OP_DATA_49, "OP_DATA_49", 50, opcodePushData)
opcodeArray[OP_DATA_50]   = opcode(OP_DATA_50, "OP_DATA_50", 51, opcodePushData)
opcodeArray[OP_DATA_51]   = opcode(OP_DATA_51, "OP_DATA_51", 52, opcodePushData)
opcodeArray[OP_DATA_52]   = opcode(OP_DATA_52, "OP_DATA_52", 53, opcodePushData)
opcodeArray[OP_DATA_53]   = opcode(OP_DATA_53, "OP_DATA_53", 54, opcodePushData)
opcodeArray[OP_DATA_54]   = opcode(OP_DATA_54, "OP_DATA_54", 55, opcodePushData)
opcodeArray[OP_DATA_55]   = opcode(OP_DATA_55, "OP_DATA_55", 56, opcodePushData)
opcodeArray[OP_DATA_56]   = opcode(OP_DATA_56, "OP_DATA_56", 57, opcodePushData)
opcodeArray[OP_DATA_57]   = opcode(OP_DATA_57, "OP_DATA_57", 58, opcodePushData)
opcodeArray[OP_DATA_58]   = opcode(OP_DATA_58, "OP_DATA_58", 59, opcodePushData)
opcodeArray[OP_DATA_59]   = opcode(OP_DATA_59, "OP_DATA_59", 60, opcodePushData)
opcodeArray[OP_DATA_60]   = opcode(OP_DATA_60, "OP_DATA_60", 61, opcodePushData)
opcodeArray[OP_DATA_61]   = opcode(OP_DATA_61, "OP_DATA_61", 62, opcodePushData)
opcodeArray[OP_DATA_62]   = opcode(OP_DATA_62, "OP_DATA_62", 63, opcodePushData)
opcodeArray[OP_DATA_63]   = opcode(OP_DATA_63, "OP_DATA_63", 64, opcodePushData)
opcodeArray[OP_DATA_64]   = opcode(OP_DATA_64, "OP_DATA_64", 65, opcodePushData)
opcodeArray[OP_DATA_65]   = opcode(OP_DATA_65, "OP_DATA_65", 66, opcodePushData)
opcodeArray[OP_DATA_66]   = opcode(OP_DATA_66, "OP_DATA_66", 67, opcodePushData)
opcodeArray[OP_DATA_67]   = opcode(OP_DATA_67, "OP_DATA_67", 68, opcodePushData)
opcodeArray[OP_DATA_68]   = opcode(OP_DATA_68, "OP_DATA_68", 69, opcodePushData)
opcodeArray[OP_DATA_69]   = opcode(OP_DATA_69, "OP_DATA_69", 70, opcodePushData)
opcodeArray[OP_DATA_70]   = opcode(OP_DATA_70, "OP_DATA_70", 71, opcodePushData)
opcodeArray[OP_DATA_71]   = opcode(OP_DATA_71, "OP_DATA_71", 72, opcodePushData)
opcodeArray[OP_DATA_72]   = opcode(OP_DATA_72, "OP_DATA_72", 73, opcodePushData)
opcodeArray[OP_DATA_73]   = opcode(OP_DATA_73, "OP_DATA_73", 74, opcodePushData)
opcodeArray[OP_DATA_74]   = opcode(OP_DATA_74, "OP_DATA_74", 75, opcodePushData)
opcodeArray[OP_DATA_75]   = opcode(OP_DATA_75, "OP_DATA_75", 76, opcodePushData)
opcodeArray[OP_PUSHDATA1] = opcode(OP_PUSHDATA1, "OP_PUSHDATA1", -1, opcodePushData)
opcodeArray[OP_PUSHDATA2] = opcode(OP_PUSHDATA2, "OP_PUSHDATA2", -2, opcodePushData)
opcodeArray[OP_PUSHDATA4] = opcode(OP_PUSHDATA4, "OP_PUSHDATA4", -4, opcodePushData)
opcodeArray[OP_1NEGATE]   = opcode(OP_1NEGATE, "OP_1NEGATE", 1, opcode1Negate)
opcodeArray[OP_RESERVED]  = opcode(OP_RESERVED, "OP_RESERVED", 1, opcodeReserved)
opcodeArray[OP_TRUE]      = opcode(OP_TRUE, "OP_1", 1, opcodeN)
opcodeArray[OP_2]         = opcode(OP_2, "OP_2", 1, opcodeN)
opcodeArray[OP_3]         = opcode(OP_3, "OP_3", 1, opcodeN)
opcodeArray[OP_4]         = opcode(OP_4, "OP_4", 1, opcodeN)
opcodeArray[OP_5]         = opcode(OP_5, "OP_5", 1, opcodeN)
opcodeArray[OP_6]         = opcode(OP_6, "OP_6", 1, opcodeN)
opcodeArray[OP_7]         = opcode(OP_7, "OP_7", 1, opcodeN)
opcodeArray[OP_8]         = opcode(OP_8, "OP_8", 1, opcodeN)
opcodeArray[OP_9]         = opcode(OP_9, "OP_9", 1, opcodeN)
opcodeArray[OP_10]        = opcode(OP_10, "OP_10", 1, opcodeN)
opcodeArray[OP_11]        = opcode(OP_11, "OP_11", 1, opcodeN)
opcodeArray[OP_12]        = opcode(OP_12, "OP_12", 1, opcodeN)
opcodeArray[OP_13]        = opcode(OP_13, "OP_13", 1, opcodeN)
opcodeArray[OP_14]        = opcode(OP_14, "OP_14", 1, opcodeN)
opcodeArray[OP_15]        = opcode(OP_15, "OP_15", 1, opcodeN)
opcodeArray[OP_16]        = opcode(OP_16, "OP_16", 1, opcodeN)

# Control opcodes.
opcodeArray[OP_NOP]                 = opcode(OP_NOP, "OP_NOP", 1, opcodeNop)
opcodeArray[OP_VER]                 = opcode(OP_VER, "OP_VER", 1, opcodeReserved)
opcodeArray[OP_IF]                  = opcode(OP_IF, "OP_IF", 1, opcodeIf)
opcodeArray[OP_NOTIF]               = opcode(OP_NOTIF, "OP_NOTIF", 1, opcodeNotIf)
opcodeArray[OP_VERIF]               = opcode(OP_VERIF, "OP_VERIF", 1, opcodeReserved)
opcodeArray[OP_VERNOTIF]            = opcode(
    OP_VERNOTIF, "OP_VERNOTIF", 1, opcodeReserved
)
opcodeArray[OP_ELSE]                = opcode(OP_ELSE, "OP_ELSE", 1, opcodeElse)
opcodeArray[OP_ENDIF]               = opcode(OP_ENDIF, "OP_ENDIF", 1, opcodeEndif)
opcodeArray[OP_VERIFY]              = opcode(OP_VERIFY, "OP_VERIFY", 1, opcodeVerify)
opcodeArray[OP_RETURN]              = opcode(OP_RETURN, "OP_RETURN", 1, opcodeReturn)
opcodeArray[OP_CHECKLOCKTIMEVERIFY] = opcode(
    OP_CHECKLOCKTIMEVERIFY, "OP_CHECKLOCKTIMEVERIFY", 1, opcodeCheckLockTimeVerify
)
opcodeArray[OP_CHECKSEQUENCEVERIFY] = opcode(
    OP_CHECKSEQUENCEVERIFY, "OP_CHECKSEQUENCEVERIFY", 1, opcodeCheckSequenceVerify
)

# Stack opcodes.
opcodeArray[OP_TOALTSTACK]   = opcode(
    OP_TOALTSTACK, "OP_TOALTSTACK", 1, opcodeToAltStack
)
opcodeArray[OP_FROMALTSTACK] = opcode(
    OP_FROMALTSTACK, "OP_FROMALTSTACK", 1, opcodeFromAltStack
)
opcodeArray[OP_2DROP]        = opcode(OP_2DROP, "OP_2DROP", 1, opcode2Drop)
opcodeArray[OP_2DUP]         = opcode(OP_2DUP, "OP_2DUP", 1, opcode2Dup)
opcodeArray[OP_3DUP]         = opcode(OP_3DUP, "OP_3DUP", 1, opcode3Dup)
opcodeArray[OP_2OVER]        = opcode(OP_2OVER, "OP_2OVER", 1, opcode2Over)
opcodeArray[OP_2ROT]         = opcode(OP_2ROT, "OP_2ROT", 1, opcode2Rot)
opcodeArray[OP_2SWAP]        = opcode(OP_2SWAP, "OP_2SWAP", 1, opcode2Swap)
opcodeArray[OP_IFDUP]        = opcode(OP_IFDUP, "OP_IFDUP", 1, opcodeIfDup)
opcodeArray[OP_DEPTH]        = opcode(OP_DEPTH, "OP_DEPTH", 1, opcodeDepth)
opcodeArray[OP_DROP]         = opcode(OP_DROP, "OP_DROP", 1, opcodeDrop)
opcodeArray[OP_DUP]          = opcode(OP_DUP, "OP_DUP", 1, opcodeDup)
opcodeArray[OP_NIP]          = opcode(OP_NIP, "OP_NIP", 1, opcodeNip)
opcodeArray[OP_OVER]         = opcode(OP_OVER, "OP_OVER", 1, opcodeOver)
opcodeArray[OP_PICK]         = opcode(OP_PICK, "OP_PICK", 1, opcodePick)
opcodeArray[OP_ROLL]         = opcode(OP_ROLL, "OP_ROLL", 1, opcodeRoll)
opcodeArray[OP_ROT]          = opcode(OP_ROT, "OP_ROT", 1, opcodeRot)
opcodeArray[OP_SWAP]         = opcode(OP_SWAP, "OP_SWAP", 1, opcodeSwap)
opcodeArray[OP_TUCK]         = opcode(OP_TUCK, "OP_TUCK", 1, opcodeTuck)

# Splice opcodes.
opcodeArray[OP_CAT]    = opcode(OP_CAT, "OP_CAT", 1, opcodeCat)
opcodeArray[OP_SUBSTR] = opcode(OP_SUBSTR, "OP_SUBSTR", 1, opcodeSubstr)
opcodeArray[OP_LEFT]   = opcode(OP_LEFT, "OP_LEFT", 1, opcodeLeft)
opcodeArray[OP_RIGHT]  = opcode(OP_RIGHT, "OP_RIGHT", 1, opcodeRight)
opcodeArray[OP_SIZE]   = opcode(OP_SIZE, "OP_SIZE", 1, opcodeSize)

# Bitwise logic opcodes for int32 registers derived from the stack.
opcodeArray[OP_INVERT] = opcode(OP_INVERT, "OP_INVERT", 1, opcodeInvert)
opcodeArray[OP_AND]    = opcode(OP_AND, "OP_AND", 1, opcodeAnd)
opcodeArray[OP_OR]     = opcode(OP_OR, "OP_OR", 1, opcodeOr)
opcodeArray[OP_XOR]    = opcode(OP_XOR, "OP_XOR", 1, opcodeXor)

# Bytewise comparison function opcodes for byte strings.
opcodeArray[OP_EQUAL]       = opcode(OP_EQUAL, "OP_EQUAL", 1, opcodeEqual)
opcodeArray[OP_EQUALVERIFY] = opcode(
    OP_EQUALVERIFY, "OP_EQUALVERIFY", 1, opcodeEqualVerify
)

# Bitwise rotation opcodes for an int32 register derived from the stack.
opcodeArray[OP_ROTR] = opcode(OP_ROTR, "OP_ROTR", 1, opcodeRotr)
opcodeArray[OP_ROTL] = opcode(OP_ROTL, "OP_ROTL", 1, opcodeRotl)

# Numeric related opcodes.
opcodeArray[OP_1ADD]               = opcode(OP_1ADD, "OP_1ADD", 1, opcode1Add)
opcodeArray[OP_1SUB]               = opcode(OP_1SUB, "OP_1SUB", 1, opcode1Sub)
opcodeArray[OP_2MUL]               = opcode(OP_2MUL, "OP_2MUL", 1, opcodeNop)
opcodeArray[OP_2DIV]               = opcode(OP_2DIV, "OP_2DIV", 1, opcodeNop)
opcodeArray[OP_NEGATE]             = opcode(OP_NEGATE, "OP_NEGATE", 1, opcodeNegate)
opcodeArray[OP_ABS]                = opcode(OP_ABS, "OP_ABS", 1, opcodeAbs)
opcodeArray[OP_NOT]                = opcode(OP_NOT, "OP_NOT", 1, opcodeNot)
opcodeArray[OP_0NOTEQUAL]          = opcode(
    OP_0NOTEQUAL, "OP_0NOTEQUAL", 1, opcode0NotEqual
)
opcodeArray[OP_ADD]                = opcode(OP_ADD, "OP_ADD", 1, opcodeAdd)
opcodeArray[OP_SUB]                = opcode(OP_SUB, "OP_SUB", 1, opcodeSub)
opcodeArray[OP_MUL]                = opcode(OP_MUL, "OP_MUL", 1, opcodeMul)
opcodeArray[OP_DIV]                = opcode(OP_DIV, "OP_DIV", 1, opcodeDiv)
opcodeArray[OP_MOD]                = opcode(OP_MOD, "OP_MOD", 1, opcodeMod)
opcodeArray[OP_LSHIFT]             = opcode(OP_LSHIFT, "OP_LSHIFT", 1, opcodeLShift)
opcodeArray[OP_RSHIFT]             = opcode(OP_RSHIFT, "OP_RSHIFT", 1, opcodeRShift)
opcodeArray[OP_BOOLAND]            = opcode(OP_BOOLAND, "OP_BOOLAND", 1, opcodeBoolAnd)
opcodeArray[OP_BOOLOR]             = opcode(OP_BOOLOR, "OP_BOOLOR", 1, opcodeBoolOr)
opcodeArray[OP_NUMEQUAL]           = opcode(
    OP_NUMEQUAL, "OP_NUMEQUAL", 1, opcodeNumEqual
)
opcodeArray[OP_NUMEQUALVERIFY]     = opcode(
    OP_NUMEQUALVERIFY, "OP_NUMEQUALVERIFY", 1, opcodeNumEqualVerify
)
opcodeArray[OP_NUMNOTEQUAL]        = opcode(
    OP_NUMNOTEQUAL, "OP_NUMNOTEQUAL", 1, opcodeNumNotEqual
)
opcodeArray[OP_LESSTHAN]           = opcode(
    OP_LESSTHAN, "OP_LESSTHAN", 1, opcodeLessThan
)
opcodeArray[OP_GREATERTHAN] = opcode(
    OP_GREATERTHAN, "OP_GREATERTHAN", 1, opcodeGreaterThan
)
opcodeArray[OP_LESSTHANOREQUAL]    = opcode(
    OP_LESSTHANOREQUAL, "OP_LESSTHANOREQUAL", 1, opcodeLessThanOrEqual
)
opcodeArray[OP_GREATERTHANOREQUAL] = opcode(
    OP_GREATERTHANOREQUAL, "OP_GREATERTHANOREQUAL", 1, opcodeGreaterThanOrEqual
)
opcodeArray[OP_MIN]                = opcode(OP_MIN, "OP_MIN", 1, opcodeMin)
opcodeArray[OP_MAX]                = opcode(OP_MAX, "OP_MAX", 1, opcodeMax)
opcodeArray[OP_WITHIN]             = opcode(OP_WITHIN, "OP_WITHIN", 1, opcodeWithin)

# Crypto opcodes.
opcodeArray[OP_RIPEMD160]           = opcode(
    OP_RIPEMD160, "OP_RIPEMD160", 1, opcodeRipemd160
)
opcodeArray[OP_SHA1]                = opcode(OP_SHA1, "OP_SHA1", 1, opcodeSha1)
opcodeArray[OP_SHA256]              = opcode(OP_SHA256, "OP_SHA256", 1, opcodeSha256)
opcodeArray[OP_BLAKE256]            = opcode(
    OP_BLAKE256, "OP_BLAKE256", 1, opcodeBlake256
)
opcodeArray[OP_HASH160]             = opcode(OP_HASH160, "OP_HASH160", 1, opcodeHash160)
opcodeArray[OP_HASH256]             = opcode(OP_HASH256, "OP_HASH256", 1, opcodeHash256)
opcodeArray[OP_CODESEPARATOR]       = opcode(
    OP_CODESEPARATOR, "OP_CODESEPARATOR", 1, opcodeDisabled
)
opcodeArray[OP_CHECKSIG]            = opcode(
    OP_CHECKSIG, "OP_CHECKSIG", 1, opcodeCheckSig
)
opcodeArray[OP_CHECKSIGVERIFY]      = opcode(
    OP_CHECKSIGVERIFY, "OP_CHECKSIGVERIFY", 1, opcodeCheckSigVerify
)
opcodeArray[OP_CHECKMULTISIG]       = opcode(
    OP_CHECKMULTISIG, "OP_CHECKMULTISIG", 1, opcodeCheckMultiSig
)
opcodeArray[OP_CHECKMULTISIGVERIFY] = opcode(
    OP_CHECKMULTISIGVERIFY, "OP_CHECKMULTISIGVERIFY", 1, opcodeCheckMultiSigVerify
)

# Reserved opcodes.
opcodeArray[OP_NOP1]  = opcode(OP_NOP1, "OP_NOP1", 1, opcodeNop)
opcodeArray[OP_NOP4]  = opcode(OP_NOP4, "OP_NOP4", 1, opcodeNop)
opcodeArray[OP_NOP5]  = opcode(OP_NOP5, "OP_NOP5", 1, opcodeNop)
opcodeArray[OP_NOP6]  = opcode(OP_NOP6, "OP_NOP6", 1, opcodeNop)
opcodeArray[OP_NOP7]  = opcode(OP_NOP7, "OP_NOP7", 1, opcodeNop)
opcodeArray[OP_NOP8]  = opcode(OP_NOP8, "OP_NOP8", 1, opcodeNop)
opcodeArray[OP_NOP9]  = opcode(OP_NOP9, "OP_NOP9", 1, opcodeNop)
opcodeArray[OP_NOP10] = opcode(OP_NOP10, "OP_NOP10", 1, opcodeNop)

# SS* opcodes.
opcodeArray[OP_SSTX]       = opcode(OP_SSTX, "OP_SSTX", 1, opcodeNop)
opcodeArray[OP_SSGEN]      = opcode(OP_SSGEN, "OP_SSGEN", 1, opcodeNop)
opcodeArray[OP_SSRTX]      = opcode(OP_SSRTX, "OP_SSRTX", 1, opcodeNop)
opcodeArray[OP_SSTXCHANGE] = opcode(OP_SSTXCHANGE, "OP_SSTXCHANGE", 1, opcodeNop)

# Alternative checksig opcode.
opcodeArray[OP_CHECKSIGALT]       = opcode(
    OP_CHECKSIGALT, "OP_CHECKSIGALT", 1, opcodeCheckSigAlt
)
opcodeArray[OP_CHECKSIGALTVERIFY] = opcode(
    OP_CHECKSIGALTVERIFY, "OP_CHECKSIGALTVERIFY", 1, opcodeCheckSigAltVerify
)

# Undefined opcodes.
opcodeArray[OP_UNKNOWN193] = opcode(OP_UNKNOWN193, "OP_UNKNOWN193", 1, opcodeNop)
opcodeArray[OP_UNKNOWN194] = opcode(OP_UNKNOWN194, "OP_UNKNOWN194", 1, opcodeNop)
opcodeArray[OP_UNKNOWN195] = opcode(OP_UNKNOWN195, "OP_UNKNOWN195", 1, opcodeNop)
opcodeArray[OP_UNKNOWN196] = opcode(OP_UNKNOWN196, "OP_UNKNOWN196", 1, opcodeNop)
opcodeArray[OP_UNKNOWN197] = opcode(OP_UNKNOWN197, "OP_UNKNOWN197", 1, opcodeNop)
opcodeArray[OP_UNKNOWN198] = opcode(OP_UNKNOWN198, "OP_UNKNOWN198", 1, opcodeNop)
opcodeArray[OP_UNKNOWN199] = opcode(OP_UNKNOWN199, "OP_UNKNOWN199", 1, opcodeNop)
opcodeArray[OP_UNKNOWN200] = opcode(OP_UNKNOWN200, "OP_UNKNOWN200", 1, opcodeNop)
opcodeArray[OP_UNKNOWN201] = opcode(OP_UNKNOWN201, "OP_UNKNOWN201", 1, opcodeNop)
opcodeArray[OP_UNKNOWN202] = opcode(OP_UNKNOWN202, "OP_UNKNOWN202", 1, opcodeNop)
opcodeArray[OP_UNKNOWN203] = opcode(OP_UNKNOWN203, "OP_UNKNOWN203", 1, opcodeNop)
opcodeArray[OP_UNKNOWN204] = opcode(OP_UNKNOWN204, "OP_UNKNOWN204", 1, opcodeNop)
opcodeArray[OP_UNKNOWN205] = opcode(OP_UNKNOWN205, "OP_UNKNOWN205", 1, opcodeNop)
opcodeArray[OP_UNKNOWN206] = opcode(OP_UNKNOWN206, "OP_UNKNOWN206", 1, opcodeNop)
opcodeArray[OP_UNKNOWN207] = opcode(OP_UNKNOWN207, "OP_UNKNOWN207", 1, opcodeNop)
opcodeArray[OP_UNKNOWN208] = opcode(OP_UNKNOWN208, "OP_UNKNOWN208", 1, opcodeNop)
opcodeArray[OP_UNKNOWN209] = opcode(OP_UNKNOWN209, "OP_UNKNOWN209", 1, opcodeNop)
opcodeArray[OP_UNKNOWN210] = opcode(OP_UNKNOWN210, "OP_UNKNOWN210", 1, opcodeNop)
opcodeArray[OP_UNKNOWN211] = opcode(OP_UNKNOWN211, "OP_UNKNOWN211", 1, opcodeNop)
opcodeArray[OP_UNKNOWN212] = opcode(OP_UNKNOWN212, "OP_UNKNOWN212", 1, opcodeNop)
opcodeArray[OP_UNKNOWN213] = opcode(OP_UNKNOWN213, "OP_UNKNOWN213", 1, opcodeNop)
opcodeArray[OP_UNKNOWN214] = opcode(OP_UNKNOWN214, "OP_UNKNOWN214", 1, opcodeNop)
opcodeArray[OP_UNKNOWN215] = opcode(OP_UNKNOWN215, "OP_UNKNOWN215", 1, opcodeNop)
opcodeArray[OP_UNKNOWN216] = opcode(OP_UNKNOWN216, "OP_UNKNOWN216", 1, opcodeNop)
opcodeArray[OP_UNKNOWN217] = opcode(OP_UNKNOWN217, "OP_UNKNOWN217", 1, opcodeNop)
opcodeArray[OP_UNKNOWN218] = opcode(OP_UNKNOWN218, "OP_UNKNOWN218", 1, opcodeNop)
opcodeArray[OP_UNKNOWN219] = opcode(OP_UNKNOWN219, "OP_UNKNOWN219", 1, opcodeNop)
opcodeArray[OP_UNKNOWN220] = opcode(OP_UNKNOWN220, "OP_UNKNOWN220", 1, opcodeNop)
opcodeArray[OP_UNKNOWN221] = opcode(OP_UNKNOWN221, "OP_UNKNOWN221", 1, opcodeNop)
opcodeArray[OP_UNKNOWN222] = opcode(OP_UNKNOWN222, "OP_UNKNOWN222", 1, opcodeNop)
opcodeArray[OP_UNKNOWN223] = opcode(OP_UNKNOWN223, "OP_UNKNOWN223", 1, opcodeNop)
opcodeArray[OP_UNKNOWN224] = opcode(OP_UNKNOWN224, "OP_UNKNOWN224", 1, opcodeNop)
opcodeArray[OP_UNKNOWN225] = opcode(OP_UNKNOWN225, "OP_UNKNOWN225", 1, opcodeNop)
opcodeArray[OP_UNKNOWN226] = opcode(OP_UNKNOWN226, "OP_UNKNOWN226", 1, opcodeNop)
opcodeArray[OP_UNKNOWN227] = opcode(OP_UNKNOWN227, "OP_UNKNOWN227", 1, opcodeNop)
opcodeArray[OP_UNKNOWN228] = opcode(OP_UNKNOWN228, "OP_UNKNOWN228", 1, opcodeNop)
opcodeArray[OP_UNKNOWN229] = opcode(OP_UNKNOWN229, "OP_UNKNOWN229", 1, opcodeNop)
opcodeArray[OP_UNKNOWN230] = opcode(OP_UNKNOWN230, "OP_UNKNOWN230", 1, opcodeNop)
opcodeArray[OP_UNKNOWN231] = opcode(OP_UNKNOWN231, "OP_UNKNOWN231", 1, opcodeNop)
opcodeArray[OP_UNKNOWN232] = opcode(OP_UNKNOWN232, "OP_UNKNOWN232", 1, opcodeNop)
opcodeArray[OP_UNKNOWN233] = opcode(OP_UNKNOWN233, "OP_UNKNOWN233", 1, opcodeNop)
opcodeArray[OP_UNKNOWN234] = opcode(OP_UNKNOWN234, "OP_UNKNOWN234", 1, opcodeNop)
opcodeArray[OP_UNKNOWN235] = opcode(OP_UNKNOWN235, "OP_UNKNOWN235", 1, opcodeNop)
opcodeArray[OP_UNKNOWN236] = opcode(OP_UNKNOWN236, "OP_UNKNOWN236", 1, opcodeNop)
opcodeArray[OP_UNKNOWN237] = opcode(OP_UNKNOWN237, "OP_UNKNOWN237", 1, opcodeNop)
opcodeArray[OP_UNKNOWN238] = opcode(OP_UNKNOWN238, "OP_UNKNOWN238", 1, opcodeNop)
opcodeArray[OP_UNKNOWN239] = opcode(OP_UNKNOWN239, "OP_UNKNOWN239", 1, opcodeNop)
opcodeArray[OP_UNKNOWN240] = opcode(OP_UNKNOWN240, "OP_UNKNOWN240", 1, opcodeNop)
opcodeArray[OP_UNKNOWN241] = opcode(OP_UNKNOWN241, "OP_UNKNOWN241", 1, opcodeNop)
opcodeArray[OP_UNKNOWN242] = opcode(OP_UNKNOWN242, "OP_UNKNOWN242", 1, opcodeNop)
opcodeArray[OP_UNKNOWN243] = opcode(OP_UNKNOWN243, "OP_UNKNOWN243", 1, opcodeNop)
opcodeArray[OP_UNKNOWN244] = opcode(OP_UNKNOWN244, "OP_UNKNOWN244", 1, opcodeNop)
opcodeArray[OP_UNKNOWN245] = opcode(OP_UNKNOWN245, "OP_UNKNOWN245", 1, opcodeNop)
opcodeArray[OP_UNKNOWN246] = opcode(OP_UNKNOWN246, "OP_UNKNOWN246", 1, opcodeNop)
opcodeArray[OP_UNKNOWN247] = opcode(OP_UNKNOWN247, "OP_UNKNOWN247", 1, opcodeNop)
opcodeArray[OP_UNKNOWN248] = opcode(OP_UNKNOWN248, "OP_UNKNOWN248", 1, opcodeNop)

# Bitcoin Core internal use opcode.  Defined here for completeness.
opcodeArray[OP_INVALID249]   = opcode(OP_INVALID249, "OP_INVALID249", 1, opcodeInvalid)
opcodeArray[OP_SMALLINTEGER] = opcode(
    OP_SMALLINTEGER, "OP_SMALLINTEGER", 1, opcodeInvalid
)
opcodeArray[OP_PUBKEYS]      = opcode(OP_PUBKEYS, "OP_PUBKEYS", 1, opcodeInvalid)
opcodeArray[OP_UNKNOWN252]   = opcode(OP_UNKNOWN252, "OP_UNKNOWN252", 1, opcodeInvalid)
opcodeArray[OP_PUBKEYHASH]   = opcode(OP_PUBKEYHASH, "OP_PUBKEYHASH", 1, opcodeInvalid)
opcodeArray[OP_PUBKEY]       = opcode(OP_PUBKEY, "OP_PUBKEY", 1, opcodeInvalid)

opcodeArray[OP_INVALIDOPCODE] = opcode(
    OP_INVALIDOPCODE, "OP_INVALIDOPCODE", 1, opcodeInvalid
)
