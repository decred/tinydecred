"""
Copyright (c) 2020, The Decred developers
See LICENSE for details

Definitions allowing Cython to generate optimized C code that builds a
dynamic library speeding up the field.py code.
"""

import cython


cdef int twoBitsMask = 0x03
cdef int fourBitsMask = 0x0F
cdef int sixBitsMask = 0x3F
cdef int eightBitsMask = 0xFF
cdef int fieldWords = 10
cdef int fieldBase = 26
cdef int fieldBaseMask = (1 << fieldBase) - 1
cdef int fieldMSBBits = 256 - (fieldBase * (fieldWords - 1))
cdef int fieldMSBMask = (1 << fieldMSBBits) - 1
cdef long fieldPrimeWordZero = 0x3FFFC2F
cdef long fieldPrimeWordOne = 0x3FFFFBF
cdef long primePartBy16 = 68719492368


cdef class FieldVal:
    cdef public long n[10]

    @cython.locals(
        m=cython.long,
        t0=cython.long,
        t1=cython.long,
        t2=cython.long,
        t3=cython.long,
        t4=cython.long,
        t5=cython.long,
        t6=cython.long,
        t7=cython.long,
        t8=cython.long,
        t9=cython.long,
    )
    cpdef normalize(self)

    cpdef negateVal(self, FieldVal val, int magnitude)

    cpdef add(self, FieldVal val)

    @cython.locals(
        m=cython.long,
        n=cython.long,
        t0=cython.long,
        t1=cython.long,
        t2=cython.long,
        t3=cython.long,
        t4=cython.long,
        t5=cython.long,
        t6=cython.long,
        t7=cython.long,
        t8=cython.long,
        t9=cython.long,
        t10=cython.long,
        t11=cython.long,
        t12=cython.long,
        t13=cython.long,
        t14=cython.long,
        t15=cython.long,
        t16=cython.long,
        t17=cython.long,
        t18=cython.long,
        t19=cython.long,
    )
    cpdef squareVal(self, FieldVal val)

    cpdef mulInt(self, long val)

    @cython.locals(
        d=cython.long,
        m=cython.long,
        t0=cython.long,
        t1=cython.long,
        t2=cython.long,
        t3=cython.long,
        t4=cython.long,
        t5=cython.long,
        t6=cython.long,
        t7=cython.long,
        t8=cython.long,
        t9=cython.long,
        t10=cython.long,
        t11=cython.long,
        t12=cython.long,
        t13=cython.long,
        t14=cython.long,
        t15=cython.long,
        t16=cython.long,
        t17=cython.long,
        t18=cython.long,
        t19=cython.long,
    )
    cpdef mul2(self, FieldVal val, FieldVal val2)

    cpdef add2(self, FieldVal val, FieldVal val2)

    cpdef putBytes(self, char b[32])

    # inverse relies heavily on FieldVal methods, preventing optimization.
    # @cython.locals(
    #     a2=FieldVal,
    #     a3=FieldVal,
    #     a4=FieldVal,
    #     a10=FieldVal,
    #     a11=FieldVal,
    #     a21=FieldVal,
    #     a42=FieldVal,
    #     a45=FieldVal,
    #     a63=FieldVal,
    #     a1019=FieldVal,
    #     a1023=FieldVal,
    # )
    # cpdef inverse(self)
