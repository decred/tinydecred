"""
Copyright (c) 2020, The Decred developers
See LICENSE for details

Definitions allowing Cython to generate optimized C code that builds a
dynamic library speeding up the field.py code.
"""

import cython


cdef unsigned long twoBitsMask = 0x03
cdef unsigned long fourBitsMask = 0x0F
cdef unsigned long sixBitsMask = 0x3F
cdef unsigned long eightBitsMask = 0xFF
cdef unsigned long fieldWords = 10
cdef unsigned long fieldBase = 26
cdef unsigned long fieldBaseMask = (1 << fieldBase) - 1
cdef unsigned long fieldMSBBits = 256 - (fieldBase * (fieldWords - 1))
cdef unsigned long fieldMSBMask = (1 << fieldMSBBits) - 1
cdef unsigned long fieldPrimeWordZero = 0x3FFFC2F
cdef unsigned long fieldPrimeWordOne = 0x3FFFFBF
cdef unsigned long primePartBy16 = 68719492368


cdef class FieldVal:
    cdef public unsigned long n[10]

    @cython.locals(
        m=cython.ulong,
        t0=cython.ulong,
        t1=cython.ulong,
        t2=cython.ulong,
        t3=cython.ulong,
        t4=cython.ulong,
        t5=cython.ulong,
        t6=cython.ulong,
        t7=cython.ulong,
        t8=cython.ulong,
        t9=cython.ulong,
    )
    cpdef normalize(self)

    cpdef negateVal(self, FieldVal val, unsigned long magnitude)

    cpdef add(self, FieldVal val)

    @cython.locals(
        m=cython.ulong,
        n=cython.ulong,
        t0=cython.ulong,
        t1=cython.ulong,
        t2=cython.ulong,
        t3=cython.ulong,
        t4=cython.ulong,
        t5=cython.ulong,
        t6=cython.ulong,
        t7=cython.ulong,
        t8=cython.ulong,
        t9=cython.ulong,
        t10=cython.ulong,
        t11=cython.ulong,
        t12=cython.ulong,
        t13=cython.ulong,
        t14=cython.ulong,
        t15=cython.ulong,
        t16=cython.ulong,
        t17=cython.ulong,
        t18=cython.ulong,
        t19=cython.ulong,
    )
    cpdef squareVal(self, FieldVal val)

    cpdef mulInt(self, long val)

    @cython.locals(
        d=cython.ulong,
        m=cython.ulong,
        t0=cython.ulong,
        t1=cython.ulong,
        t2=cython.ulong,
        t3=cython.ulong,
        t4=cython.ulong,
        t5=cython.ulong,
        t6=cython.ulong,
        t7=cython.ulong,
        t8=cython.ulong,
        t9=cython.ulong,
        t10=cython.ulong,
        t11=cython.ulong,
        t12=cython.ulong,
        t13=cython.ulong,
        t14=cython.ulong,
        t15=cython.ulong,
        t16=cython.ulong,
        t17=cython.ulong,
        t18=cython.ulong,
        t19=cython.ulong,
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
