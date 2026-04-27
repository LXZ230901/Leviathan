// Created by Yilu, 2023/11/13

#pragma once

#include "ie1.hpp"
#include "ie2.hpp"
#include "ie3.hpp"
#include "ie4.hpp"
#include "ie6.hpp"

namespace nas
{
    
// mutator helper functions
void mutate_sht(ESecurityHeaderType &sht);
int gen_sht();
int mutate_secmod();
uint32_t generate_bit(int len);
int generate_int(int range);
void mutate_octet_string(OctetString &stream);
void mutate_string(std::string &str);
void mutate_pdu(OctetString &pdu);

struct NasMessageMutator
{
    template <typename T>
    inline void mandatoryIE(T *ptr)
    {
        Mutate2346(*ptr);
    }

    template <typename T>
    inline void mandatoryIE1(T *ptr)
    {
        MutateIe1(0, *ptr);
    }

    template <typename T, typename U>
    inline void mandatoryIE1(T *ptr1, U *ptr2)
    {
        MutateIe1(*ptr1, *ptr2);
    }

    template <typename T>
    inline void optionalIE(int iei, std::optional<T> *ptr)
    {
        if (!ptr->has_value())
        {
            ptr->emplace(T());
            Mutate2346(ptr->value());
        }
        else
        {
            if (generate_int(4) == 0) // 1/4 chance delete an exist optional IE
            {
                ptr->reset();
            }
            else
            {
                Mutate2346(ptr->value());
            }
        }


    }

    template <typename T>
    inline void optionalIE1(int iei, std::optional<T> *ptr)
    {
        if (!ptr->has_value())
        {
            ptr->emplace(T());
            MutateIe1(iei, ptr->value());
        }
        else
        {
            if (generate_int(4) == 0) // 1/4 chance delete an exist optional IE
            {
                ptr->reset();
            }
            else
            {
                MutateIe1(iei, ptr->value());
            }
        }
    }

    // corruptValue primitives: overwrite IE with arbitrary raw bytes (CWE-20)
    template <typename T>
    inline void corruptValue(T *ptr, const OctetString &bytes)
    {
        Corrupt2346(*ptr, bytes);
    }

    template <typename T>
    inline void corruptValue1(T *ptr, const OctetString &bytes)
    {
        CorruptIe1(0, *ptr, bytes);
    }

    template <typename T, typename U>
    inline void corruptValue1(T *ptr1, U *ptr2, const OctetString &bytes)
    {
        CorruptIe1(*ptr1, *ptr2, bytes);
    }

    template <typename T>
    inline void corruptOptionalIE(int iei, std::optional<T> *ptr, const OctetString &bytes)
    {
        if (!ptr->has_value())
            ptr->emplace(T());
        Corrupt2346(ptr->value(), bytes);
    }

    template <typename T>
    inline void corruptOptionalIE1(int iei, std::optional<T> *ptr, const OctetString &bytes)
    {
        if (!ptr->has_value())
            ptr->emplace(T());
        CorruptIe1(iei, ptr->value(), bytes);
    }
};

}