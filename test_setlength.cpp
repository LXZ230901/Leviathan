//
// Minimal unit test for setIELength fakeLength mechanism in EncodeIe4/EncodeIe6
// Tests the core encoding templates directly without full NAS message infrastructure
// Build: cd /home/liuxz/5G/UERANSIM_CoreTesting &&
//        g++ -std=c++17 -Isrc test_setlength.cpp -o test_setlength && ./test_setlength
//
#include <iostream>
#include <cassert>
#include <utils/octet_string.hpp>
#include <utils/octet_view.hpp>
#include <lib/nas/base.hpp>

using namespace std;

static int passed = 0, failed = 0;

#define TEST(name) cout << "\n[TEST] " << (name) << endl;
#define CHECK(cond, msg) do { \
    if (cond) { cout << "  PASS: " << (msg) << endl; passed++; } \
    else { cout << "  FAIL: " << (msg) << endl; failed++; } \
} while(0)

// Minimal mock IE4 type (OctetString is move-only)
struct MockIE4 : public nas::InformationElement4
{
    OctetString payload{};

    MockIE4() = default;
    explicit MockIE4(OctetString &&p) : payload(std::move(p)) {}

    static void Encode(const MockIE4 &ie, OctetString &stream)
    {
        stream.append(ie.payload);
    }
};

// Minimal mock IE6 type (OctetString is move-only)
struct MockIE6 : public nas::InformationElement6
{
    OctetString payload{};

    MockIE6() = default;
    explicit MockIE6(OctetString &&p) : payload(std::move(p)) {}

    static void Encode(const MockIE6 &ie, OctetString &stream)
    {
        stream.append(ie.payload);
    }
};

// ============================================================================
// Test 1: IE4 uses actual length when fakeLength == -1 (default)
// ============================================================================
void test_ie4_default_length()
{
    TEST("IE4: uses actual length when fakeLength == -1 (default)");

    MockIE4 ie(OctetString::FromHex("AABBCCDD"));
    CHECK(ie.fakeLength == -1, "fakeLength defaults to -1");

    OctetString stream;
    nas::EncodeIe4(ie, stream);

    cout << "  Encoded hex: " << stream.toHexString() << endl;
    // IE4: 1 byte length + payload
    // Length byte should be 4 (AABBCCDD = 4 bytes)
    CHECK(stream.length() == 5, "total length = 1 (length byte) + 4 (payload) = 5");
    CHECK(stream.data()[0] == 4, "length byte = 4 (actual payload size)");

    // Verify payload bytes start at offset 1
    CHECK(stream.data()[1] == 0xAA && stream.data()[2] == 0xBB &&
          stream.data()[3] == 0xCC && stream.data()[4] == 0xDD,
          "payload bytes correctly preserved at offset 1");
}

// ============================================================================
// Test 2: IE4 uses fakeLength when set (fakeLen = 0)
// ============================================================================
void test_ie4_fake_length_zero()
{
    TEST("IE4: uses fakeLength = 0");

    MockIE4 ie(OctetString::FromHex("AABBCCDD"));
    ie.fakeLength = 0;  // claim zero-length payload

    OctetString stream;
    nas::EncodeIe4(ie, stream);

    cout << "  Encoded hex: " << stream.toHexString() << endl;
    CHECK(stream.length() == 5, "total length still 5 (length byte + payload still written)");
    CHECK(stream.data()[0] == 0, "length byte = 0 (fakeLen, CWE-119: length inconsistency)");
    CHECK(stream.data()[1] == 0xAA, "payload byte[0] = 0xAA still present");
}

// ============================================================================
// Test 3: IE4 uses fakeLength when set (fakeLen = 0xFF, max 1-byte)
// ============================================================================
void test_ie4_fake_length_max()
{
    TEST("IE4: uses fakeLength = 0xFF (max 1-byte value)");

    MockIE4 ie(OctetString::FromHex("AABB"));
    ie.fakeLength = 0xFF;

    OctetString stream;
    nas::EncodeIe4(ie, stream);

    cout << "  Encoded hex: " << stream.toHexString() << endl;
    CHECK(stream.data()[0] == 0xFF, "length byte = 0xFF (fakeLen)");
    CHECK(stream.length() == 3, "total length = 1 + 2 = 3 (payload unchanged)");
}

// ============================================================================
// Test 4: IE6 uses actual length when fakeLength == -1 (default)
// ============================================================================
void test_ie6_default_length()
{
    TEST("IE6: uses actual length when fakeLength == -1 (default)");

    MockIE6 ie(OctetString::FromHex("112233445566"));
    CHECK(ie.fakeLength == -1, "fakeLength defaults to -1");

    OctetString stream;
    nas::EncodeIe6(ie, stream);

    cout << "  Encoded hex: " << stream.toHexString() << endl;
    // IE6: 2 bytes length + payload
    CHECK(stream.length() == 8, "total length = 2 (length bytes) + 6 (payload) = 8");
    CHECK(stream.data()[0] == 0, "length byte[0] = 0x00");
    CHECK(stream.data()[1] == 6, "length byte[1] = 0x06 (actual payload size)");

    // Payload starts at offset 2
    CHECK(stream.data()[2] == 0x11 && stream.data()[3] == 0x22 &&
          stream.data()[4] == 0x33 && stream.data()[5] == 0x44 &&
          stream.data()[6] == 0x55 && stream.data()[7] == 0x66,
          "payload bytes correctly preserved at offset 2");
}

// ============================================================================
// Test 5: IE6 uses fakeLength when set (fakeLen = 0xFFFF, max 2-byte)
// ============================================================================
void test_ie6_fake_length_max()
{
    TEST("IE6: uses fakeLength = 0xFFFF (max 2-byte value)");

    MockIE6 ie(OctetString::FromHex("AABB"));
    ie.fakeLength = 0xFFFF;

    OctetString stream;
    nas::EncodeIe6(ie, stream);

    cout << "  Encoded hex: " << stream.toHexString() << endl;
    CHECK(stream.data()[0] == 0xFF, "length byte[0] = 0xFF");
    CHECK(stream.data()[1] == 0xFF, "length byte[1] = 0xFF");
    CHECK(stream.length() == 4, "total length = 2 + 2 = 4");
}

// ============================================================================
// Test 6: IE6 uses fakeLength when set (fakeLen = 0x0100)
// ============================================================================
void test_ie6_fake_length_256()
{
    TEST("IE6: uses fakeLength = 0x100 (256)");

    MockIE6 ie(OctetString::FromHex("AABBCC"));
    ie.fakeLength = 0x100;

    OctetString stream;
    nas::EncodeIe6(ie, stream);

    cout << "  Encoded hex: " << stream.toHexString() << endl;
    CHECK(stream.data()[0] == 0x01, "length byte[0] = 0x01");
    CHECK(stream.data()[1] == 0x00, "length byte[1] = 0x00");
}

// ============================================================================
// Test 7: fakeLength reset to -1 restores actual length
// ============================================================================
void test_fake_length_reset()
{
    TEST("fakeLength reset to -1 restores actual length");

    MockIE4 ie(OctetString::FromHex("AABBCCDDEEFF"));

    // First encode with fake length
    ie.fakeLength = 0x42;
    OctetString fakeStream;
    nas::EncodeIe4(ie, fakeStream);
    CHECK(fakeStream.data()[0] == 0x42, "fake length = 0x42");

    // Reset and encode with actual length
    ie.fakeLength = -1;
    OctetString realStream;
    nas::EncodeIe4(ie, realStream);
    CHECK(realStream.data()[0] == 6, "actual length = 6 after reset");
}

// ============================================================================
// Test 8: empty payload with fakeLength (buffer over-read scenario)
// ============================================================================
void test_ie4_empty_payload_fake_length()
{
    TEST("IE4: empty payload with fakeLength > 0 (CWE-119: buffer over-read)");

    MockIE4 ie(OctetString::FromHex(""));  // empty payload
    ie.fakeLength = 100;  // claim 100 bytes exist

    OctetString stream;
    nas::EncodeIe4(ie, stream);

    cout << "  Encoded hex: " << stream.toHexString() << endl;
    CHECK(stream.length() == 1, "only the length byte is written (payload empty)");
    CHECK(stream.data()[0] == 100, "length byte = 100 (fakeLen, inconsistent with actual data)");
}

// ============================================================================
// Test 9: Verify fakeLength is mutable (can be modified through const ref)
// ============================================================================
void test_fake_length_mutable()
{
    TEST("fakeLength is mutable, modifiable through const reference");

    MockIE4 ie(OctetString::FromHex("AA"));
    const MockIE4 &constRef = ie;
    constRef.fakeLength = 5;  // should compile and work due to 'mutable'

    CHECK(ie.fakeLength == 5, "fakeLength modifiable through const reference (mutable keyword)");

    OctetString stream;
    nas::EncodeIe4(constRef, stream);  // EncodeIe4 takes const T&
    CHECK(stream.data()[0] == 5, "EncodeIe4 reads fakeLength from const ref correctly");
}

// ============================================================================
// Test 10: IE4 and IE6 length field size difference
// ============================================================================
void test_ie4_vs_ie6_field_size()
{
    TEST("IE4 has 1-byte length, IE6 has 2-byte length");

    MockIE4 ie4(OctetString::FromHex("AABB"));
    MockIE6 ie6(OctetString::FromHex("AABB"));

    ie4.fakeLength = 0xFF;
    ie6.fakeLength = 0xFFFF;

    OctetString s4, s6;
    nas::EncodeIe4(ie4, s4);
    nas::EncodeIe6(ie6, s6);

    cout << "  IE4 hex: " << s4.toHexString() << endl;
    cout << "  IE6 hex: " << s6.toHexString() << endl;

    CHECK(s4.length() == 3, "IE4: 1 len byte + 2 payload = 3");
    CHECK(s6.length() == 4, "IE6: 2 len bytes + 2 payload = 4");
    CHECK(s4.data()[0] == 0xFF, "IE4 len byte = 0xFF");
    CHECK(s6.data()[0] == 0xFF, "IE6 len byte[0] = 0xFF");
    CHECK(s6.data()[1] == 0xFF, "IE6 len byte[1] = 0xFF");
}

int main()
{
    cout << "========================================" << endl;
    cout << " setIELength Core Mechanism Test" << endl;
    cout << " (Tests EncodeIe4/EncodeIe6 fakeLength)" << endl;
    cout << "========================================" << endl;

    test_ie4_default_length();
    test_ie4_fake_length_zero();
    test_ie4_fake_length_max();
    test_ie6_default_length();
    test_ie6_fake_length_max();
    test_ie6_fake_length_256();
    test_fake_length_reset();
    test_ie4_empty_payload_fake_length();
    test_fake_length_mutable();
    test_ie4_vs_ie6_field_size();

    cout << "\n========================================" << endl;
    cout << " Results: " << passed << " passed, " << failed << " failed" << endl;
    cout << "========================================" << endl;

    return failed > 0 ? 1 : 0;
}
