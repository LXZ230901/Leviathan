//
// Standalone test for corruptValue primitive
// Build: cd /home/liuxz/5G/UERANSIM_CoreTesting &&
//        g++ -std=c++17 -Isrc -I/usr/include test_corrupt.cpp src/lib/nas/*.cpp src/utils/*.cpp src/ext/*.cpp -o test_corrupt
//
#include <iostream>
#include <cassert>
#include <lib/nas/msg.hpp>
#include <lib/nas/encode.hpp>
#include <lib/nas/nas_mutator.hpp>

using namespace nas;
using namespace std;

static int passed = 0, failed = 0;

#define TEST(name) cout << "\n[TEST] " << (name) << endl;
#define CHECK(cond, msg) do { \
    if (cond) { cout << "  PASS: " << (msg) << endl; passed++; } \
    else { cout << "  FAIL: " << (msg) << endl; failed++; } \
} while(0)

void test_registration_request_ie0()
{
    TEST("RegistrationRequest IE0: corruptValue1 on nasKeySetIdentifier + registrationType");

    // Create a valid RegistrationRequest
    RegistrationRequest msg;
    msg.epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    msg.sht = ESecurityHeaderType::NOT_PROTECTED;
    msg.messageType = EMessageType::REGISTRATION_REQUEST;
    msg.nasKeySetIdentifier.ksi = nas::IENasKeySetIdentifier::NOT_AVAILABLE_OR_RESERVED;
    msg.nasKeySetIdentifier.tsc = nas::ETypeOfSecurityContext::NATIVE_SECURITY_CONTEXT;
    msg.registrationType.followOnRequestPending = nas::EFollowOnRequest::NO_FOR_PENDING;
    msg.registrationType.registrationType = nas::ERegistrationType::INITIAL_REGISTRATION;

    // Encode original
    OctetString origStream;
    EncodeNasMessage(msg, origStream);
    cout << "  Original hex: " << origStream.toHexString() << endl;

    // Apply corruptValue1 to IE0: nasKeySetIdentifier + registrationType
    // The IE1 composite takes first 4-bit as TSC, second 4-bit as NAS KSI,
    // third 4-bit as registration type bits
    // We'll set: TSC=0, NAS_KSI=7, FOR=1, REG_TYPE=mobility_updating(2)
    // byte=0x07, then reg= (0x07 >> 1) & 0x7 = 0x3 -> meaning it's split differently
    // Actually let's just inject 0x00 to force all zeros
    NasMessageMutator mutator;
    OctetString corruptBytes = OctetString::FromHex("00");
    msg.onCorrupt(mutator, 0, corruptBytes);

    OctetString corruptStream;
    EncodeNasMessage(msg, corruptStream);
    cout << "  Corrupt hex: " << corruptStream.toHexString() << endl;

    CHECK(origStream.toHexString() != corruptStream.toHexString(),
          "IE0 corrupted: hex changed after corruptValue1");
}

void test_registration_request_ie1_mobile_identity()
{
    TEST("RegistrationRequest IE1: corruptValue on mobileIdentity (IE6)");

    RegistrationRequest msg;
    msg.epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    msg.sht = ESecurityHeaderType::NOT_PROTECTED;
    msg.messageType = EMessageType::REGISTRATION_REQUEST;

    // Set a known SUCI identity
    msg.mobileIdentity.type = EIdentityType::SUCI;
    msg.mobileIdentity.supiFormat = ESupiFormat::IMSI;
    msg.mobileIdentity.value = "0010203040506070809010";

    OctetString origStream;
    EncodeNasMessage(msg, origStream);

    // Apply corruptValue to IE1 with specific bytes
    NasMessageMutator mutator;
    // Overwrite mobileIdentity with 0xFF bytes (invalid type + garbage data)
    OctetString corruptBytes = OctetString::FromHex("FFAABB");
    msg.onCorrupt(mutator, 1, corruptBytes);

    OctetString corruptStream;
    EncodeNasMessage(msg, corruptStream);

    cout << "  Original hex: " << origStream.toHexString() << endl;
    cout << "  Corrupt hex: " << corruptStream.toHexString() << endl;

    CHECK(origStream.toHexString() != corruptStream.toHexString(),
          "IE1 corrupted: hex changed after corruptValue");
    CHECK(msg.mobileIdentity.type == (EIdentityType)(0xFF & 0x7),
          "mobileIdentity.type set to 0x7 (=0xFF & 0x7) as expected");
}

void test_authentication_response()
{
    TEST("AuthenticationResponse IE0: corruptValue on authenticationResponseParameter (IE4)");

    AuthenticationResponse msg;
    msg.epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    msg.sht = ESecurityHeaderType::NOT_PROTECTED;
    msg.messageType = EMessageType::AUTHENTICATION_RESPONSE;
    msg.authenticationResponseParameter = IEAuthenticationResponseParameter{};
    msg.authenticationResponseParameter->rawData = OctetString::FromHex("AABBCCDD");

    OctetString origStream;
    EncodeNasMessage(msg, origStream);
    cout << "  Original hex: " << origStream.toHexString() << endl;

    // Corrupt with specific raw bytes
    NasMessageMutator mutator;
    OctetString corruptBytes = OctetString::FromHex("DEADBEEF");
    msg.onCorrupt(mutator, 0, corruptBytes);

    cout << "  rawData after corrupt: " << msg.authenticationResponseParameter->rawData.toHexString() << endl;
    CHECK(msg.authenticationResponseParameter->rawData.toHexString() == "DEADBEEF",
          "authenticationResponseParameter.rawData overwritten with DEADBEEF");

    OctetString corruptStream;
    EncodeNasMessage(msg, corruptStream);
    cout << "  Corrupt hex: " << corruptStream.toHexString() << endl;
}

void test_five_gmm_status()
{
    TEST("FiveGMmStatus IE0: corruptValue on mmCause (IE3, single enum)");

    FiveGMmStatus msg;
    msg.epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    msg.sht = ESecurityHeaderType::NOT_PROTECTED;
    msg.messageType = EMessageType::FIVEG_MM_STATUS;
    msg.mmCause.value = EMmCause::UNSPECIFIED_PROTOCOL_ERROR;  // 111

    // Corrupt with illegal value 0xFF (> max defined enum)
    NasMessageMutator mutator;
    OctetString corruptBytes = OctetString::FromHex("FF");
    msg.onCorrupt(mutator, 0, corruptBytes);

    cout << "  mmCause.value after corrupt: " << (int)msg.mmCause.value << endl;
    CHECK((int)msg.mmCause.value == 0xFF,
          "mmCause set to 0xFF (illegal enum, CWE-20 test)");

    OctetString corruptStream;
    EncodeNasMessage(msg, corruptStream);
    cout << "  Corrupt hex: " << corruptStream.toHexString() << endl;
}

void test_security_mode_complete()
{
    TEST("SecurityModeComplete IE0: corruptValue1 on imeiSv (IE1)");

    SecurityModeComplete msg;
    msg.epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    msg.sht = ESecurityHeaderType::NOT_PROTECTED;
    msg.messageType = EMessageType::SECURITY_MODE_COMPLETE;

    OctetString origStream;
    EncodeNasMessage(msg, origStream);
    cout << "  Original hex: " << origStream.toHexString() << endl;

    // Corrupt with specific IE1 value
    NasMessageMutator mutator;
    OctetString corruptBytes = OctetString::FromHex("0A"); // val=0xA for imeiSv
    msg.onCorrupt(mutator, 0, corruptBytes);

    OctetString corruptStream;
    EncodeNasMessage(msg, corruptStream);
    cout << "  Corrupt hex: " << corruptStream.toHexString() << endl;
}

void test_optional_ie_corrupt()
{
    TEST("RegistrationRequest IE2: corruptOptionalIE1 on nonCurrentNgKsi");

    RegistrationRequest msg;
    msg.epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    msg.sht = ESecurityHeaderType::NOT_PROTECTED;
    msg.messageType = EMessageType::REGISTRATION_REQUEST;

    // Before corrupt: optional IE should be empty
    CHECK(!msg.nonCurrentNgKsi.has_value(), "nonCurrentNgKsi is empty before corrupt");

    // Corrupt with optionalIE1 - should auto-emplace
    NasMessageMutator mutator;
    OctetString corruptBytes = OctetString::FromHex("07"); // val=7: TSC=0, NAS_KSI=7
    msg.onCorrupt(mutator, 2, corruptBytes);

    CHECK(msg.nonCurrentNgKsi.has_value(), "nonCurrentNgKsi emplaced after corruptOptionalIE1");

    OctetString corruptStream;
    EncodeNasMessage(msg, corruptStream);
    cout << "  Corrupt hex (with optional IE): " << corruptStream.toHexString() << endl;
}

void test_identity_response()
{
    TEST("IdentityResponse IE0: corruptValue on mobileIdentity");

    IdentityResponse msg;
    msg.epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    msg.sht = ESecurityHeaderType::NOT_PROTECTED;
    msg.messageType = EMessageType::IDENTITY_RESPONSE;
    msg.mobileIdentity.type = EIdentityType::SUCI;
    msg.mobileIdentity.supiFormat = ESupiFormat::IMSI;
    msg.mobileIdentity.value = "0010203040506070809010";

    OctetString origStream;
    EncodeNasMessage(msg, origStream);
    cout << "  Original hex: " << origStream.toHexString() << endl;

    // Corrupt with type confusion - set IMEI instead of SUCI
    NasMessageMutator mutator;
    OctetString corruptBytes = OctetString::FromHex("03010203040506"); // type=0x03 (IMEI)
    msg.onCorrupt(mutator, 0, corruptBytes);

    cout << "  mobileIdentity.type after corrupt: " << (int)msg.mobileIdentity.type << endl;
    CHECK(msg.mobileIdentity.type == (EIdentityType)0x3 || msg.mobileIdentity.type == EIdentityType::IMEI,
          "mobileIdentity type changed (type confusion test)");

    OctetString corruptStream;
    EncodeNasMessage(msg, corruptStream);
    cout << "  Corrupt hex: " << corruptStream.toHexString() << endl;
}

int main()
{
    cout << "========================================" << endl;
    cout << " CorruptValue Primitive Verification Test" << endl;
    cout << "========================================" << endl;

    test_registration_request_ie0();
    test_registration_request_ie1_mobile_identity();
    test_authentication_response();
    test_five_gmm_status();
    test_security_mode_complete();
    test_optional_ie_corrupt();
    test_identity_response();

    cout << "\n========================================" << endl;
    cout << " Results: " << passed << " passed, " << failed << " failed" << endl;
    cout << "========================================" << endl;

    return failed > 0 ? 1 : 0;
}
