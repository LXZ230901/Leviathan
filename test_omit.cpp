//
// Standalone test for omitIE primitive
// Build: cd /home/liuxz/5G/UERANSIM_CoreTesting &&
//        g++ -std=c++17 -Isrc test_omit.cpp test_stubs.cpp src/lib/nas/*.cpp src/utils/*.cpp src/ext/*.cpp -o test_omit
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

// ============================================================================
// Test 1: omit mandatory IE1 (single 4-bit) from SecurityModeReject
// ============================================================================
void test_omit_mandatory_ie1_single()
{
    TEST("omit mandatory IE1 (single 4-bit): SecurityModeReject IE0 (mmCause)");

    SecurityModeReject msg;
    msg.epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    msg.sht = ESecurityHeaderType::NOT_PROTECTED;
    msg.messageType = EMessageType::SECURITY_MODE_REJECT;
    msg.mmCause.value = EMmCause::UNSPECIFIED_PROTOCOL_ERROR;

    OctetString origStream;
    EncodeNasMessage(msg, origStream);
    cout << "  Original hex: " << origStream.toHexString() << endl;
    cout << "  Original length: " << origStream.length() << endl;

    // Omit IE0 (mandatory mmCause)
    NasMessageMutator mutator;
    msg.onOmit(mutator, 0);

    CHECK(msg.omitMandatory.count(0) == 1, "omitMandatory set contains index 0");

    OctetString omitStream;
    EncodeNasMessage(msg, omitStream);
    cout << "  After omit hex: " << omitStream.toHexString() << endl;
    cout << "  After omit length: " << omitStream.length() << endl;

    CHECK(omitStream.length() < origStream.length(),
          "encoded message is shorter after omitting mandatory IE");
}

// ============================================================================
// Test 2: omit compound mandatory IE1 from RegistrationRequest
// ============================================================================
void test_omit_mandatory_ie1_compound()
{
    TEST("omit compound mandatory IE1: RegistrationRequest IE0 (ngKSI + registrationType)");

    RegistrationRequest msg;
    msg.epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    msg.sht = ESecurityHeaderType::NOT_PROTECTED;
    msg.messageType = EMessageType::REGISTRATION_REQUEST;
    msg.nasKeySetIdentifier.ksi = IENasKeySetIdentifier::NOT_AVAILABLE_OR_RESERVED;
    msg.nasKeySetIdentifier.tsc = ETypeOfSecurityContext::NATIVE_SECURITY_CONTEXT;
    msg.registrationType.followOnRequestPending = EFollowOnRequest::NO_FOR_PENDING;
    msg.registrationType.registrationType = ERegistrationType::INITIAL_REGISTRATION;
    msg.mobileIdentity.type = EIdentityType::SUCI;
    msg.mobileIdentity.supiFormat = ESupiFormat::IMSI;
    msg.mobileIdentity.value = "0010203040506070809010";

    OctetString origStream;
    EncodeNasMessage(msg, origStream);
    cout << "  Original hex: " << origStream.toHexString() << endl;
    cout << "  Original length: " << origStream.length() << endl;

    // Omit IE0 (compound IE1: nasKeySetIdentifier + registrationType)
    NasMessageMutator mutator;
    msg.onOmit(mutator, 0);

    CHECK(msg.omitMandatory.count(0) == 1, "omitMandatory set contains index 0");
    CHECK(msg.omitMandatory.count(1) == 0, "omitMandatory does NOT contain index 1 (mobileIdentity still encoded)");

    OctetString omitStream;
    EncodeNasMessage(msg, omitStream);
    cout << "  After omit hex: " << omitStream.toHexString() << endl;
    cout << "  After omit length: " << omitStream.length() << endl;

    CHECK(omitStream.length() < origStream.length(),
          "encoded message is shorter after omitting compound IE1");
}

// ============================================================================
// Test 3: omit mandatory IE (variable length) from RegistrationRequest
// ============================================================================
void test_omit_mandatory_ie_variable()
{
    TEST("omit mandatory IE (variable): RegistrationRequest IE1 (mobileIdentity)");

    RegistrationRequest msg;
    msg.epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    msg.sht = ESecurityHeaderType::NOT_PROTECTED;
    msg.messageType = EMessageType::REGISTRATION_REQUEST;
    msg.nasKeySetIdentifier.ksi = IENasKeySetIdentifier::NOT_AVAILABLE_OR_RESERVED;
    msg.nasKeySetIdentifier.tsc = ETypeOfSecurityContext::NATIVE_SECURITY_CONTEXT;
    msg.registrationType.followOnRequestPending = EFollowOnRequest::NO_FOR_PENDING;
    msg.registrationType.registrationType = ERegistrationType::INITIAL_REGISTRATION;
    msg.mobileIdentity.type = EIdentityType::SUCI;
    msg.mobileIdentity.supiFormat = ESupiFormat::IMSI;
    msg.mobileIdentity.value = "0010203040506070809010";

    OctetString origStream;
    EncodeNasMessage(msg, origStream);
    cout << "  Original hex: " << origStream.toHexString() << endl;

    // Omit IE1 (mandatory mobileIdentity)
    NasMessageMutator mutator;
    msg.onOmit(mutator, 1);

    CHECK(msg.omitMandatory.count(1) == 1, "omitMandatory set contains index 1");

    OctetString omitStream;
    EncodeNasMessage(msg, omitStream);
    cout << "  After omit hex: " << omitStream.toHexString() << endl;

    CHECK(omitStream.length() < origStream.length(),
          "encoded message is shorter after omitting mobileIdentity");
}

// ============================================================================
// Test 4: omit optional IE from RegistrationRequest
// ============================================================================
void test_omit_optional_ie()
{
    TEST("omit optional IE: RegistrationRequest IE7 (requestedNSSAI)");

    RegistrationRequest msg;
    msg.epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    msg.sht = ESecurityHeaderType::NOT_PROTECTED;
    msg.messageType = EMessageType::REGISTRATION_REQUEST;
    msg.nasKeySetIdentifier.ksi = IENasKeySetIdentifier::NOT_AVAILABLE_OR_RESERVED;
    msg.nasKeySetIdentifier.tsc = ETypeOfSecurityContext::NATIVE_SECURITY_CONTEXT;
    msg.registrationType.followOnRequestPending = EFollowOnRequest::NO_FOR_PENDING;
    msg.registrationType.registrationType = ERegistrationType::INITIAL_REGISTRATION;
    msg.mobileIdentity.type = EIdentityType::SUCI;
    msg.mobileIdentity.supiFormat = ESupiFormat::IMSI;
    msg.mobileIdentity.value = "0010203040506070809010";

    // First emplace the optional IE so it's present
    msg.requestedNSSAI.emplace();
    msg.requestedNSSAI->sNssais.push_back(IESNssai{});
    msg.requestedNSSAI->sNssais[0].sst = 1;

    OctetString origStream;
    EncodeNasMessage(msg, origStream);
    cout << "  Original hex: " << origStream.toHexString() << endl;
    cout << "  Original length: " << origStream.length() << endl;

    // Verify optional IE is present
    CHECK(msg.requestedNSSAI.has_value(), "requestedNSSAI has value before omit");

    // Omit IE7 (optional requestedNSSAI)
    NasMessageMutator mutator;
    msg.onOmit(mutator, 7);

    CHECK(!msg.requestedNSSAI.has_value(), "requestedNSSAI reset after omitOptionalIE");

    OctetString omitStream;
    EncodeNasMessage(msg, omitStream);
    cout << "  After omit hex: " << omitStream.toHexString() << endl;
    cout << "  After omit length: " << omitStream.length() << endl;

    CHECK(omitStream.length() < origStream.length(),
          "encoded message is shorter after omitting optional IE");
}

// ============================================================================
// Test 5: omit optional IE1 from RegistrationRequest
// ============================================================================
void test_omit_optional_ie1()
{
    TEST("omit optional IE1: RegistrationRequest IE2 (nonCurrentNgKsi)");

    RegistrationRequest msg;
    msg.epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    msg.sht = ESecurityHeaderType::NOT_PROTECTED;
    msg.messageType = EMessageType::REGISTRATION_REQUEST;
    msg.nasKeySetIdentifier.ksi = IENasKeySetIdentifier::NOT_AVAILABLE_OR_RESERVED;
    msg.nasKeySetIdentifier.tsc = ETypeOfSecurityContext::NATIVE_SECURITY_CONTEXT;
    msg.registrationType.followOnRequestPending = EFollowOnRequest::NO_FOR_PENDING;
    msg.registrationType.registrationType = ERegistrationType::INITIAL_REGISTRATION;
    msg.mobileIdentity.type = EIdentityType::SUCI;
    msg.mobileIdentity.supiFormat = ESupiFormat::IMSI;
    msg.mobileIdentity.value = "0010203040506070809010";

    // Emplace optional IE1
    msg.nonCurrentNgKsi.emplace();
    msg.nonCurrentNgKsi->tsc = ETypeOfSecurityContext::NATIVE_SECURITY_CONTEXT;
    msg.nonCurrentNgKsi->ksi = 3;

    OctetString origStream;
    EncodeNasMessage(msg, origStream);
    cout << "  Original hex: " << origStream.toHexString() << endl;

    CHECK(msg.nonCurrentNgKsi.has_value(), "nonCurrentNgKsi has value before omit");

    // Omit IE2 (optional nonCurrentNgKsi)
    NasMessageMutator mutator;
    msg.onOmit(mutator, 2);

    CHECK(!msg.nonCurrentNgKsi.has_value(), "nonCurrentNgKsi reset after omitOptionalIE1");

    OctetString omitStream;
    EncodeNasMessage(msg, omitStream);
    cout << "  After omit hex: " << omitStream.toHexString() << endl;

    CHECK(omitStream.length() < origStream.length(),
          "encoded message is shorter after omitting optional IE1");
}

// ============================================================================
// Test 6: omit all mandatory IEs from SecurityModeCommand
// ============================================================================
void test_omit_all_mandatory()
{
    TEST("omit all mandatory IEs: SecurityModeCommand IE0,1,2");

    SecurityModeCommand msg;
    msg.epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    msg.sht = ESecurityHeaderType::NOT_PROTECTED;
    msg.messageType = EMessageType::SECURITY_MODE_COMMAND;
    msg.selectedNasSecurityAlgorithms.integrity = ETypeOfIntegrityProtectionAlgorithm::IA0;
    msg.selectedNasSecurityAlgorithms.ciphering = ETypeOfCipheringAlgorithm::EA0;
    msg.ngKsi.tsc = ETypeOfSecurityContext::NATIVE_SECURITY_CONTEXT;
    msg.ngKsi.ksi = 0;
    msg.replayedUeSecurityCapabilities.b_5G_EA0 = 1;
    msg.replayedUeSecurityCapabilities.b_5G_IA0 = 1;

    OctetString origStream;
    EncodeNasMessage(msg, origStream);
    cout << "  Original hex: " << origStream.toHexString() << endl;
    cout << "  Original length: " << origStream.length() << endl;

    // Omit all 3 mandatory IEs
    NasMessageMutator mutator;
    msg.onOmit(mutator, 0);
    msg.onOmit(mutator, 1);
    msg.onOmit(mutator, 2);

    CHECK(msg.omitMandatory.size() == 3, "all 3 mandatory IEs marked for omission");

    OctetString omitStream;
    EncodeNasMessage(msg, omitStream);
    cout << "  After omit hex: " << omitStream.toHexString() << endl;
    cout << "  After omit length: " << omitStream.length() << endl;

    // After omitting all mandatory IEs, only the header (epd + sht + msgType) remains
    // plus any optional IEs (but none were emplaced)
    // Header = 3 octets
    CHECK(omitStream.length() == 3,
          "only 3-byte header remains after omitting all mandatory IEs (no optionals emplaced)");
}

// ============================================================================
// Test 7: omit from message with only optionals (AuthenticationResponse)
// ============================================================================
void test_omit_optional_only_message()
{
    TEST("omit optional IE from all-optional message: AuthenticationResponse IE0");

    AuthenticationResponse msg;
    msg.epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    msg.sht = ESecurityHeaderType::NOT_PROTECTED;
    msg.messageType = EMessageType::AUTHENTICATION_RESPONSE;
    msg.authenticationResponseParameter = IEAuthenticationResponseParameter{};
    msg.authenticationResponseParameter->rawData = OctetString::FromHex("AABBCCDD");

    OctetString origStream;
    EncodeNasMessage(msg, origStream);
    cout << "  Original hex: " << origStream.toHexString() << endl;

    CHECK(msg.authenticationResponseParameter.has_value(), "authResponseParam has value before omit");

    // Omit IE0 (optional authenticationResponseParameter)
    NasMessageMutator mutator;
    msg.onOmit(mutator, 0);

    CHECK(!msg.authenticationResponseParameter.has_value(), "authResponseParam reset after omit");

    OctetString omitStream;
    EncodeNasMessage(msg, omitStream);
    cout << "  After omit hex: " << omitStream.toHexString() << endl;

    CHECK(omitStream.length() < origStream.length(),
          "encoded message is shorter after omitting optional IE");
}

// ============================================================================
// Test 8: omitMandatory set is empty by default
// ============================================================================
void test_omit_default_state()
{
    TEST("default state: omitMandatory is empty, encoding unchanged");

    RegistrationRequest msg;
    msg.epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    msg.sht = ESecurityHeaderType::NOT_PROTECTED;
    msg.messageType = EMessageType::REGISTRATION_REQUEST;
    msg.nasKeySetIdentifier.ksi = IENasKeySetIdentifier::NOT_AVAILABLE_OR_RESERVED;
    msg.nasKeySetIdentifier.tsc = ETypeOfSecurityContext::NATIVE_SECURITY_CONTEXT;
    msg.registrationType.followOnRequestPending = EFollowOnRequest::NO_FOR_PENDING;
    msg.registrationType.registrationType = ERegistrationType::INITIAL_REGISTRATION;
    msg.mobileIdentity.type = EIdentityType::SUCI;
    msg.mobileIdentity.supiFormat = ESupiFormat::IMSI;
    msg.mobileIdentity.value = "0010203040506070809010";

    CHECK(msg.omitMandatory.empty(), "omitMandatory is empty by default");

    OctetString stream1, stream2;
    EncodeNasMessage(msg, stream1);
    EncodeNasMessage(msg, stream2);

    CHECK(stream1.toHexString() == stream2.toHexString(),
          "repeated encoding produces identical output when no IEs omitted");
}

// ============================================================================
// Test 9: omit a non-existent IE index (should be no-op)
// ============================================================================
void test_omit_invalid_index()
{
    TEST("omit invalid IE index: RegistrationRequest IE99 (no-op)");

    RegistrationRequest msg;
    msg.epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    msg.sht = ESecurityHeaderType::NOT_PROTECTED;
    msg.messageType = EMessageType::REGISTRATION_REQUEST;
    msg.nasKeySetIdentifier.ksi = IENasKeySetIdentifier::NOT_AVAILABLE_OR_RESERVED;
    msg.nasKeySetIdentifier.tsc = ETypeOfSecurityContext::NATIVE_SECURITY_CONTEXT;
    msg.registrationType.followOnRequestPending = EFollowOnRequest::NO_FOR_PENDING;
    msg.registrationType.registrationType = ERegistrationType::INITIAL_REGISTRATION;
    msg.mobileIdentity.type = EIdentityType::SUCI;
    msg.mobileIdentity.supiFormat = ESupiFormat::IMSI;
    msg.mobileIdentity.value = "0010203040506070809010";

    OctetString origStream;
    EncodeNasMessage(msg, origStream);
    cout << "  Original hex: " << origStream.toHexString() << endl;

    // Omit non-existent IE index
    NasMessageMutator mutator;
    msg.onOmit(mutator, 99);

    CHECK(msg.omitMandatory.empty(), "omitMandatory still empty (invalid index ignored)");

    OctetString afterStream;
    EncodeNasMessage(msg, afterStream);

    CHECK(origStream.toHexString() == afterStream.toHexString(),
          "encoding unchanged after omitting invalid IE index");
}

// ============================================================================
// Test 10: omit mandatory IE from FiveGMmStatus (single IE3 enum)
// ============================================================================
void test_omit_mandatory_ie3()
{
    TEST("omit mandatory IE3 enum: FiveGMmStatus IE0 (mmCause)");

    FiveGMmStatus msg;
    msg.epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    msg.sht = ESecurityHeaderType::NOT_PROTECTED;
    msg.messageType = EMessageType::FIVEG_MM_STATUS;
    msg.mmCause.value = EMmCause::UNSPECIFIED_PROTOCOL_ERROR;

    OctetString origStream;
    EncodeNasMessage(msg, origStream);
    cout << "  Original hex: " << origStream.toHexString() << endl;
    cout << "  Original length: " << origStream.length() << endl;

    NasMessageMutator mutator;
    msg.onOmit(mutator, 0);

    CHECK(msg.omitMandatory.count(0) == 1, "omitMandatory set contains index 0");

    OctetString omitStream;
    EncodeNasMessage(msg, omitStream);
    cout << "  After omit hex: " << omitStream.toHexString() << endl;
    cout << "  After omit length: " << omitStream.length() << endl;

    // After omitting the only mandatory IE, only header remains (epd + sht + msgType = 3 bytes)
    CHECK(omitStream.length() == 3,
          "only 3-byte header remains after omitting sole mandatory IE");
}

int main()
{
    cout << "========================================" << endl;
    cout << " omitIE Primitive Verification Test" << endl;
    cout << "========================================" << endl;

    test_omit_mandatory_ie1_single();
    test_omit_mandatory_ie1_compound();
    test_omit_mandatory_ie_variable();
    test_omit_optional_ie();
    test_omit_optional_ie1();
    test_omit_all_mandatory();
    test_omit_optional_only_message();
    test_omit_default_state();
    test_omit_invalid_index();
    test_omit_mandatory_ie3();

    cout << "\n========================================" << endl;
    cout << " Results: " << passed << " passed, " << failed << " failed" << endl;
    cout << "========================================" << endl;

    return failed > 0 ? 1 : 0;
}
