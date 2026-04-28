//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "msg.hpp"

// fuzzing
#include "nas_mutator.hpp"

namespace nas
{

AuthenticationFailure::AuthenticationFailure()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::AUTHENTICATION_FAILURE;
}

void AuthenticationFailure::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE(&mmCause);
    b.optionalIE(0x30, &authenticationFailureParameter);
}

// fuzzing
void AuthenticationFailure::onMutate(NasMessageMutator &m)
{
    int i = generate_int(3);
    switch (i)
    {
    case 0:
        m.mandatoryIE(&mmCause);
        break;
    case 1:
        m.optionalIE(0x30, &authenticationFailureParameter);
        break;
    default:
        break;
    }
}

void AuthenticationFailure::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue(&mmCause, bytes);
        break;
    case 1:
        m.corruptOptionalIE(0x30, &authenticationFailureParameter, bytes);
        break;
    default:
        break;
    }
}

void AuthenticationFailure::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        m.omitOptionalIE(&authenticationFailureParameter);
        break;
    default:
        break;
    }
}

void AuthenticationFailure::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        m.setIELengthOptional(&authenticationFailureParameter, fakeLen);
        break;
    default:
        break;
    }
}


AuthenticationReject::AuthenticationReject()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::AUTHENTICATION_REJECT;
}

void AuthenticationReject::onBuild(NasMessageBuilder &b)
{
    b.optionalIE(0x78, &eapMessage);
}

void AuthenticationReject::onMutate(NasMessageMutator &m)
{
    if (generate_bit(1))
        m.optionalIE(0x78, &eapMessage);
}

void AuthenticationReject::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptOptionalIE(0x78, &eapMessage, bytes);
        break;
    default:
        break;
    }
}

void AuthenticationReject::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        m.omitOptionalIE(&eapMessage);
        break;
    default:
        break;
    }
}

void AuthenticationReject::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        m.setIELengthOptional(&eapMessage, fakeLen);
        break;
    default:
        break;
    }
}


AuthenticationRequest::AuthenticationRequest()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::AUTHENTICATION_REQUEST;
}

void AuthenticationRequest::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE1(&ngKSI);
    b.mandatoryIE(&abba);
    b.optionalIE(0x21, &authParamRAND);
    b.optionalIE(0x20, &authParamAUTN);
    b.optionalIE(0x78, &eapMessage);
}

void AuthenticationRequest::onMutate(NasMessageMutator &m)
{
    int i = generate_int(6);
    switch (i)
    {
    case 0:
        m.mandatoryIE1(&ngKSI);
        break;
    case 1:
        m.mandatoryIE(&abba);
        break;
    case 2:
        m.optionalIE(0x21, &authParamRAND);
        break;
    case 3:
        m.optionalIE(0x20, &authParamAUTN);
        break;
    case 4:
        m.optionalIE(0x78, &eapMessage);
        break;
    default:
        break;
    }
}

void AuthenticationRequest::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue1(&ngKSI, bytes);
        break;
    case 1:
        m.corruptValue(&abba, bytes);
        break;
    case 2:
        m.corruptOptionalIE(0x21, &authParamRAND, bytes);
        break;
    case 3:
        m.corruptOptionalIE(0x20, &authParamAUTN, bytes);
        break;
    case 4:
        m.corruptOptionalIE(0x78, &eapMessage, bytes);
        break;
    default:
        break;
    }
}

void AuthenticationRequest::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        this->omitMandatory.insert(1);
        break;
    case 2:
        m.omitOptionalIE(&authParamRAND);
        break;
    case 3:
        m.omitOptionalIE(&authParamAUTN);
        break;
    case 4:
        m.omitOptionalIE(&eapMessage);
        break;
    default:
        break;
    }
}

void AuthenticationRequest::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        m.setIELength(&abba, fakeLen);
        break;
    case 2:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 3:
        m.setIELengthOptional(&authParamAUTN, fakeLen);
        break;
    case 4:
        m.setIELengthOptional(&eapMessage, fakeLen);
        break;
    default:
        break;
    }
}


AuthenticationResponse::AuthenticationResponse()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::AUTHENTICATION_RESPONSE;
}

void AuthenticationResponse::onBuild(NasMessageBuilder &b)
{
    b.optionalIE(0x2D, &authenticationResponseParameter);
    b.optionalIE(0x78, &eapMessage);
}

void AuthenticationResponse::onMutate(NasMessageMutator &m)
{
    // TODO: not mutate

    // int i = generate_int(3);
    // switch (i)
    // {
    // case 0:
    //     m.optionalIE(0x2D, &authenticationResponseParameter);
    //     break;
    // case 1:
    //     m.optionalIE(0x78, &eapMessage);
    //     break;
    // default:
    //     break;
    // }
}

AuthenticationResult::AuthenticationResult()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::AUTHENTICATION_RESULT;
}

void AuthenticationResult::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE1(&ngKSI);
    b.mandatoryIE(&eapMessage);
    b.optionalIE(0x38, &abba);
}

void AuthenticationResult::onMutate(NasMessageMutator &m)
{
    int i = generate_int(4);
    switch (i)
    {
    case 0:
        m.mandatoryIE1(&ngKSI);
        break;
    case 1:
        m.mandatoryIE(&eapMessage);
        break;
    case 2:
        m.optionalIE(0x38, &abba);
        break;
    default:
        break;
    }
}

void AuthenticationResult::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue1(&ngKSI, bytes);
        break;
    case 1:
        m.corruptValue(&eapMessage, bytes);
        break;
    case 2:
        m.corruptOptionalIE(0x38, &abba, bytes);
        break;
    default:
        break;
    }
}

void AuthenticationResult::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        this->omitMandatory.insert(1);
        break;
    case 2:
        m.omitOptionalIE(&abba);
        break;
    default:
        break;
    }
}

void AuthenticationResult::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        m.setIELength(&eapMessage, fakeLen);
        break;
    case 2:
        m.setIELengthOptional(&abba, fakeLen);
        break;
    default:
        break;
    }
}


ConfigurationUpdateCommand::ConfigurationUpdateCommand()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::CONFIGURATION_UPDATE_COMMAND;
}

void ConfigurationUpdateCommand::onBuild(NasMessageBuilder &b)
{
    b.optionalIE1(0xD, &configurationUpdateIndication);
    b.optionalIE(0x77, &guti);
    b.optionalIE(0x54, &taiList);
    b.optionalIE(0x15, &allowedNssai);
    b.optionalIE(0x27, &serviceAreaList);
    b.optionalIE(0x43, &networkFullName);
    b.optionalIE(0x45, &networkShortName);
    b.optionalIE(0x46, &localTimeZone);
    b.optionalIE(0x47, &universalTimeAndLocalTimeZone);
    b.optionalIE(0x49, &networkDaylightSavingTime);
    b.optionalIE(0x79, &ladnInformation);
    b.optionalIE1(0xB, &micoIndication);
    b.optionalIE1(0x9, &networkSlicingIndication);
    b.optionalIE(0x31, &configuredNssai);
    b.optionalIE(0x11, &rejectedNssai);
    b.optionalIE(0x76, &operatorDefinedAccessCategoryDefinitions);
    b.optionalIE1(0xF, &smsIndication);
}

void ConfigurationUpdateCommand::onMutate(NasMessageMutator &m)
{
    int i = generate_int(18);
    switch (i)
    {
    case 0:
        m.optionalIE1(0xD, &configurationUpdateIndication);
        break;
    case 1:
        m.optionalIE(0x77, &guti);
        break;
    case 2:
        m.optionalIE(0x54, &taiList);
        break;
    case 3:
        m.optionalIE(0x15, &allowedNssai);
        break;
    case 4:
        m.optionalIE(0x27, &serviceAreaList);
        break;
    case 5:
        m.optionalIE(0x43, &networkFullName);
        break;
    case 6:
        m.optionalIE(0x45, &networkShortName);
        break;
    case 7:
        m.optionalIE(0x46, &localTimeZone);
        break;
    case 8:
        m.optionalIE(0x47, &universalTimeAndLocalTimeZone);
        break;
    case 9:
        m.optionalIE(0x49, &networkDaylightSavingTime);
        break;
    case 10:
        m.optionalIE(0x79, &ladnInformation);
        break;
    case 11:
        m.optionalIE1(0xB, &micoIndication);
        break;
    case 12:
        m.optionalIE1(0x9, &networkSlicingIndication);
        break;
    case 13:
        m.optionalIE(0x31, &configuredNssai);
        break;
    case 14:
        m.optionalIE(0x11, &rejectedNssai);
        break;
    case 15:
        m.optionalIE(0x76, &operatorDefinedAccessCategoryDefinitions);
        break;
    case 16:
        m.optionalIE1(0xF, &smsIndication);
        break;
    default:
        break;
    }  
}

void ConfigurationUpdateCommand::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptOptionalIE1(0xD, &configurationUpdateIndication, bytes);
        break;
    case 1:
        m.corruptOptionalIE(0x77, &guti, bytes);
        break;
    case 2:
        m.corruptOptionalIE(0x54, &taiList, bytes);
        break;
    case 3:
        m.corruptOptionalIE(0x15, &allowedNssai, bytes);
        break;
    case 4:
        m.corruptOptionalIE(0x27, &serviceAreaList, bytes);
        break;
    case 5:
        m.corruptOptionalIE(0x43, &networkFullName, bytes);
        break;
    case 6:
        m.corruptOptionalIE(0x45, &networkShortName, bytes);
        break;
    case 7:
        m.corruptOptionalIE(0x46, &localTimeZone, bytes);
        break;
    case 8:
        m.corruptOptionalIE(0x47, &universalTimeAndLocalTimeZone, bytes);
        break;
    case 9:
        m.corruptOptionalIE(0x49, &networkDaylightSavingTime, bytes);
        break;
    case 10:
        m.corruptOptionalIE(0x79, &ladnInformation, bytes);
        break;
    case 11:
        m.corruptOptionalIE1(0xB, &micoIndication, bytes);
        break;
    case 12:
        m.corruptOptionalIE1(0x9, &networkSlicingIndication, bytes);
        break;
    case 13:
        m.corruptOptionalIE(0x31, &configuredNssai, bytes);
        break;
    case 14:
        m.corruptOptionalIE(0x11, &rejectedNssai, bytes);
        break;
    case 15:
        m.corruptOptionalIE(0x76, &operatorDefinedAccessCategoryDefinitions, bytes);
        break;
    case 16:
        m.corruptOptionalIE1(0xF, &smsIndication, bytes);
        break;
    default:
        break;
    }
}

void ConfigurationUpdateCommand::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        m.omitOptionalIE1(&configurationUpdateIndication);
        break;
    case 1:
        m.omitOptionalIE(&guti);
        break;
    case 2:
        m.omitOptionalIE(&taiList);
        break;
    case 3:
        m.omitOptionalIE(&allowedNssai);
        break;
    case 4:
        m.omitOptionalIE(&serviceAreaList);
        break;
    case 5:
        m.omitOptionalIE(&networkFullName);
        break;
    case 6:
        m.omitOptionalIE(&networkShortName);
        break;
    case 7:
        m.omitOptionalIE(&localTimeZone);
        break;
    case 8:
        m.omitOptionalIE(&universalTimeAndLocalTimeZone);
        break;
    case 9:
        m.omitOptionalIE(&networkDaylightSavingTime);
        break;
    case 10:
        m.omitOptionalIE(&ladnInformation);
        break;
    case 11:
        m.omitOptionalIE1(&micoIndication);
        break;
    case 12:
        m.omitOptionalIE1(&networkSlicingIndication);
        break;
    case 13:
        m.omitOptionalIE(&configuredNssai);
        break;
    case 14:
        m.omitOptionalIE(&rejectedNssai);
        break;
    case 15:
        m.omitOptionalIE(&operatorDefinedAccessCategoryDefinitions);
        break;
    case 16:
        m.omitOptionalIE1(&smsIndication);
        break;
    default:
        break;
    }
}

void ConfigurationUpdateCommand::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        m.setIELengthOptional(&guti, fakeLen);
        break;
    case 2:
        m.setIELengthOptional(&taiList, fakeLen);
        break;
    case 3:
        m.setIELengthOptional(&allowedNssai, fakeLen);
        break;
    case 4:
        m.setIELengthOptional(&serviceAreaList, fakeLen);
        break;
    case 5:
        m.setIELengthOptional(&networkFullName, fakeLen);
        break;
    case 6:
        m.setIELengthOptional(&networkShortName, fakeLen);
        break;
    case 7:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 8:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 9:
        m.setIELengthOptional(&networkDaylightSavingTime, fakeLen);
        break;
    case 10:
        m.setIELengthOptional(&ladnInformation, fakeLen);
        break;
    case 11:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 12:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 13:
        m.setIELengthOptional(&configuredNssai, fakeLen);
        break;
    case 14:
        m.setIELengthOptional(&rejectedNssai, fakeLen);
        break;
    case 15:
        m.setIELengthOptional(&operatorDefinedAccessCategoryDefinitions, fakeLen);
        break;
    case 16:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    default:
        break;
    }
}


ConfigurationUpdateComplete::ConfigurationUpdateComplete()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::CONFIGURATION_UPDATE_COMPLETE;
}

void ConfigurationUpdateComplete::onBuild(NasMessageBuilder &b)
{
}

void ConfigurationUpdateComplete::onMutate(NasMessageMutator &m)
{   
}

void ConfigurationUpdateComplete::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    // No IEs to corrupt
    default:
        break;
    }
}

void ConfigurationUpdateComplete::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    default:
        break;
    }
}

void ConfigurationUpdateComplete::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    default:
        break;
    }
}


DeRegistrationAcceptUeOriginating::DeRegistrationAcceptUeOriginating()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::DEREGISTRATION_ACCEPT_UE_ORIGINATING;
}

void DeRegistrationAcceptUeOriginating::onBuild(NasMessageBuilder &b)
{
}

void DeRegistrationAcceptUeOriginating::onMutate(NasMessageMutator &m)
{
}

void DeRegistrationAcceptUeOriginating::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    // No IEs to corrupt
    default:
        break;
    }
}

void DeRegistrationAcceptUeOriginating::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    default:
        break;
    }
}

void DeRegistrationAcceptUeOriginating::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    default:
        break;
    }
}


DeRegistrationAcceptUeTerminated::DeRegistrationAcceptUeTerminated()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::DEREGISTRATION_ACCEPT_UE_TERMINATED;
}

void DeRegistrationAcceptUeTerminated::onBuild(NasMessageBuilder &b)
{
}

void DeRegistrationAcceptUeTerminated::onMutate(NasMessageMutator &m)
{
}

void DeRegistrationAcceptUeTerminated::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    // No IEs to corrupt
    default:
        break;
    }
}

void DeRegistrationAcceptUeTerminated::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    default:
        break;
    }
}

void DeRegistrationAcceptUeTerminated::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    default:
        break;
    }
}


DeRegistrationRequestUeOriginating::DeRegistrationRequestUeOriginating()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::DEREGISTRATION_REQUEST_UE_ORIGINATING;
}

void DeRegistrationRequestUeOriginating::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE1(&ngKSI, &deRegistrationType);
    b.mandatoryIE(&mobileIdentity);
}

void DeRegistrationRequestUeOriginating::onMutate(NasMessageMutator &m)
{
    int i = generate_int(3);
    printf("Mutate DeRegistrationRequestUeOriginating, i = %d\n", i);
    switch (i)
    {
    case 0:
        m.mandatoryIE1(&ngKSI, &deRegistrationType);
        break;
    case 1:
        m.mandatoryIE(&mobileIdentity);
        break;
    default:
        break;
    }
}

void DeRegistrationRequestUeOriginating::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue1(&ngKSI, &deRegistrationType, bytes);
        break;
    case 1:
        m.corruptValue(&mobileIdentity, bytes);
        break;
    default:
        break;
    }
}

void DeRegistrationRequestUeOriginating::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        this->omitMandatory.insert(1);
        break;
    default:
        break;
    }
}

void DeRegistrationRequestUeOriginating::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        m.setIELength(&mobileIdentity, fakeLen);
        break;
    default:
        break;
    }
}


DeRegistrationRequestUeTerminated::DeRegistrationRequestUeTerminated()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::DEREGISTRATION_REQUEST_UE_TERMINATED;
}

void DeRegistrationRequestUeTerminated::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE1(&deRegistrationType);
    b.optionalIE(0x58, &mmCause);
    b.optionalIE(0x5F, &t3346Value);
}

void DeRegistrationRequestUeTerminated::onMutate(NasMessageMutator &m)
{
    int i = generate_int(4);
    switch (i)
    {
    case 0:
        m.mandatoryIE1(&deRegistrationType);
        break;
    case 1:
        m.optionalIE(0x58, &mmCause);
        break;
    case 2:
        m.optionalIE(0x5F, &t3346Value);
        break;
    default:
        break;
    }
}

void DeRegistrationRequestUeTerminated::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue1(&deRegistrationType, bytes);
        break;
    case 1:
        m.corruptOptionalIE(0x58, &mmCause, bytes);
        break;
    case 2:
        m.corruptOptionalIE(0x5F, &t3346Value, bytes);
        break;
    default:
        break;
    }
}

void DeRegistrationRequestUeTerminated::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        m.omitOptionalIE(&mmCause);
        break;
    case 2:
        m.omitOptionalIE(&t3346Value);
        break;
    default:
        break;
    }
}

void DeRegistrationRequestUeTerminated::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 2:
        m.setIELengthOptional(&t3346Value, fakeLen);
        break;
    default:
        break;
    }
}


DlNasTransport::DlNasTransport()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::DL_NAS_TRANSPORT;
}

void DlNasTransport::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE1(&payloadContainerType);
    b.mandatoryIE(&payloadContainer);
    b.optionalIE(0x12, &pduSessionId);
    b.optionalIE(0x24, &additionalInformation);
    b.optionalIE(0x58, &mmCause);
    b.optionalIE(0x37, &backOffTimerValue);
}

void DlNasTransport::onMutate(NasMessageMutator &m)
{
    int i = generate_int(7);
    switch (i)
    {
    case 0:
        m.mandatoryIE1(&payloadContainerType);
        break;
    case 1:
        m.mandatoryIE(&payloadContainer);
        break;
    case 2:
        m.optionalIE(0x12, &pduSessionId);
        break;
    case 3:
        m.optionalIE(0x24, &additionalInformation);
        break;
    case 4:
        m.optionalIE(0x58, &mmCause);
        break;
    case 5:
        m.optionalIE(0x37, &backOffTimerValue);
        break;
    default:
        break;
    }
}

void DlNasTransport::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue1(&payloadContainerType, bytes);
        break;
    case 1:
        m.corruptValue(&payloadContainer, bytes);
        break;
    case 2:
        m.corruptOptionalIE(0x12, &pduSessionId, bytes);
        break;
    case 3:
        m.corruptOptionalIE(0x24, &additionalInformation, bytes);
        break;
    case 4:
        m.corruptOptionalIE(0x58, &mmCause, bytes);
        break;
    case 5:
        m.corruptOptionalIE(0x37, &backOffTimerValue, bytes);
        break;
    default:
        break;
    }
}

void DlNasTransport::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        this->omitMandatory.insert(1);
        break;
    case 2:
        m.omitOptionalIE(&pduSessionId);
        break;
    case 3:
        m.omitOptionalIE(&additionalInformation);
        break;
    case 4:
        m.omitOptionalIE(&mmCause);
        break;
    case 5:
        m.omitOptionalIE(&backOffTimerValue);
        break;
    default:
        break;
    }
}

void DlNasTransport::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        m.setIELength(&payloadContainer, fakeLen);
        break;
    case 2:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 3:
        m.setIELengthOptional(&additionalInformation, fakeLen);
        break;
    case 4:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 5:
        m.setIELengthOptional(&backOffTimerValue, fakeLen);
        break;
    default:
        break;
    }
}


FiveGMmStatus::FiveGMmStatus()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::FIVEG_MM_STATUS;
}

void FiveGMmStatus::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE(&mmCause);
}

void FiveGMmStatus::onMutate(NasMessageMutator &m)
{
    if (generate_bit(1))
        m.mandatoryIE(&mmCause);
}

void FiveGMmStatus::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue(&mmCause, bytes);
        break;
    default:
        break;
    }
}

void FiveGMmStatus::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    default:
        break;
    }
}

void FiveGMmStatus::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    default:
        break;
    }
}


FiveGSmStatus::FiveGSmStatus()
{
    epd = EExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES;
    messageType = EMessageType::FIVEG_SM_STATUS;
}

void FiveGSmStatus::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE(&smCause);
}

void FiveGSmStatus::onMutate(NasMessageMutator &m)
{
    if (generate_bit(1))
        m.mandatoryIE(&smCause);
}

void FiveGSmStatus::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue(&smCause, bytes);
        break;
    default:
        break;
    }
}

void FiveGSmStatus::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    default:
        break;
    }
}

void FiveGSmStatus::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    default:
        break;
    }
}


IdentityRequest::IdentityRequest()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::IDENTITY_REQUEST;
}

void IdentityRequest::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE1(&identityType);
}

void IdentityRequest::onMutate(NasMessageMutator &m)
{
    if (generate_bit(1))
        m.mandatoryIE1(&identityType);
}

void IdentityRequest::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue1(&identityType, bytes);
        break;
    default:
        break;
    }
}

void IdentityRequest::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    default:
        break;
    }
}

void IdentityRequest::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    default:
        break;
    }
}


IdentityResponse::IdentityResponse()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::IDENTITY_RESPONSE;
}

void IdentityResponse::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE(&mobileIdentity);
}

void IdentityResponse::onMutate(NasMessageMutator &m)
{
    if (generate_bit(1))
        m.mandatoryIE(&mobileIdentity);
}

void IdentityResponse::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue(&mobileIdentity, bytes);
        break;
    default:
        break;
    }
}

void IdentityResponse::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    default:
        break;
    }
}

void IdentityResponse::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        m.setIELength(&mobileIdentity, fakeLen);
        break;
    default:
        break;
    }
}


Notification::Notification()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::NOTIFICATION;
}

void Notification::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE1(&accessType);
}

void Notification::onMutate(NasMessageMutator &m)
{
    if (generate_bit(1))
        m.mandatoryIE1(&accessType);
}

void Notification::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue1(&accessType, bytes);
        break;
    default:
        break;
    }
}

void Notification::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    default:
        break;
    }
}

void Notification::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    default:
        break;
    }
}


NotificationResponse::NotificationResponse()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::NOTIFICATION_RESPONSE;
}

void NotificationResponse::onBuild(NasMessageBuilder &b)
{
    b.optionalIE(0x50, &pduSessionStatus);
}

void NotificationResponse::onMutate(NasMessageMutator &m)
{
    if (generate_bit(1))
        m.optionalIE(0x50, &pduSessionStatus);
}

void NotificationResponse::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptOptionalIE(0x50, &pduSessionStatus, bytes);
        break;
    default:
        break;
    }
}

void NotificationResponse::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        m.omitOptionalIE(&pduSessionStatus);
        break;
    default:
        break;
    }
}

void NotificationResponse::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        m.setIELengthOptional(&pduSessionStatus, fakeLen);
        break;
    default:
        break;
    }
}


PduSessionAuthenticationCommand::PduSessionAuthenticationCommand()
{
    epd = EExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES;
    messageType = EMessageType::PDU_SESSION_AUTHENTICATION_COMMAND;
}

void PduSessionAuthenticationCommand::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE(&eapMessage);
    b.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
}

void PduSessionAuthenticationCommand::onMutate(NasMessageMutator &m)
{
    int i = generate_int(3);
    switch (i)
    {
    case 0:
        m.mandatoryIE(&eapMessage);
        break;
    case 1:
        m.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionAuthenticationCommand::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue(&eapMessage, bytes);
        break;
    case 1:
        m.corruptOptionalIE(0x7B, &extendedProtocolConfigurationOptions, bytes);
        break;
    default:
        break;
    }
}

void PduSessionAuthenticationCommand::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        m.omitOptionalIE(&extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionAuthenticationCommand::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        m.setIELength(&eapMessage, fakeLen);
        break;
    case 1:
        m.setIELengthOptional(&extendedProtocolConfigurationOptions, fakeLen);
        break;
    default:
        break;
    }
}


PduSessionAuthenticationComplete::PduSessionAuthenticationComplete()
{
    epd = EExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES;
    messageType = EMessageType::PDU_SESSION_AUTHENTICATION_COMPLETE;
}

void PduSessionAuthenticationComplete::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE(&eapMessage);
    b.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
}

void PduSessionAuthenticationComplete::onMutate(NasMessageMutator &m)
{
    int i = generate_int(3);
    switch (i)
    {
    case 0:
        m.mandatoryIE(&eapMessage);
        break;
    case 1:
        m.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionAuthenticationComplete::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue(&eapMessage, bytes);
        break;
    case 1:
        m.corruptOptionalIE(0x7B, &extendedProtocolConfigurationOptions, bytes);
        break;
    default:
        break;
    }
}

void PduSessionAuthenticationComplete::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        m.omitOptionalIE(&extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionAuthenticationComplete::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        m.setIELength(&eapMessage, fakeLen);
        break;
    case 1:
        m.setIELengthOptional(&extendedProtocolConfigurationOptions, fakeLen);
        break;
    default:
        break;
    }
}


PduSessionAuthenticationResult::PduSessionAuthenticationResult()
{
    epd = EExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES;
    messageType = EMessageType::PDU_SESSION_AUTHENTICATION_RESULT;
}

void PduSessionAuthenticationResult::onBuild(NasMessageBuilder &b)
{
    b.optionalIE(0x78, &eapMessage);
    b.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
}

void PduSessionAuthenticationResult::onMutate(NasMessageMutator &m)
{
    int i = generate_int(3);
    switch (i)
    {
    case 0:
        m.optionalIE(0x78, &eapMessage);
        break;
    case 1:
        m.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionAuthenticationResult::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptOptionalIE(0x78, &eapMessage, bytes);
        break;
    case 1:
        m.corruptOptionalIE(0x7B, &extendedProtocolConfigurationOptions, bytes);
        break;
    default:
        break;
    }
}

void PduSessionAuthenticationResult::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        m.omitOptionalIE(&eapMessage);
        break;
    case 1:
        m.omitOptionalIE(&extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionAuthenticationResult::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        m.setIELengthOptional(&eapMessage, fakeLen);
        break;
    case 1:
        m.setIELengthOptional(&extendedProtocolConfigurationOptions, fakeLen);
        break;
    default:
        break;
    }
}


PduSessionEstablishmentAccept::PduSessionEstablishmentAccept()
{
    epd = EExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES;
    messageType = EMessageType::PDU_SESSION_ESTABLISHMENT_ACCEPT;
}

void PduSessionEstablishmentAccept::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE1(&selectedSscMode, &selectedPduSessionType);
    b.mandatoryIE(&authorizedQoSRules);
    b.mandatoryIE(&sessionAmbr);
    b.optionalIE(0x59, &smCause);
    b.optionalIE(0x29, &pduAddress);
    b.optionalIE(0x56, &rqTimerValue);
    b.optionalIE(0x22, &sNssai);
    b.optionalIE1(0x8, &alwaysOnPduSessionIndication);
    b.optionalIE(0x7F, &mappedEpsBearerContexts);
    b.optionalIE(0x78, &eapMessage);
    b.optionalIE(0x79, &authorizedQoSFlowDescriptions);
    b.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
    b.optionalIE(0x25, &dnn);
}

void PduSessionEstablishmentAccept::onMutate(NasMessageMutator &m)
{
    int i = generate_int(14);
    switch (i)
    {
    case 0:
        m.mandatoryIE1(&selectedSscMode, &selectedPduSessionType);
        break;
    case 1:
        m.mandatoryIE(&authorizedQoSRules);
        break;
    case 2:
        m.mandatoryIE(&sessionAmbr);
        break;
    case 3:
        m.optionalIE(0x59, &smCause);
        break;
    case 4:
        m.optionalIE(0x29, &pduAddress);
        break;
    case 5:
        m.optionalIE(0x56, &rqTimerValue);
        break;
    case 6:
        m.optionalIE(0x22, &sNssai);
        break;
    case 7:
        m.optionalIE1(0x8, &alwaysOnPduSessionIndication);
        break;
    case 8:
        m.optionalIE(0x7F, &mappedEpsBearerContexts);
        break;
    case 9:
        m.optionalIE(0x78, &eapMessage);
        break;
    case 10:
        m.optionalIE(0x79, &authorizedQoSFlowDescriptions);
        break;
    case 11:
        m.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
        break;
    case 12:
        m.optionalIE(0x25, &dnn);
        break;
    default:
        break;
    }
}

void PduSessionEstablishmentAccept::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue1(&selectedSscMode, &selectedPduSessionType, bytes);
        break;
    case 1:
        m.corruptValue(&authorizedQoSRules, bytes);
        break;
    case 2:
        m.corruptValue(&sessionAmbr, bytes);
        break;
    case 3:
        m.corruptOptionalIE(0x59, &smCause, bytes);
        break;
    case 4:
        m.corruptOptionalIE(0x29, &pduAddress, bytes);
        break;
    case 5:
        m.corruptOptionalIE(0x56, &rqTimerValue, bytes);
        break;
    case 6:
        m.corruptOptionalIE(0x22, &sNssai, bytes);
        break;
    case 7:
        m.corruptOptionalIE1(0x8, &alwaysOnPduSessionIndication, bytes);
        break;
    case 8:
        m.corruptOptionalIE(0x7F, &mappedEpsBearerContexts, bytes);
        break;
    case 9:
        m.corruptOptionalIE(0x78, &eapMessage, bytes);
        break;
    case 10:
        m.corruptOptionalIE(0x79, &authorizedQoSFlowDescriptions, bytes);
        break;
    case 11:
        m.corruptOptionalIE(0x7B, &extendedProtocolConfigurationOptions, bytes);
        break;
    case 12:
        m.corruptOptionalIE(0x25, &dnn, bytes);
        break;
    default:
        break;
    }
}

void PduSessionEstablishmentAccept::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        this->omitMandatory.insert(1);
        break;
    case 2:
        this->omitMandatory.insert(2);
        break;
    case 3:
        m.omitOptionalIE(&smCause);
        break;
    case 4:
        m.omitOptionalIE(&pduAddress);
        break;
    case 5:
        m.omitOptionalIE(&rqTimerValue);
        break;
    case 6:
        m.omitOptionalIE(&sNssai);
        break;
    case 7:
        m.omitOptionalIE1(&alwaysOnPduSessionIndication);
        break;
    case 8:
        m.omitOptionalIE(&mappedEpsBearerContexts);
        break;
    case 9:
        m.omitOptionalIE(&eapMessage);
        break;
    case 10:
        m.omitOptionalIE(&authorizedQoSFlowDescriptions);
        break;
    case 11:
        m.omitOptionalIE(&extendedProtocolConfigurationOptions);
        break;
    case 12:
        m.omitOptionalIE(&dnn);
        break;
    default:
        break;
    }
}

void PduSessionEstablishmentAccept::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        m.setIELength(&authorizedQoSRules, fakeLen);
        break;
    case 2:
        m.setIELength(&sessionAmbr, fakeLen);
        break;
    case 3:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 4:
        m.setIELengthOptional(&pduAddress, fakeLen);
        break;
    case 5:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 6:
        m.setIELengthOptional(&sNssai, fakeLen);
        break;
    case 7:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 8:
        m.setIELengthOptional(&mappedEpsBearerContexts, fakeLen);
        break;
    case 9:
        m.setIELengthOptional(&eapMessage, fakeLen);
        break;
    case 10:
        m.setIELengthOptional(&authorizedQoSFlowDescriptions, fakeLen);
        break;
    case 11:
        m.setIELengthOptional(&extendedProtocolConfigurationOptions, fakeLen);
        break;
    case 12:
        m.setIELengthOptional(&dnn, fakeLen);
        break;
    default:
        break;
    }
}


PduSessionEstablishmentReject::PduSessionEstablishmentReject()
{
    epd = EExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES;
    messageType = EMessageType::PDU_SESSION_ESTABLISHMENT_REJECT;
}

void PduSessionEstablishmentReject::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE(&smCause);
    b.optionalIE(0x37, &backOffTimerValue);
    b.optionalIE1(0xF, &allowedSscMode);
    b.optionalIE(0x78, &eapMessage);
    b.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
}

void PduSessionEstablishmentReject::onMutate(NasMessageMutator &m)
{
    int i = generate_int(6);
    switch (i)
    {
    case 0:
        m.mandatoryIE(&smCause);
        break;
    case 1:
        m.optionalIE(0x37, &backOffTimerValue);
        break;
    case 2:
        m.optionalIE1(0xF, &allowedSscMode);
        break;
    case 3:
        m.optionalIE(0x78, &eapMessage);
        break;
    case 4:
        m.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionEstablishmentReject::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue(&smCause, bytes);
        break;
    case 1:
        m.corruptOptionalIE(0x37, &backOffTimerValue, bytes);
        break;
    case 2:
        m.corruptOptionalIE1(0xF, &allowedSscMode, bytes);
        break;
    case 3:
        m.corruptOptionalIE(0x78, &eapMessage, bytes);
        break;
    case 4:
        m.corruptOptionalIE(0x7B, &extendedProtocolConfigurationOptions, bytes);
        break;
    default:
        break;
    }
}

void PduSessionEstablishmentReject::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        m.omitOptionalIE(&backOffTimerValue);
        break;
    case 2:
        m.omitOptionalIE1(&allowedSscMode);
        break;
    case 3:
        m.omitOptionalIE(&eapMessage);
        break;
    case 4:
        m.omitOptionalIE(&extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionEstablishmentReject::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        m.setIELengthOptional(&backOffTimerValue, fakeLen);
        break;
    case 2:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 3:
        m.setIELengthOptional(&eapMessage, fakeLen);
        break;
    case 4:
        m.setIELengthOptional(&extendedProtocolConfigurationOptions, fakeLen);
        break;
    default:
        break;
    }
}


PduSessionEstablishmentRequest::PduSessionEstablishmentRequest()
{
    epd = EExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES;
    messageType = EMessageType::PDU_SESSION_ESTABLISHMENT_REQUEST;
}

void PduSessionEstablishmentRequest::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE(&integrityProtectionMaximumDataRate);
    b.optionalIE1(0x9, &pduSessionType);
    b.optionalIE1(0xA, &sscMode);
    b.optionalIE(0x28, &smCapability);
    b.optionalIE(0x55, &maximumNumberOfSupportedPacketFilters);
    b.optionalIE1(0xB, &alwaysOnPduSessionRequested);
    b.optionalIE(0x39, &smPduDnRequestContainer);
    b.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
}

void PduSessionEstablishmentRequest::onMutate(NasMessageMutator &m)
{
    int i = generate_int(9);
    switch (i)
    {
    case 0:
        m.mandatoryIE(&integrityProtectionMaximumDataRate);
        break;
    case 1:
        m.optionalIE1(0x9, &pduSessionType);
        break;
    case 2:
        m.optionalIE1(0xA, &sscMode);
        break;
    case 3:
        m.optionalIE(0x28, &smCapability);
        break;
    case 4:
        m.optionalIE(0x55, &maximumNumberOfSupportedPacketFilters);
        break;
    case 5:
        m.optionalIE1(0xB, &alwaysOnPduSessionRequested);
        break;
    case 6:
        m.optionalIE(0x39, &smPduDnRequestContainer);
        break;
    case 7: 
        m.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionEstablishmentRequest::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue(&integrityProtectionMaximumDataRate, bytes);
        break;
    case 1:
        m.corruptOptionalIE1(0x9, &pduSessionType, bytes);
        break;
    case 2:
        m.corruptOptionalIE1(0xA, &sscMode, bytes);
        break;
    case 3:
        m.corruptOptionalIE(0x28, &smCapability, bytes);
        break;
    case 4:
        m.corruptOptionalIE(0x55, &maximumNumberOfSupportedPacketFilters, bytes);
        break;
    case 5:
        m.corruptOptionalIE1(0xB, &alwaysOnPduSessionRequested, bytes);
        break;
    case 6:
        m.corruptOptionalIE(0x39, &smPduDnRequestContainer, bytes);
        break;
    case 7:
        m.corruptOptionalIE(0x7B, &extendedProtocolConfigurationOptions, bytes);
        break;
    default:
        break;
    }
}

void PduSessionEstablishmentRequest::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        m.omitOptionalIE1(&pduSessionType);
        break;
    case 2:
        m.omitOptionalIE1(&sscMode);
        break;
    case 3:
        m.omitOptionalIE(&smCapability);
        break;
    case 4:
        m.omitOptionalIE(&maximumNumberOfSupportedPacketFilters);
        break;
    case 5:
        m.omitOptionalIE1(&alwaysOnPduSessionRequested);
        break;
    case 6:
        m.omitOptionalIE(&smPduDnRequestContainer);
        break;
    case 7:
        m.omitOptionalIE(&extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionEstablishmentRequest::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 2:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 3:
        m.setIELengthOptional(&smCapability, fakeLen);
        break;
    case 4:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 5:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 6:
        m.setIELengthOptional(&smPduDnRequestContainer, fakeLen);
        break;
    case 7:
        m.setIELengthOptional(&extendedProtocolConfigurationOptions, fakeLen);
        break;
    default:
        break;
    }
}


PduSessionModificationCommand::PduSessionModificationCommand()
{
    epd = EExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES;
    messageType = EMessageType::PDU_SESSION_MODIFICATION_COMMAND;
}

void PduSessionModificationCommand::onBuild(NasMessageBuilder &b)
{
    b.optionalIE(0x59, &smCause);
    b.optionalIE(0x2A, &sessionAmbr);
    b.optionalIE(0x56, &rqTimerValue);
    b.optionalIE1(0x8, &alwaysOnPduSessionIndication);
    b.optionalIE(0x7A, &authorizedQoSRules);
    b.optionalIE(0x7F, &mappedEpsBearerContexts);
    b.optionalIE(0x79, &authorizedQoSFlowDescriptions);
    b.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
}

void PduSessionModificationCommand::onMutate(NasMessageMutator &m)
{
    int i = generate_int(9);
    switch (i)
    {
    case 0:
        m.optionalIE(0x59, &smCause);
        break;
    case 1:
        m.optionalIE(0x2A, &sessionAmbr);
        break;
    case 2:
        m.optionalIE(0x56, &rqTimerValue);
        break;
    case 3:
        m.optionalIE1(0x8, &alwaysOnPduSessionIndication);
        break;
    case 4:
        m.optionalIE(0x7A, &authorizedQoSRules);
        break;
    case 5:
        m.optionalIE(0x7F, &mappedEpsBearerContexts);
        break;
    case 6:
        m.optionalIE(0x79, &authorizedQoSFlowDescriptions);
        break;
    case 7:
        m.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionModificationCommand::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptOptionalIE(0x59, &smCause, bytes);
        break;
    case 1:
        m.corruptOptionalIE(0x2A, &sessionAmbr, bytes);
        break;
    case 2:
        m.corruptOptionalIE(0x56, &rqTimerValue, bytes);
        break;
    case 3:
        m.corruptOptionalIE1(0x8, &alwaysOnPduSessionIndication, bytes);
        break;
    case 4:
        m.corruptOptionalIE(0x7A, &authorizedQoSRules, bytes);
        break;
    case 5:
        m.corruptOptionalIE(0x7F, &mappedEpsBearerContexts, bytes);
        break;
    case 6:
        m.corruptOptionalIE(0x79, &authorizedQoSFlowDescriptions, bytes);
        break;
    case 7:
        m.corruptOptionalIE(0x7B, &extendedProtocolConfigurationOptions, bytes);
        break;
    default:
        break;
    }
}

void PduSessionModificationCommand::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        m.omitOptionalIE(&smCause);
        break;
    case 1:
        m.omitOptionalIE(&sessionAmbr);
        break;
    case 2:
        m.omitOptionalIE(&rqTimerValue);
        break;
    case 3:
        m.omitOptionalIE1(&alwaysOnPduSessionIndication);
        break;
    case 4:
        m.omitOptionalIE(&authorizedQoSRules);
        break;
    case 5:
        m.omitOptionalIE(&mappedEpsBearerContexts);
        break;
    case 6:
        m.omitOptionalIE(&authorizedQoSFlowDescriptions);
        break;
    case 7:
        m.omitOptionalIE(&extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionModificationCommand::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        m.setIELengthOptional(&sessionAmbr, fakeLen);
        break;
    case 2:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 3:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 4:
        m.setIELengthOptional(&authorizedQoSRules, fakeLen);
        break;
    case 5:
        m.setIELengthOptional(&mappedEpsBearerContexts, fakeLen);
        break;
    case 6:
        m.setIELengthOptional(&authorizedQoSFlowDescriptions, fakeLen);
        break;
    case 7:
        m.setIELengthOptional(&extendedProtocolConfigurationOptions, fakeLen);
        break;
    default:
        break;
    }
}


PduSessionModificationCommandReject::PduSessionModificationCommandReject()
{
    epd = EExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES;
    messageType = EMessageType::PDU_SESSION_MODIFICATION_COMMAND_REJECT;
}

void PduSessionModificationCommandReject::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE(&smCause);
    b.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
}

void PduSessionModificationCommandReject::onMutate(NasMessageMutator &m)
{
    int i = generate_int(3);
    switch (i)
    {
    case 0:
        m.mandatoryIE(&smCause);
        break;
    case 1:
        m.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionModificationCommandReject::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue(&smCause, bytes);
        break;
    case 1:
        m.corruptOptionalIE(0x7B, &extendedProtocolConfigurationOptions, bytes);
        break;
    default:
        break;
    }
}

void PduSessionModificationCommandReject::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        m.omitOptionalIE(&extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionModificationCommandReject::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        m.setIELengthOptional(&extendedProtocolConfigurationOptions, fakeLen);
        break;
    default:
        break;
    }
}


PduSessionModificationComplete::PduSessionModificationComplete()
{
    epd = EExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES;
    messageType = EMessageType::PDU_SESSION_MODIFICATION_COMPLETE;
}

void PduSessionModificationComplete::onBuild(NasMessageBuilder &b)
{
    b.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
}

void PduSessionModificationComplete::onMutate(NasMessageMutator &m)
{
    if (generate_bit(1))
        m.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
}

void PduSessionModificationComplete::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptOptionalIE(0x7B, &extendedProtocolConfigurationOptions, bytes);
        break;
    default:
        break;
    }
}

void PduSessionModificationComplete::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        m.omitOptionalIE(&extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionModificationComplete::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        m.setIELengthOptional(&extendedProtocolConfigurationOptions, fakeLen);
        break;
    default:
        break;
    }
}


PduSessionModificationReject::PduSessionModificationReject()
{
    epd = EExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES;
    messageType = EMessageType::PDU_SESSION_MODIFICATION_REJECT;
}

void PduSessionModificationReject::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE(&smCause);
    b.optionalIE(0x37, &backOffTimerValue);
    b.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
}

void PduSessionModificationReject::onMutate(NasMessageMutator &m)
{
    int i = generate_int(4);
    switch (i)
    {
    case 0:
        m.mandatoryIE(&smCause);
        break;
    case 1:
        m.optionalIE(0x37, &backOffTimerValue);
        break;
    case 2:
        m.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionModificationReject::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue(&smCause, bytes);
        break;
    case 1:
        m.corruptOptionalIE(0x37, &backOffTimerValue, bytes);
        break;
    case 2:
        m.corruptOptionalIE(0x7B, &extendedProtocolConfigurationOptions, bytes);
        break;
    default:
        break;
    }
}

void PduSessionModificationReject::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        m.omitOptionalIE(&backOffTimerValue);
        break;
    case 2:
        m.omitOptionalIE(&extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionModificationReject::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        m.setIELengthOptional(&backOffTimerValue, fakeLen);
        break;
    case 2:
        m.setIELengthOptional(&extendedProtocolConfigurationOptions, fakeLen);
        break;
    default:
        break;
    }
}


PduSessionModificationRequest::PduSessionModificationRequest()
{
    epd = EExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES;
    messageType = EMessageType::PDU_SESSION_MODIFICATION_REQUEST;
}

void PduSessionModificationRequest::onBuild(NasMessageBuilder &b)
{
    b.optionalIE(0x28, &smCapability);
    b.optionalIE(0x59, &smCause);
    b.optionalIE(0x55, &maximumNumberOfSupportedPacketFilters);
    b.optionalIE1(0xB, &alwaysOnPduSessionRequested);
    b.optionalIE(0x13, &integrityProtectionMaximumDataRate);
    b.optionalIE(0x7A, &requestedQosRules);
    b.optionalIE(0x79, &requestedQosFlowDescriptions);
    b.optionalIE(0x7F, &mappedEpsBearerContexts);
    b.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
}

void PduSessionModificationRequest::onMutate(NasMessageMutator &m)
{
    int i = generate_int(10);
    switch (i)
    {
    case 0:
        m.optionalIE(0x28, &smCapability);
        break;
    case 1:
        m.optionalIE(0x59, &smCause);
        break;
    case 2:
        m.optionalIE(0x55, &maximumNumberOfSupportedPacketFilters);
        break;
    case 3:
        m.optionalIE1(0xB, &alwaysOnPduSessionRequested);
        break;
    case 4:
        m.optionalIE(0x13, &integrityProtectionMaximumDataRate);
        break;
    case 5:
        m.optionalIE(0x7A, &requestedQosRules);
        break;
    case 6:
        m.optionalIE(0x79, &requestedQosFlowDescriptions);
        break;
    case 7:
        m.optionalIE(0x7F, &mappedEpsBearerContexts);
        break;
    case 8:
        m.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionModificationRequest::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptOptionalIE(0x28, &smCapability, bytes);
        break;
    case 1:
        m.corruptOptionalIE(0x59, &smCause, bytes);
        break;
    case 2:
        m.corruptOptionalIE(0x55, &maximumNumberOfSupportedPacketFilters, bytes);
        break;
    case 3:
        m.corruptOptionalIE1(0xB, &alwaysOnPduSessionRequested, bytes);
        break;
    case 4:
        m.corruptOptionalIE(0x13, &integrityProtectionMaximumDataRate, bytes);
        break;
    case 5:
        m.corruptOptionalIE(0x7A, &requestedQosRules, bytes);
        break;
    case 6:
        m.corruptOptionalIE(0x79, &requestedQosFlowDescriptions, bytes);
        break;
    case 7:
        m.corruptOptionalIE(0x7F, &mappedEpsBearerContexts, bytes);
        break;
    case 8:
        m.corruptOptionalIE(0x7B, &extendedProtocolConfigurationOptions, bytes);
        break;
    default:
        break;
    }
}

void PduSessionModificationRequest::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        m.omitOptionalIE(&smCapability);
        break;
    case 1:
        m.omitOptionalIE(&smCause);
        break;
    case 2:
        m.omitOptionalIE(&maximumNumberOfSupportedPacketFilters);
        break;
    case 3:
        m.omitOptionalIE1(&alwaysOnPduSessionRequested);
        break;
    case 4:
        m.omitOptionalIE(&integrityProtectionMaximumDataRate);
        break;
    case 5:
        m.omitOptionalIE(&requestedQosRules);
        break;
    case 6:
        m.omitOptionalIE(&requestedQosFlowDescriptions);
        break;
    case 7:
        m.omitOptionalIE(&mappedEpsBearerContexts);
        break;
    case 8:
        m.omitOptionalIE(&extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionModificationRequest::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        m.setIELengthOptional(&smCapability, fakeLen);
        break;
    case 1:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 2:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 3:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 4:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 5:
        m.setIELengthOptional(&requestedQosRules, fakeLen);
        break;
    case 6:
        m.setIELengthOptional(&requestedQosFlowDescriptions, fakeLen);
        break;
    case 7:
        m.setIELengthOptional(&mappedEpsBearerContexts, fakeLen);
        break;
    case 8:
        m.setIELengthOptional(&extendedProtocolConfigurationOptions, fakeLen);
        break;
    default:
        break;
    }
}


PduSessionReleaseCommand::PduSessionReleaseCommand()
{
    epd = EExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES;
    messageType = EMessageType::PDU_SESSION_RELEASE_COMMAND;
}

void PduSessionReleaseCommand::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE(&smCause);
    b.optionalIE(0x37, &backOffTimerValue);
    b.optionalIE(0x78, &eapMessage);
    b.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
}

void PduSessionReleaseCommand::onMutate(NasMessageMutator &m)
{
    int i = generate_int(5);
    switch (i)
    {
    case 0:
        m.mandatoryIE(&smCause);
        break;
    case 1:
        m.optionalIE(0x37, &backOffTimerValue);
        break;
    case 2:
        m.optionalIE(0x78, &eapMessage);
        break;
    case 3:
        m.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionReleaseCommand::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue(&smCause, bytes);
        break;
    case 1:
        m.corruptOptionalIE(0x37, &backOffTimerValue, bytes);
        break;
    case 2:
        m.corruptOptionalIE(0x78, &eapMessage, bytes);
        break;
    case 3:
        m.corruptOptionalIE(0x7B, &extendedProtocolConfigurationOptions, bytes);
        break;
    default:
        break;
    }
}

void PduSessionReleaseCommand::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        m.omitOptionalIE(&backOffTimerValue);
        break;
    case 2:
        m.omitOptionalIE(&eapMessage);
        break;
    case 3:
        m.omitOptionalIE(&extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionReleaseCommand::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        m.setIELengthOptional(&backOffTimerValue, fakeLen);
        break;
    case 2:
        m.setIELengthOptional(&eapMessage, fakeLen);
        break;
    case 3:
        m.setIELengthOptional(&extendedProtocolConfigurationOptions, fakeLen);
        break;
    default:
        break;
    }
}


PduSessionReleaseComplete::PduSessionReleaseComplete()
{
    epd = EExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES;
    messageType = EMessageType::PDU_SESSION_RELEASE_COMPLETE;
}

void PduSessionReleaseComplete::onBuild(NasMessageBuilder &b)
{
    b.optionalIE(0x59, &smCause);
    b.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
}

void PduSessionReleaseComplete::onMutate(NasMessageMutator &m)
{
    int i = generate_int(3);
    switch (i)
    {
    case 0:
        m.optionalIE(0x59, &smCause);
        break;
    case 1:
        m.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionReleaseComplete::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptOptionalIE(0x59, &smCause, bytes);
        break;
    case 1:
        m.corruptOptionalIE(0x7B, &extendedProtocolConfigurationOptions, bytes);
        break;
    default:
        break;
    }
}

void PduSessionReleaseComplete::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        m.omitOptionalIE(&smCause);
        break;
    case 1:
        m.omitOptionalIE(&extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionReleaseComplete::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        m.setIELengthOptional(&extendedProtocolConfigurationOptions, fakeLen);
        break;
    default:
        break;
    }
}


PduSessionReleaseReject::PduSessionReleaseReject()
{
    epd = EExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES;
    messageType = EMessageType::PDU_SESSION_RELEASE_REJECT;
}

void PduSessionReleaseReject::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE(&smCause);
    b.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
}

void PduSessionReleaseReject::onMutate(NasMessageMutator &m)
{
    int i = generate_int(3);
    switch (i)
    {
    case 0:
        m.mandatoryIE(&smCause);
        break;
    case 1:
        m.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionReleaseReject::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue(&smCause, bytes);
        break;
    case 1:
        m.corruptOptionalIE(0x7B, &extendedProtocolConfigurationOptions, bytes);
        break;
    default:
        break;
    }
}

void PduSessionReleaseReject::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        m.omitOptionalIE(&extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionReleaseReject::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        m.setIELengthOptional(&extendedProtocolConfigurationOptions, fakeLen);
        break;
    default:
        break;
    }
}


PduSessionReleaseRequest::PduSessionReleaseRequest()
{
    epd = EExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES;
    messageType = EMessageType::PDU_SESSION_RELEASE_REQUEST;
}

void PduSessionReleaseRequest::onBuild(NasMessageBuilder &b)
{
    b.optionalIE(0x59, &smCause);
    b.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
}

void PduSessionReleaseRequest::onMutate(NasMessageMutator &m)
{
    int i = generate_int(3);
    switch (i)
    {
    case 0:
        m.optionalIE(0x59, &smCause);
        break;
    case 1:
        m.optionalIE(0x7B, &extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionReleaseRequest::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptOptionalIE(0x59, &smCause, bytes);
        break;
    case 1:
        m.corruptOptionalIE(0x7B, &extendedProtocolConfigurationOptions, bytes);
        break;
    default:
        break;
    }
}

void PduSessionReleaseRequest::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        m.omitOptionalIE(&smCause);
        break;
    case 1:
        m.omitOptionalIE(&extendedProtocolConfigurationOptions);
        break;
    default:
        break;
    }
}

void PduSessionReleaseRequest::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        m.setIELengthOptional(&extendedProtocolConfigurationOptions, fakeLen);
        break;
    default:
        break;
    }
}


RegistrationAccept::RegistrationAccept()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::REGISTRATION_ACCEPT;
}

void RegistrationAccept::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE(&registrationResult);
    b.optionalIE1(0x9, &networkSlicingIndication);
    b.optionalIE1(0xA, &nssaiInclusionMode);
    b.optionalIE1(0xB, &micoIndication);
    b.optionalIE(0x77, &mobileIdentity);
    b.optionalIE(0x4A, &equivalentPLMNs);
    b.optionalIE(0x54, &taiList);
    b.optionalIE(0x15, &allowedNSSAI);
    b.optionalIE(0x11, &rejectedNSSAI);
    b.optionalIE(0x31, &configuredNSSAI);
    b.optionalIE(0x21, &networkFeatureSupport);
    b.optionalIE(0x50, &pduSessionStatus);
    b.optionalIE(0x26, &pduSessionReactivationResult);
    b.optionalIE(0x72, &pduSessionReactivationResultErrorCause);
    b.optionalIE(0x79, &ladnInformation);
    b.optionalIE(0x27, &serviceAreaList);
    b.optionalIE(0x5E, &t3512Value);
    b.optionalIE(0x5D, &non3gppDeRegistrationTimerValue);
    b.optionalIE(0x16, &t3502Value);
    b.optionalIE(0x34, &emergencyNumberList);
    b.optionalIE(0x7A, &extendedEmergencyNumberList);
    b.optionalIE(0x73, &sorTransparentContainer);
    b.optionalIE(0x78, &eapMessage);
    b.optionalIE(0x76, &operatorDefinedAccessCategoryDefinitions);
    b.optionalIE(0x51, &negotiatedDrxParameters);
}

void RegistrationAccept::onMutate(NasMessageMutator &m)
{
    int i = generate_int(26);
    switch (i)
    {
    case 0:
        m.mandatoryIE(&registrationResult);
        break;
    case 1:
        m.optionalIE1(0x9, &networkSlicingIndication);
        break;
    case 2:
        m.optionalIE1(0xA, &nssaiInclusionMode);
        break;
    case 3:
        m.optionalIE1(0xB, &micoIndication);
        break;
    case 4:
        m.optionalIE(0x77, &mobileIdentity);
        break;
    case 5:
        m.optionalIE(0x4A, &equivalentPLMNs);
        break;
    case 6:
        m.optionalIE(0x54, &taiList);
        break;
    case 7:
        m.optionalIE(0x15, &allowedNSSAI);
        break;
    case 8:
        m.optionalIE(0x11, &rejectedNSSAI);
        break;
    case 9:
        m.optionalIE(0x31, &configuredNSSAI);
        break;
    case 10:
        m.optionalIE(0x21, &networkFeatureSupport);
        break;
    case 11:
        m.optionalIE(0x50, &pduSessionStatus);
        break;
    case 12:
        m.optionalIE(0x26, &pduSessionReactivationResult);
        break;
    case 13:
        m.optionalIE(0x72, &pduSessionReactivationResultErrorCause);
        break;
    case 14:
        m.optionalIE(0x79, &ladnInformation);
        break;
    case 15:
        m.optionalIE(0x27, &serviceAreaList);
        break;
    case 16:
        m.optionalIE(0x5E, &t3512Value);
        break;
    case 17:
        m.optionalIE(0x5D, &non3gppDeRegistrationTimerValue);
        break;
    case 18:
        m.optionalIE(0x16, &t3502Value);
        break;
    case 19:
        m.optionalIE(0x34, &emergencyNumberList);
        break;
    case 20:
        m.optionalIE(0x7A, &extendedEmergencyNumberList);
        break;
    case 21:
        m.optionalIE(0x73, &sorTransparentContainer);
        break;
    case 22:
        m.optionalIE(0x78, &eapMessage);
        break;
    case 23:
        m.optionalIE(0x76, &operatorDefinedAccessCategoryDefinitions);
        break;
    case 24:
        m.optionalIE(0x51, &negotiatedDrxParameters);
        break;
    default:
        break;
    }
}

void RegistrationAccept::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue(&registrationResult, bytes);
        break;
    case 1:
        m.corruptOptionalIE1(0x9, &networkSlicingIndication, bytes);
        break;
    case 2:
        m.corruptOptionalIE1(0xA, &nssaiInclusionMode, bytes);
        break;
    case 3:
        m.corruptOptionalIE1(0xB, &micoIndication, bytes);
        break;
    case 4:
        m.corruptOptionalIE(0x77, &mobileIdentity, bytes);
        break;
    case 5:
        m.corruptOptionalIE(0x4A, &equivalentPLMNs, bytes);
        break;
    case 6:
        m.corruptOptionalIE(0x54, &taiList, bytes);
        break;
    case 7:
        m.corruptOptionalIE(0x15, &allowedNSSAI, bytes);
        break;
    case 8:
        m.corruptOptionalIE(0x11, &rejectedNSSAI, bytes);
        break;
    case 9:
        m.corruptOptionalIE(0x31, &configuredNSSAI, bytes);
        break;
    case 10:
        m.corruptOptionalIE(0x21, &networkFeatureSupport, bytes);
        break;
    case 11:
        m.corruptOptionalIE(0x50, &pduSessionStatus, bytes);
        break;
    case 12:
        m.corruptOptionalIE(0x26, &pduSessionReactivationResult, bytes);
        break;
    case 13:
        m.corruptOptionalIE(0x72, &pduSessionReactivationResultErrorCause, bytes);
        break;
    case 14:
        m.corruptOptionalIE(0x79, &ladnInformation, bytes);
        break;
    case 15:
        m.corruptOptionalIE(0x27, &serviceAreaList, bytes);
        break;
    case 16:
        m.corruptOptionalIE(0x5E, &t3512Value, bytes);
        break;
    case 17:
        m.corruptOptionalIE(0x5D, &non3gppDeRegistrationTimerValue, bytes);
        break;
    case 18:
        m.corruptOptionalIE(0x16, &t3502Value, bytes);
        break;
    case 19:
        m.corruptOptionalIE(0x34, &emergencyNumberList, bytes);
        break;
    case 20:
        m.corruptOptionalIE(0x7A, &extendedEmergencyNumberList, bytes);
        break;
    case 21:
        m.corruptOptionalIE(0x73, &sorTransparentContainer, bytes);
        break;
    case 22:
        m.corruptOptionalIE(0x78, &eapMessage, bytes);
        break;
    case 23:
        m.corruptOptionalIE(0x76, &operatorDefinedAccessCategoryDefinitions, bytes);
        break;
    case 24:
        m.corruptOptionalIE(0x51, &negotiatedDrxParameters, bytes);
        break;
    default:
        break;
    }
}

void RegistrationAccept::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        m.omitOptionalIE1(&networkSlicingIndication);
        break;
    case 2:
        m.omitOptionalIE1(&nssaiInclusionMode);
        break;
    case 3:
        m.omitOptionalIE1(&micoIndication);
        break;
    case 4:
        m.omitOptionalIE(&mobileIdentity);
        break;
    case 5:
        m.omitOptionalIE(&equivalentPLMNs);
        break;
    case 6:
        m.omitOptionalIE(&taiList);
        break;
    case 7:
        m.omitOptionalIE(&allowedNSSAI);
        break;
    case 8:
        m.omitOptionalIE(&rejectedNSSAI);
        break;
    case 9:
        m.omitOptionalIE(&configuredNSSAI);
        break;
    case 10:
        m.omitOptionalIE(&networkFeatureSupport);
        break;
    case 11:
        m.omitOptionalIE(&pduSessionStatus);
        break;
    case 12:
        m.omitOptionalIE(&pduSessionReactivationResult);
        break;
    case 13:
        m.omitOptionalIE(&pduSessionReactivationResultErrorCause);
        break;
    case 14:
        m.omitOptionalIE(&ladnInformation);
        break;
    case 15:
        m.omitOptionalIE(&serviceAreaList);
        break;
    case 16:
        m.omitOptionalIE(&t3512Value);
        break;
    case 17:
        m.omitOptionalIE(&non3gppDeRegistrationTimerValue);
        break;
    case 18:
        m.omitOptionalIE(&t3502Value);
        break;
    case 19:
        m.omitOptionalIE(&emergencyNumberList);
        break;
    case 20:
        m.omitOptionalIE(&extendedEmergencyNumberList);
        break;
    case 21:
        m.omitOptionalIE(&sorTransparentContainer);
        break;
    case 22:
        m.omitOptionalIE(&eapMessage);
        break;
    case 23:
        m.omitOptionalIE(&operatorDefinedAccessCategoryDefinitions);
        break;
    case 24:
        m.omitOptionalIE(&negotiatedDrxParameters);
        break;
    default:
        break;
    }
}

void RegistrationAccept::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        m.setIELength(&registrationResult, fakeLen);
        break;
    case 1:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 2:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 3:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 4:
        m.setIELengthOptional(&mobileIdentity, fakeLen);
        break;
    case 5:
        m.setIELengthOptional(&equivalentPLMNs, fakeLen);
        break;
    case 6:
        m.setIELengthOptional(&taiList, fakeLen);
        break;
    case 7:
        m.setIELengthOptional(&allowedNSSAI, fakeLen);
        break;
    case 8:
        m.setIELengthOptional(&rejectedNSSAI, fakeLen);
        break;
    case 9:
        m.setIELengthOptional(&configuredNSSAI, fakeLen);
        break;
    case 10:
        m.setIELengthOptional(&networkFeatureSupport, fakeLen);
        break;
    case 11:
        m.setIELengthOptional(&pduSessionStatus, fakeLen);
        break;
    case 12:
        m.setIELengthOptional(&pduSessionReactivationResult, fakeLen);
        break;
    case 13:
        m.setIELengthOptional(&pduSessionReactivationResultErrorCause, fakeLen);
        break;
    case 14:
        m.setIELengthOptional(&ladnInformation, fakeLen);
        break;
    case 15:
        m.setIELengthOptional(&serviceAreaList, fakeLen);
        break;
    case 16:
        m.setIELengthOptional(&t3512Value, fakeLen);
        break;
    case 17:
        m.setIELengthOptional(&non3gppDeRegistrationTimerValue, fakeLen);
        break;
    case 18:
        m.setIELengthOptional(&t3502Value, fakeLen);
        break;
    case 19:
        m.setIELengthOptional(&emergencyNumberList, fakeLen);
        break;
    case 20:
        m.setIELengthOptional(&extendedEmergencyNumberList, fakeLen);
        break;
    case 21:
        m.setIELengthOptional(&sorTransparentContainer, fakeLen);
        break;
    case 22:
        m.setIELengthOptional(&eapMessage, fakeLen);
        break;
    case 23:
        m.setIELengthOptional(&operatorDefinedAccessCategoryDefinitions, fakeLen);
        break;
    case 24:
        m.setIELengthOptional(&negotiatedDrxParameters, fakeLen);
        break;
    default:
        break;
    }
}


RegistrationComplete::RegistrationComplete()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::REGISTRATION_COMPLETE;
}

void RegistrationComplete::onBuild(NasMessageBuilder &b)
{
    b.optionalIE(0x73, &sorTransparentContainer);
}

void RegistrationComplete::onMutate(NasMessageMutator &m)
{
    if (generate_bit(1))
        m.optionalIE(0x73, &sorTransparentContainer);
}

void RegistrationComplete::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptOptionalIE(0x73, &sorTransparentContainer, bytes);
        break;
    default:
        break;
    }
}

void RegistrationComplete::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        m.omitOptionalIE(&sorTransparentContainer);
        break;
    default:
        break;
    }
}

void RegistrationComplete::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        m.setIELengthOptional(&sorTransparentContainer, fakeLen);
        break;
    default:
        break;
    }
}


RegistrationReject::RegistrationReject()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::REGISTRATION_REJECT;
}

void RegistrationReject::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE(&mmCause);
    b.optionalIE(0x5F, &t3346value);
    b.optionalIE(0x16, &t3502value);
    b.optionalIE(0x78, &eapMessage);
}

void RegistrationReject::onMutate(NasMessageMutator &m)
{
    int i = generate_int(5);
    switch (i)
    {
    case 0:
        m.mandatoryIE(&mmCause);
        break;
    case 1:
        m.optionalIE(0x5F, &t3346value);
        break;
    case 2:
        m.optionalIE(0x16, &t3502value);
        break;
    case 3:
        m.optionalIE(0x78, &eapMessage);
        break;
    default:
        break;
    }
}

void RegistrationReject::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue(&mmCause, bytes);
        break;
    case 1:
        m.corruptOptionalIE(0x5F, &t3346value, bytes);
        break;
    case 2:
        m.corruptOptionalIE(0x16, &t3502value, bytes);
        break;
    case 3:
        m.corruptOptionalIE(0x78, &eapMessage, bytes);
        break;
    default:
        break;
    }
}

void RegistrationReject::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        m.omitOptionalIE(&t3346value);
        break;
    case 2:
        m.omitOptionalIE(&t3502value);
        break;
    case 3:
        m.omitOptionalIE(&eapMessage);
        break;
    default:
        break;
    }
}

void RegistrationReject::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        m.setIELengthOptional(&t3346value, fakeLen);
        break;
    case 2:
        m.setIELengthOptional(&t3502value, fakeLen);
        break;
    case 3:
        m.setIELengthOptional(&eapMessage, fakeLen);
        break;
    default:
        break;
    }
}


RegistrationRequest::RegistrationRequest()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::REGISTRATION_REQUEST;
}

void RegistrationRequest::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE1(&nasKeySetIdentifier, &registrationType);
    b.mandatoryIE(&mobileIdentity);
    b.optionalIE1(0xC, &nonCurrentNgKsi);
    b.optionalIE1(0xB, &micoIndication);
    b.optionalIE1(0x9, &networkSlicingIndication);
    b.optionalIE(0x10, &mmCapability);
    b.optionalIE(0x2E, &ueSecurityCapability);
    b.optionalIE(0x2F, &requestedNSSAI);
    b.optionalIE(0x52, &lastVisitedRegisteredTai);
    b.optionalIE(0x17, &s1UeNetworkCapability);
    b.optionalIE(0x40, &uplinkDataStatus);
    b.optionalIE(0x50, &pduSessionStatus);
    b.optionalIE(0x2B, &ueStatus);
    b.optionalIE(0x77, &additionalGuti);
    b.optionalIE(0x25, &allowedPduSessionStatus);
    b.optionalIE(0x18, &uesUsageSetting);
    b.optionalIE(0x51, &requestedDrxParameters);
    b.optionalIE(0x70, &epsNasMessageContainer);
    b.optionalIE(0x7E, &ladnIndication);
    b.optionalIE(0x7B, &payloadContainer);
    b.optionalIE(0x53, &updateType);
    b.optionalIE(0x71, &nasMessageContainer);
}

void RegistrationRequest::onMutate(NasMessageMutator &m)
{
    int i = generate_int(23);
    printf("mutate RegistrationRequest, i = %d\n", i);
    switch (i)
    {
    case 0:
        m.mandatoryIE1(&nasKeySetIdentifier, &registrationType);
        break;
    case 1:
        m.mandatoryIE(&mobileIdentity);
        break;
    case 2:
        m.optionalIE1(0xC, &nonCurrentNgKsi);
        break;
    case 3:
        m.optionalIE1(0xB, &micoIndication);
        break;
    case 4:
        m.optionalIE1(0x9, &networkSlicingIndication);
        break;
    case 5:
        m.optionalIE(0x10, &mmCapability);
        break;
    case 6:
        m.optionalIE(0x2E, &ueSecurityCapability);
        break;
    case 7:
        m.optionalIE(0x2F, &requestedNSSAI);
        break;
    case 8:
        m.optionalIE(0x52, &lastVisitedRegisteredTai);
        break;
    case 9:
        m.optionalIE(0x17, &s1UeNetworkCapability);
        break;
    case 10:
        m.optionalIE(0x40, &uplinkDataStatus);
        break;
    case 11:
        m.optionalIE(0x50, &pduSessionStatus);
        break;
    case 12:
        m.optionalIE(0x2B, &ueStatus);
        break;
    case 13:
        m.optionalIE(0x77, &additionalGuti);
        break;
    case 14:
        m.optionalIE(0x25, &allowedPduSessionStatus);
        break;
    case 15:
        m.optionalIE(0x18, &uesUsageSetting);
        break;
    case 16:
        m.optionalIE(0x51, &requestedDrxParameters);
        break;
    case 17:
        m.optionalIE(0x70, &epsNasMessageContainer);
        break;
    case 18:
        m.optionalIE(0x7E, &ladnIndication);
        break;
    case 19:
        m.optionalIE(0x7B, &payloadContainer);
        break;
    case 20:
        m.optionalIE(0x53, &updateType);
        break;
    case 21:
        m.optionalIE(0x71, &nasMessageContainer);
        break;
    default:
        break;
    }
}

void RegistrationRequest::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue1(&nasKeySetIdentifier, &registrationType, bytes);
        break;
    case 1:
        m.corruptValue(&mobileIdentity, bytes);
        break;
    case 2:
        m.corruptOptionalIE1(0xC, &nonCurrentNgKsi, bytes);
        break;
    case 3:
        m.corruptOptionalIE1(0xB, &micoIndication, bytes);
        break;
    case 4:
        m.corruptOptionalIE1(0x9, &networkSlicingIndication, bytes);
        break;
    case 5:
        m.corruptOptionalIE(0x10, &mmCapability, bytes);
        break;
    case 6:
        m.corruptOptionalIE(0x2E, &ueSecurityCapability, bytes);
        break;
    case 7:
        m.corruptOptionalIE(0x2F, &requestedNSSAI, bytes);
        break;
    case 8:
        m.corruptOptionalIE(0x52, &lastVisitedRegisteredTai, bytes);
        break;
    case 9:
        m.corruptOptionalIE(0x17, &s1UeNetworkCapability, bytes);
        break;
    case 10:
        m.corruptOptionalIE(0x40, &uplinkDataStatus, bytes);
        break;
    case 11:
        m.corruptOptionalIE(0x50, &pduSessionStatus, bytes);
        break;
    case 12:
        m.corruptOptionalIE(0x2B, &ueStatus, bytes);
        break;
    case 13:
        m.corruptOptionalIE(0x77, &additionalGuti, bytes);
        break;
    case 14:
        m.corruptOptionalIE(0x25, &allowedPduSessionStatus, bytes);
        break;
    case 15:
        m.corruptOptionalIE(0x18, &uesUsageSetting, bytes);
        break;
    case 16:
        m.corruptOptionalIE(0x51, &requestedDrxParameters, bytes);
        break;
    case 17:
        m.corruptOptionalIE(0x70, &epsNasMessageContainer, bytes);
        break;
    case 18:
        m.corruptOptionalIE(0x7E, &ladnIndication, bytes);
        break;
    case 19:
        m.corruptOptionalIE(0x7B, &payloadContainer, bytes);
        break;
    case 20:
        m.corruptOptionalIE(0x53, &updateType, bytes);
        break;
    case 21:
        m.corruptOptionalIE(0x71, &nasMessageContainer, bytes);
        break;
    default:
        break;
    }
}

void RegistrationRequest::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        this->omitMandatory.insert(1);
        break;
    case 2:
        m.omitOptionalIE1(&nonCurrentNgKsi);
        break;
    case 3:
        m.omitOptionalIE1(&micoIndication);
        break;
    case 4:
        m.omitOptionalIE1(&networkSlicingIndication);
        break;
    case 5:
        m.omitOptionalIE(&mmCapability);
        break;
    case 6:
        m.omitOptionalIE(&ueSecurityCapability);
        break;
    case 7:
        m.omitOptionalIE(&requestedNSSAI);
        break;
    case 8:
        m.omitOptionalIE(&lastVisitedRegisteredTai);
        break;
    case 9:
        m.omitOptionalIE(&s1UeNetworkCapability);
        break;
    case 10:
        m.omitOptionalIE(&uplinkDataStatus);
        break;
    case 11:
        m.omitOptionalIE(&pduSessionStatus);
        break;
    case 12:
        m.omitOptionalIE(&ueStatus);
        break;
    case 13:
        m.omitOptionalIE(&additionalGuti);
        break;
    case 14:
        m.omitOptionalIE(&allowedPduSessionStatus);
        break;
    case 15:
        m.omitOptionalIE(&uesUsageSetting);
        break;
    case 16:
        m.omitOptionalIE(&requestedDrxParameters);
        break;
    case 17:
        m.omitOptionalIE(&epsNasMessageContainer);
        break;
    case 18:
        m.omitOptionalIE(&ladnIndication);
        break;
    case 19:
        m.omitOptionalIE(&payloadContainer);
        break;
    case 20:
        m.omitOptionalIE(&updateType);
        break;
    case 21:
        m.omitOptionalIE(&nasMessageContainer);
        break;
    default:
        break;
    }
}

void RegistrationRequest::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        m.setIELength(&mobileIdentity, fakeLen);
        break;
    case 2:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 3:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 4:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 5:
        m.setIELengthOptional(&mmCapability, fakeLen);
        break;
    case 6:
        m.setIELengthOptional(&ueSecurityCapability, fakeLen);
        break;
    case 7:
        m.setIELengthOptional(&requestedNSSAI, fakeLen);
        break;
    case 8:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 9:
        m.setIELengthOptional(&s1UeNetworkCapability, fakeLen);
        break;
    case 10:
        m.setIELengthOptional(&uplinkDataStatus, fakeLen);
        break;
    case 11:
        m.setIELengthOptional(&pduSessionStatus, fakeLen);
        break;
    case 12:
        m.setIELengthOptional(&ueStatus, fakeLen);
        break;
    case 13:
        m.setIELengthOptional(&additionalGuti, fakeLen);
        break;
    case 14:
        m.setIELengthOptional(&allowedPduSessionStatus, fakeLen);
        break;
    case 15:
        m.setIELengthOptional(&uesUsageSetting, fakeLen);
        break;
    case 16:
        m.setIELengthOptional(&requestedDrxParameters, fakeLen);
        break;
    case 17:
        m.setIELengthOptional(&epsNasMessageContainer, fakeLen);
        break;
    case 18:
        m.setIELengthOptional(&ladnIndication, fakeLen);
        break;
    case 19:
        m.setIELengthOptional(&payloadContainer, fakeLen);
        break;
    case 20:
        m.setIELengthOptional(&updateType, fakeLen);
        break;
    case 21:
        m.setIELengthOptional(&nasMessageContainer, fakeLen);
        break;
    default:
        break;
    }
}


SecurityModeCommand::SecurityModeCommand()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::SECURITY_MODE_COMMAND;
}

void SecurityModeCommand::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE(&selectedNasSecurityAlgorithms);
    b.mandatoryIE1(&ngKsi);
    b.mandatoryIE(&replayedUeSecurityCapabilities);
    b.optionalIE1(0xE, &imeiSvRequest);
    b.optionalIE(0x57, &epsNasSecurityAlgorithms);
    b.optionalIE(0x36, &additional5gSecurityInformation);
    b.optionalIE(0x78, &eapMessage);
    b.optionalIE(0x38, &abba);
    b.optionalIE(0x19, &replayedS1UeNetworkCapability);
}

void SecurityModeCommand::onMutate(NasMessageMutator &m)
{
    int i = generate_int(10);
    switch (i)
    {
    case 0:
        m.mandatoryIE(&selectedNasSecurityAlgorithms);
        break;
    case 1:
        m.mandatoryIE1(&ngKsi);
        break;
    case 2:
        m.mandatoryIE(&replayedUeSecurityCapabilities);
        break;
    case 3:
        m.optionalIE1(0xE, &imeiSvRequest);
        break;
    case 4:
        m.optionalIE(0x57, &epsNasSecurityAlgorithms);
        break;
    case 5:
        m.optionalIE(0x36, &additional5gSecurityInformation);
        break;
    case 6:
        m.optionalIE(0x78, &eapMessage);
        break;
    case 7:
        m.optionalIE(0x38, &abba);
        break;
    case 8:
        m.optionalIE(0x19, &replayedS1UeNetworkCapability);
        break;
    default:
        break;
    }
}

void SecurityModeCommand::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue(&selectedNasSecurityAlgorithms, bytes);
        break;
    case 1:
        m.corruptValue1(&ngKsi, bytes);
        break;
    case 2:
        m.corruptValue(&replayedUeSecurityCapabilities, bytes);
        break;
    case 3:
        m.corruptOptionalIE1(0xE, &imeiSvRequest, bytes);
        break;
    case 4:
        m.corruptOptionalIE(0x57, &epsNasSecurityAlgorithms, bytes);
        break;
    case 5:
        m.corruptOptionalIE(0x36, &additional5gSecurityInformation, bytes);
        break;
    case 6:
        m.corruptOptionalIE(0x78, &eapMessage, bytes);
        break;
    case 7:
        m.corruptOptionalIE(0x38, &abba, bytes);
        break;
    case 8:
        m.corruptOptionalIE(0x19, &replayedS1UeNetworkCapability, bytes);
        break;
    default:
        break;
    }
}

void SecurityModeCommand::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        this->omitMandatory.insert(1);
        break;
    case 2:
        this->omitMandatory.insert(2);
        break;
    case 3:
        m.omitOptionalIE1(&imeiSvRequest);
        break;
    case 4:
        m.omitOptionalIE(&epsNasSecurityAlgorithms);
        break;
    case 5:
        m.omitOptionalIE(&additional5gSecurityInformation);
        break;
    case 6:
        m.omitOptionalIE(&eapMessage);
        break;
    case 7:
        m.omitOptionalIE(&abba);
        break;
    case 8:
        m.omitOptionalIE(&replayedS1UeNetworkCapability);
        break;
    default:
        break;
    }
}

void SecurityModeCommand::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 2:
        m.setIELength(&replayedUeSecurityCapabilities, fakeLen);
        break;
    case 3:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 4:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 5:
        m.setIELengthOptional(&additional5gSecurityInformation, fakeLen);
        break;
    case 6:
        m.setIELengthOptional(&eapMessage, fakeLen);
        break;
    case 7:
        m.setIELengthOptional(&abba, fakeLen);
        break;
    case 8:
        m.setIELengthOptional(&replayedS1UeNetworkCapability, fakeLen);
        break;
    default:
        break;
    }
}


SecurityModeComplete::SecurityModeComplete()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::SECURITY_MODE_COMPLETE;
}

void SecurityModeComplete::onBuild(NasMessageBuilder &b)
{
    b.optionalIE(0x77, &imeiSv);
    b.optionalIE(0x71, &nasMessageContainer);
}

void SecurityModeComplete::onMutate(NasMessageMutator &m)
{
    int i = generate_int(3);
    switch (i)
    {
    case 0:
        m.optionalIE(0x77, &imeiSv);
        break;
    case 1:
        m.optionalIE(0x71, &nasMessageContainer);
        break;
    default:
        break;
    }
}

void SecurityModeComplete::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptOptionalIE(0x77, &imeiSv, bytes);
        break;
    case 1:
        m.corruptOptionalIE(0x71, &nasMessageContainer, bytes);
        break;
    default:
        break;
    }
}

void SecurityModeComplete::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        m.omitOptionalIE(&imeiSv);
        break;
    case 1:
        m.omitOptionalIE(&nasMessageContainer);
        break;
    default:
        break;
    }
}

void SecurityModeComplete::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        m.setIELengthOptional(&imeiSv, fakeLen);
        break;
    case 1:
        m.setIELengthOptional(&nasMessageContainer, fakeLen);
        break;
    default:
        break;
    }
}


SecurityModeReject::SecurityModeReject()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::SECURITY_MODE_REJECT;
}

void SecurityModeReject::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE(&mmCause);
}

void SecurityModeReject::onMutate(NasMessageMutator &m)
{
    if (generate_bit(1))
        m.mandatoryIE(&mmCause);
}

void SecurityModeReject::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue(&mmCause, bytes);
        break;
    default:
        break;
    }
}

void SecurityModeReject::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    default:
        break;
    }
}

void SecurityModeReject::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    default:
        break;
    }
}


ServiceAccept::ServiceAccept()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::SERVICE_ACCEPT;
}

void ServiceAccept::onBuild(NasMessageBuilder &b)
{
    b.optionalIE(0x50, &pduSessionStatus);
    b.optionalIE(0x26, &pduSessionReactivationResult);
    b.optionalIE(0x72, &pduSessionReactivationResultErrorCause);
    b.optionalIE(0x78, &eapMessage);
}

void ServiceAccept::onMutate(NasMessageMutator &m)
{  
    int i = generate_int(5);
    switch (i)
    {
    case 0:
        m.optionalIE(0x50, &pduSessionStatus);
        break;
    case 1:
        m.optionalIE(0x26, &pduSessionReactivationResult);
        break;
    case 2:
        m.optionalIE(0x72, &pduSessionReactivationResultErrorCause);
        break;
    case 3:
        m.optionalIE(0x78, &eapMessage);
        break;
    default:
        break;
    }
}

void ServiceAccept::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptOptionalIE(0x50, &pduSessionStatus, bytes);
        break;
    case 1:
        m.corruptOptionalIE(0x26, &pduSessionReactivationResult, bytes);
        break;
    case 2:
        m.corruptOptionalIE(0x72, &pduSessionReactivationResultErrorCause, bytes);
        break;
    case 3:
        m.corruptOptionalIE(0x78, &eapMessage, bytes);
        break;
    default:
        break;
    }
}

void ServiceAccept::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        m.omitOptionalIE(&pduSessionStatus);
        break;
    case 1:
        m.omitOptionalIE(&pduSessionReactivationResult);
        break;
    case 2:
        m.omitOptionalIE(&pduSessionReactivationResultErrorCause);
        break;
    case 3:
        m.omitOptionalIE(&eapMessage);
        break;
    default:
        break;
    }
}

void ServiceAccept::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        m.setIELengthOptional(&pduSessionStatus, fakeLen);
        break;
    case 1:
        m.setIELengthOptional(&pduSessionReactivationResult, fakeLen);
        break;
    case 2:
        m.setIELengthOptional(&pduSessionReactivationResultErrorCause, fakeLen);
        break;
    case 3:
        m.setIELengthOptional(&eapMessage, fakeLen);
        break;
    default:
        break;
    }
}


ServiceReject::ServiceReject()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::SERVICE_REJECT;
}

void ServiceReject::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE(&mmCause);
    b.optionalIE(0x50, &pduSessionStatus);
    b.optionalIE(0x5f, &t3346Value);
    b.optionalIE(0x78, &eapMessage);
}

void ServiceReject::onMutate(NasMessageMutator &m)
{
    int i = generate_int(5);
    switch (i)
    {
    case 0:
        m.mandatoryIE(&mmCause);
        break;
    case 1:
        m.optionalIE(0x50, &pduSessionStatus);
        break;
    case 2:
        m.optionalIE(0x5f, &t3346Value);
        break;
    case 3:
        m.optionalIE(0x78, &eapMessage);
        break;
    default:
        break;
    }
}

void ServiceReject::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue(&mmCause, bytes);
        break;
    case 1:
        m.corruptOptionalIE(0x50, &pduSessionStatus, bytes);
        break;
    case 2:
        m.corruptOptionalIE(0x5f, &t3346Value, bytes);
        break;
    case 3:
        m.corruptOptionalIE(0x78, &eapMessage, bytes);
        break;
    default:
        break;
    }
}

void ServiceReject::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        m.omitOptionalIE(&pduSessionStatus);
        break;
    case 2:
        m.omitOptionalIE(&t3346Value);
        break;
    case 3:
        m.omitOptionalIE(&eapMessage);
        break;
    default:
        break;
    }
}

void ServiceReject::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        m.setIELengthOptional(&pduSessionStatus, fakeLen);
        break;
    case 2:
        m.setIELengthOptional(&t3346Value, fakeLen);
        break;
    case 3:
        m.setIELengthOptional(&eapMessage, fakeLen);
        break;
    default:
        break;
    }
}


ServiceRequest::ServiceRequest()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::SERVICE_REQUEST;
}

void ServiceRequest::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE1(&serviceType, &ngKSI);
    b.mandatoryIE(&tmsi);
    b.optionalIE(0x40, &uplinkDataStatus);
    b.optionalIE(0x50, &pduSessionStatus);
    b.optionalIE(0x25, &allowedPduSessionStatus);
    b.optionalIE(0x71, &nasMessageContainer);
}

void ServiceRequest::onMutate(NasMessageMutator &m)
{
    int i = generate_int(7);
    switch (i)
    {
    case 0:
        m.mandatoryIE1(&serviceType, &ngKSI);
        break;
    case 1:
        m.mandatoryIE(&tmsi);
        break;
    case 2:
        m.optionalIE(0x40, &uplinkDataStatus);
        break;
    case 3:
        m.optionalIE(0x50, &pduSessionStatus);
        break;
    case 4:
        m.optionalIE(0x25, &allowedPduSessionStatus);
        break;
    case 5:
        m.optionalIE(0x71, &nasMessageContainer);
        break;
    default:
        break;
    }
}

void ServiceRequest::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue1(&serviceType, &ngKSI, bytes);
        break;
    case 1:
        m.corruptValue(&tmsi, bytes);
        break;
    case 2:
        m.corruptOptionalIE(0x40, &uplinkDataStatus, bytes);
        break;
    case 3:
        m.corruptOptionalIE(0x50, &pduSessionStatus, bytes);
        break;
    case 4:
        m.corruptOptionalIE(0x25, &allowedPduSessionStatus, bytes);
        break;
    case 5:
        m.corruptOptionalIE(0x71, &nasMessageContainer, bytes);
        break;
    default:
        break;
    }
}

void ServiceRequest::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        this->omitMandatory.insert(1);
        break;
    case 2:
        m.omitOptionalIE(&uplinkDataStatus);
        break;
    case 3:
        m.omitOptionalIE(&pduSessionStatus);
        break;
    case 4:
        m.omitOptionalIE(&allowedPduSessionStatus);
        break;
    case 5:
        m.omitOptionalIE(&nasMessageContainer);
        break;
    default:
        break;
    }
}

void ServiceRequest::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        m.setIELength(&tmsi, fakeLen);
        break;
    case 2:
        m.setIELengthOptional(&uplinkDataStatus, fakeLen);
        break;
    case 3:
        m.setIELengthOptional(&pduSessionStatus, fakeLen);
        break;
    case 4:
        m.setIELengthOptional(&allowedPduSessionStatus, fakeLen);
        break;
    case 5:
        m.setIELengthOptional(&nasMessageContainer, fakeLen);
        break;
    default:
        break;
    }
}


UlNasTransport::UlNasTransport()
{
    epd = EExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;
    sht = ESecurityHeaderType::NOT_PROTECTED;
    messageType = EMessageType::UL_NAS_TRANSPORT;
}

void UlNasTransport::onBuild(NasMessageBuilder &b)
{
    b.mandatoryIE1(&payloadContainerType);
    b.mandatoryIE(&payloadContainer);
    b.optionalIE(0x12, &pduSessionId);
    b.optionalIE(0x59, &oldPduSessionId);
    b.optionalIE1(0x8, &requestType);
    b.optionalIE(0x22, &sNssai);
    b.optionalIE(0x25, &dnn);
    b.optionalIE(0x24, &additionalInformation);
}

void UlNasTransport::onMutate(NasMessageMutator &m)
{
    int i = generate_int(9);
    switch (i)
    {
    case 0:
        m.mandatoryIE1(&payloadContainerType);
        break;
    case 1:
        m.mandatoryIE(&payloadContainer);
        break;
    case 2:
        m.optionalIE(0x12, &pduSessionId);
        break;
    case 3:
        m.optionalIE(0x59, &oldPduSessionId);
        break;
    case 4:
        m.optionalIE1(0x8, &requestType);
        break;
    case 5:
        m.optionalIE(0x22, &sNssai);
        break;
    case 6:
        m.optionalIE(0x25, &dnn);
        break;
    case 7:
        m.optionalIE(0x24, &additionalInformation);
        break;
    default:
        break;
    }
}

void UlNasTransport::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptValue1(&payloadContainerType, bytes);
        break;
    case 1:
        m.corruptValue(&payloadContainer, bytes);
        break;
    case 2:
        m.corruptOptionalIE(0x12, &pduSessionId, bytes);
        break;
    case 3:
        m.corruptOptionalIE(0x59, &oldPduSessionId, bytes);
        break;
    case 4:
        m.corruptOptionalIE1(0x8, &requestType, bytes);
        break;
    case 5:
        m.corruptOptionalIE(0x22, &sNssai, bytes);
        break;
    case 6:
        m.corruptOptionalIE(0x25, &dnn, bytes);
        break;
    case 7:
        m.corruptOptionalIE(0x24, &additionalInformation, bytes);
        break;
    default:
        break;
    }
}

void UlNasTransport::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        this->omitMandatory.insert(0);
        break;
    case 1:
        this->omitMandatory.insert(1);
        break;
    case 2:
        m.omitOptionalIE(&pduSessionId);
        break;
    case 3:
        m.omitOptionalIE(&oldPduSessionId);
        break;
    case 4:
        m.omitOptionalIE1(&requestType);
        break;
    case 5:
        m.omitOptionalIE(&sNssai);
        break;
    case 6:
        m.omitOptionalIE(&dnn);
        break;
    case 7:
        m.omitOptionalIE(&additionalInformation);
        break;
    default:
        break;
    }
}

void UlNasTransport::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 1:
        m.setIELength(&payloadContainer, fakeLen);
        break;
    case 2:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 3:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 4:
        // IE1/IE2/IE3: no length prefix, no-op
        break;
    case 5:
        m.setIELengthOptional(&sNssai, fakeLen);
        break;
    case 6:
        m.setIELengthOptional(&dnn, fakeLen);
        break;
    case 7:
        m.setIELengthOptional(&additionalInformation, fakeLen);
        break;
    default:
        break;
    }
}


void AuthenticationResponse::onCorrupt(NasMessageMutator &m, int ieIndex, const OctetString &bytes)
{
    switch (ieIndex)
    {
    case 0:
        m.corruptOptionalIE(0x2D, &authenticationResponseParameter, bytes);
        break;
    case 1:
        m.corruptOptionalIE(0x78, &eapMessage, bytes);
        break;
    default:
        break;
    }
}

void AuthenticationResponse::onOmit(NasMessageMutator &m, int ieIndex)
{
    switch (ieIndex)
    {
    case 0:
        m.omitOptionalIE(&authenticationResponseParameter);
        break;
    case 1:
        m.omitOptionalIE(&eapMessage);
        break;
    default:
        break;
    }
}

void AuthenticationResponse::onSetLength(NasMessageMutator &m, int ieIndex, int fakeLen)
{
    switch (ieIndex)
    {
    case 0:
        m.setIELengthOptional(&authenticationResponseParameter, fakeLen);
        break;
    case 1:
        m.setIELengthOptional(&eapMessage, fakeLen);
        break;
    default:
        break;
    }
}


} // namespace nas

namespace nas {

// corruptValue implementations
} // namespace nas

