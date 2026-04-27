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


} // namespace nas

namespace nas {

// corruptValue implementations
} // namespace nas

