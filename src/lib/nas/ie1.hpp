//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include "base.hpp"
#include "enums.hpp"

#include <utils/octet_string.hpp>
#include <utils/octet_view.hpp>

namespace nas
{

struct IE5gsIdentityType : InformationElement1
{
    EIdentityType value{};

    IE5gsIdentityType() = default;
    explicit IE5gsIdentityType(EIdentityType value);

    static IE5gsIdentityType Decode(int val);
    static int Encode(const IE5gsIdentityType &ie);
    static void Mutate(IE5gsIdentityType &ie);
    static void Corrupt(IE5gsIdentityType &ie, int val);
};

struct IE5gsRegistrationType : InformationElement1
{
    EFollowOnRequest followOnRequestPending{};
    ERegistrationType registrationType{};

    IE5gsRegistrationType() = default;
    IE5gsRegistrationType(EFollowOnRequest followOnRequestPending, ERegistrationType registrationType);

    static IE5gsRegistrationType Decode(int val);
    static int Encode(const IE5gsRegistrationType &ie);
    static void Mutate(IE5gsRegistrationType &ie);
    static void Corrupt(IE5gsRegistrationType &ie, int val);
};

struct IEAccessType : InformationElement1
{
    EAccessType value{};

    IEAccessType() = default;
    explicit IEAccessType(EAccessType value);

    static IEAccessType Decode(int val);
    static int Encode(const IEAccessType &ie);
    static void Mutate(IEAccessType &ie);
    static void Corrupt(IEAccessType &ie, int val);
};

struct IEAllowedSscMode : InformationElement1
{
    ESsc1 ssc1{};
    ESsc2 ssc2{};
    ESsc3 ssc3{};

    IEAllowedSscMode() = default;
    IEAllowedSscMode(ESsc1 ssc1, ESsc2 ssc2, ESsc3 ssc3);

    static IEAllowedSscMode Decode(int val);
    static int Encode(const IEAllowedSscMode &ie);
    static void Mutate(IEAllowedSscMode &ie);
    static void Corrupt(IEAllowedSscMode &ie, int val);
};

struct IEAlwaysOnPduSessionIndication : InformationElement1
{
    EAlwaysOnPduSessionIndication value{};

    IEAlwaysOnPduSessionIndication() = default;
    explicit IEAlwaysOnPduSessionIndication(EAlwaysOnPduSessionIndication value);

    static IEAlwaysOnPduSessionIndication Decode(int val);
    static int Encode(const IEAlwaysOnPduSessionIndication &ie);
    static void Mutate(IEAlwaysOnPduSessionIndication &ie);
    static void Corrupt(IEAlwaysOnPduSessionIndication &ie, int val);
};

struct IEAlwaysOnPduSessionRequested : InformationElement1
{
    EAlwaysOnPduSessionRequested value{};

    IEAlwaysOnPduSessionRequested() = default;
    explicit IEAlwaysOnPduSessionRequested(EAlwaysOnPduSessionRequested value);

    static IEAlwaysOnPduSessionRequested Decode(int val);
    static int Encode(const IEAlwaysOnPduSessionRequested &ie);
    static void Mutate(IEAlwaysOnPduSessionRequested &ie);
    static void Corrupt(IEAlwaysOnPduSessionRequested &ie, int val);
};

struct IEConfigurationUpdateIndication : InformationElement1
{
    EAcknowledgement ack{};
    ERegistrationRequested red{};

    IEConfigurationUpdateIndication() = default;
    IEConfigurationUpdateIndication(EAcknowledgement ack, ERegistrationRequested red);

    static IEConfigurationUpdateIndication Decode(int val);
    static int Encode(const IEConfigurationUpdateIndication &ie);
    static void Mutate(IEConfigurationUpdateIndication &ie);
    static void Corrupt(IEConfigurationUpdateIndication &ie, int val);
};

struct IEDeRegistrationType : InformationElement1
{
    EDeRegistrationAccessType accessType{};
    EReRegistrationRequired reRegistrationRequired{}; // This bit is spare in UE to Network direction
    ESwitchOff switchOff{};

    IEDeRegistrationType() = default;
    IEDeRegistrationType(EDeRegistrationAccessType accessType, EReRegistrationRequired reRegistrationRequired,
                         ESwitchOff switchOff);

    static IEDeRegistrationType Decode(int val);
    static int Encode(const IEDeRegistrationType &ie);
    static void Mutate(IEDeRegistrationType &ie);
    static void Corrupt(IEDeRegistrationType &ie, int val);
};

struct IEImeiSvRequest : InformationElement1
{
    EImeiSvRequest imeiSvRequest{};

    IEImeiSvRequest() = default;
    explicit IEImeiSvRequest(EImeiSvRequest imeiSvRequest);

    static IEImeiSvRequest Decode(int val);
    static int Encode(const IEImeiSvRequest &ie);
    static void Mutate(IEImeiSvRequest &ie);
    static void Corrupt(IEImeiSvRequest &ie, int val);
};

struct IEMicoIndication : InformationElement1
{
    ERegistrationAreaAllocationIndication raai{};

    IEMicoIndication() = default;
    explicit IEMicoIndication(ERegistrationAreaAllocationIndication raai);

    static IEMicoIndication Decode(int val);
    static int Encode(const IEMicoIndication &ie);
    static void Mutate(IEMicoIndication &ie);
    static void Corrupt(IEMicoIndication &ie, int val);
};

struct IENasKeySetIdentifier : InformationElement1
{
    static constexpr const int NOT_AVAILABLE_OR_RESERVED = 0b111;

    ETypeOfSecurityContext tsc{};
    int ksi = NOT_AVAILABLE_OR_RESERVED;

    IENasKeySetIdentifier() = default;
    IENasKeySetIdentifier(ETypeOfSecurityContext tsc, int ksi);

    static IENasKeySetIdentifier Decode(int val);
    static int Encode(const IENasKeySetIdentifier &ie);
    static void Mutate(IENasKeySetIdentifier &ie);
    static void Corrupt(IENasKeySetIdentifier &ie, int val);
};

struct IENetworkSlicingIndication : InformationElement1
{
    ENetworkSlicingSubscriptionChangeIndication nssci{}; // This is spare if dir is UE->NW
    EDefaultConfiguredNssaiIndication dcni{};            // This is spare if dir is NW->UE

    IENetworkSlicingIndication() = default;
    IENetworkSlicingIndication(ENetworkSlicingSubscriptionChangeIndication nssci,
                               EDefaultConfiguredNssaiIndication dcni);

    static IENetworkSlicingIndication Decode(int val);
    static int Encode(const IENetworkSlicingIndication &ie);
    static void Mutate(IENetworkSlicingIndication &ie);
    static void Corrupt(IENetworkSlicingIndication &ie, int val);
};

struct IENssaiInclusionMode : InformationElement1
{
    ENssaiInclusionMode nssaiInclusionMode{};

    IENssaiInclusionMode() = default;
    explicit IENssaiInclusionMode(ENssaiInclusionMode nssaiInclusionMode);

    static IENssaiInclusionMode Decode(int val);
    static int Encode(const IENssaiInclusionMode &ie);
    static void Mutate(IENssaiInclusionMode &ie);
    static void Corrupt(IENssaiInclusionMode &ie, int val);
};

struct IEPayloadContainerType : InformationElement1
{
    EPayloadContainerType payloadContainerType{};

    IEPayloadContainerType() = default;
    explicit IEPayloadContainerType(EPayloadContainerType payloadContainerType);

    static IEPayloadContainerType Decode(int val);
    static int Encode(const IEPayloadContainerType &ie);
    static void Mutate(IEPayloadContainerType &ie);
    static void Corrupt(IEPayloadContainerType &ie, int val);
};

struct IEPduSessionType : InformationElement1
{
    EPduSessionType pduSessionType{};

    IEPduSessionType() = default;
    explicit IEPduSessionType(EPduSessionType pduSessionType);

    static IEPduSessionType Decode(int val);
    static int Encode(const IEPduSessionType &ie);
    static void Mutate(IEPduSessionType &ie);
    static void Corrupt(IEPduSessionType &ie, int val);
};

struct IERequestType : InformationElement1
{
    ERequestType requestType{};

    IERequestType() = default;
    explicit IERequestType(ERequestType requestType);

    static IERequestType Decode(int val);
    static int Encode(const IERequestType &ie);
    static void Mutate(IERequestType &ie);
    static void Corrupt(IERequestType &ie, int val);
};

struct IEServiceType : InformationElement1
{
    EServiceType serviceType{};

    IEServiceType() = default;
    explicit IEServiceType(EServiceType serviceType);

    static IEServiceType Decode(int val);
    static int Encode(const IEServiceType &ie);
    static void Mutate(IEServiceType &ie);
    static void Corrupt(IEServiceType &ie, int val);
};

struct IESmsIndication : InformationElement1
{
    ESmsAvailabilityIndication sai{};

    IESmsIndication() = default;
    explicit IESmsIndication(ESmsAvailabilityIndication sai);

    static IESmsIndication Decode(int val);
    static int Encode(const IESmsIndication &ie);
    static void Mutate(IESmsIndication &ie);
    static void Corrupt(IESmsIndication &ie, int val);
};

struct IESscMode : InformationElement1
{
    ESscMode sscMode{};

    IESscMode() = default;
    explicit IESscMode(ESscMode sscMode);

    static IESscMode Decode(int val);
    static int Encode(const IESscMode &ie);
    static void Mutate(IESscMode &ie);
    static void Corrupt(IESscMode &ie, int val);
};

} // namespace nas