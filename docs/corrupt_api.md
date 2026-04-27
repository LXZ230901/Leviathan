# CorruptValue Primitive API

## Overview

`corruptValue` is a structural-level NAS message mutation primitive. It allows an external fuzzer (MutateAgent) to overwrite any specific Information Element (IE) field in any stored NAS message with arbitrary raw bytes, enabling targeted CWE-20 testing: enum out-of-bounds, illegal values, and type confusion attacks.

## Protocol

### Transport

TCP connection to the UE state learner port (default: `45678`).

### Command Format

```
corruptIe_<size>\n
<msgName>:<ieIndex>:<hexBytes>
```

| Field | Description |
|-------|-------------|
| `size` | Number of bytes to read for the data line (recommend 1024) |
| `msgName` | Message name from the supported list below |
| `ieIndex` | 0-based IE index within the message (see per-message tables) |
| `hexBytes` | Raw bytes to inject, as uppercase hex string |

### Example

```
corruptIe_100
registrationRequestIMSI:0:FF
```
Overwrites IE[0] (nasKeySetIdentifier + registrationType) of RegistrationRequest with byte `0xFF`.

## Response

```
{"ret_type":"","ret_msg":"","new_msg":"","sht":0,"secmod":0,"mm_status":"","byte_mut":0}
OK
```

---

## IE Type Reference

Each IE field has an underlying type that determines how `hexBytes` is interpreted:

| IE Type | C++ Base Class | Byte Semantics |
|---------|---------------|----------------|
| **IE1** | `InformationElement1` | 4-bit value (only low nibble of first byte used) |
| **IE2** | `InformationElement2` | Empty (no data) — corrupt is a no-op |
| **IE3** | `InformationElement3` | Variable-length value type (enum, octet, or struct) |
| **IE4** | `InformationElement4` | 1-byte length-prefixed variable-length IE |
| **IE6** | `InformationElement6` | 2-byte length-prefixed variable-length IE |

### corruptValue Method Mapping

| onMutate Pattern | onCorrupt Pattern | Use Case |
|-----------------|-------------------|----------|
| `mandatoryIE(&field)` | `corruptValue(&field, bytes)` | Single IE3/4/6 field |
| `mandatoryIE1(&field)` | `corruptValue1(0, &field, bytes)` | Single IE1 field (4-bit value) |
| `mandatoryIE1(&a, &b)` | `corruptValue1(&a, &b, bytes)` | Compound IE1 (two 4-bit halves) |
| `optionalIE(0xNN, &field)` | `corruptOptionalIE(0xNN, &field, bytes)` | Optional IE3/4/6 (auto-created if absent) |
| `optionalIE1(0xNN, &field)` | `corruptOptionalIE1(0xNN, &field, bytes)` | Optional IE1 (auto-created if absent) |

---

## Supported Messages and IE Indices

### MM Messages (Mobility Management)

#### RegistrationRequest (registrationRequestIMSI / registrationRequestGUTI)

| IE Index | Field(s) | Type | corruptValue Method | Description |
|----------|----------|------|---------------------|-------------|
| 0 | nasKeySetIdentifier + registrationType | IE1 (compound) | corruptValue1(&a, &b, bytes) | 4-bit NAS KSI + 4-bit registration type |
| 1 | mobileIdentity | IE6 | corruptValue(&f, bytes) | SUCI/GUTI/TMSI/IMEI identity |
| 2 | nonCurrentNgKsi | IE1 (optional) | corruptOptionalIE1(0xC, &f, bytes) | Non-current NAS key set identifier |
| 3 | micoIndication | IE1 (optional) | corruptOptionalIE1(0xB, &f, bytes) | MICO mode indication |
| 4 | networkSlicingIndication | IE1 (optional) | corruptOptionalIE1(0x9, &f, bytes) | Network slicing indication |
| 5 | mmCapability | IE4 (optional) | corruptOptionalIE(0x10, &f, bytes) | 5G MM capability |
| 6 | ueSecurityCapability | IE4 (optional) | corruptOptionalIE(0x2E, &f, bytes) | UE security capabilities |
| 7 | requestedNSSAI | IE4 (optional) | corruptOptionalIE(0x2F, &f, bytes) | Requested NSSAI |
| 8 | lastVisitedRegisteredTai | IE4 (optional) | corruptOptionalIE(0x52, &f, bytes) | Last visited TAI |
| 9 | s1UeNetworkCapability | IE4 (optional) | corruptOptionalIE(0x17, &f, bytes) | S1 UE network capability |
| 10 | uplinkDataStatus | IE4 (optional) | corruptOptionalIE(0x40, &f, bytes) | Uplink data status |
| 11 | pduSessionStatus | IE4 (optional) | corruptOptionalIE(0x50, &f, bytes) | PDU session status |
| 12 | ueStatus | IE4 (optional) | corruptOptionalIE(0x2B, &f, bytes) | UE status |
| 13 | additionalGuti | IE4 (optional) | corruptOptionalIE(0x77, &f, bytes) | Additional GUTI |
| 14 | allowedPduSessionStatus | IE4 (optional) | corruptOptionalIE(0x25, &f, bytes) | Allowed PDU session status |
| 15 | uesUsageSetting | IE4 (optional) | corruptOptionalIE(0x18, &f, bytes) | UE's usage setting |
| 16 | requestedDrxParameters | IE4 (optional) | corruptOptionalIE(0x51, &f, bytes) | Requested DRX parameters |
| 17 | epsNasMessageContainer | IE4 (optional) | corruptOptionalIE(0x70, &f, bytes) | EPS NAS message container |
| 18 | ladnIndication | IE4 (optional) | corruptOptionalIE(0x7E, &f, bytes) | LADN indication |
| 19 | payloadContainer | IE4 (optional) | corruptOptionalIE(0x7B, &f, bytes) | Payload container |
| 20 | updateType | IE4 (optional) | corruptOptionalIE(0x53, &f, bytes) | Update type |
| 21 | nasMessageContainer | IE4 (optional) | corruptOptionalIE(0x71, &f, bytes) | NAS message container |

#### RegistrationComplete (registrationComplete)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | sorTransparentContainer | IE4 (optional) | corruptOptionalIE(0x73, &f, bytes) | SOR transparent container |

#### RegistrationAccept (registrationAccept)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | registrationResult | IE3 | corruptValue(&f, bytes) | 5GS registration result |
| 1 | networkSlicingIndication | IE1 (optional) | corruptOptionalIE1(0x9, &f, bytes) | Network slicing indication |
| 2 | nssaiInclusionMode | IE1 (optional) | corruptOptionalIE1(0xA, &f, bytes) | NSSAI inclusion mode |
| 3 | micoIndication | IE1 (optional) | corruptOptionalIE1(0xB, &f, bytes) | MICO indication |
| 4 | mobileIdentity | IE4 (optional) | corruptOptionalIE(0x77, &f, bytes) | 5GS mobile identity (GUTI) |
| 5 | equivalentPLMNs | IE4 (optional) | corruptOptionalIE(0x4A, &f, bytes) | Equivalent PLMNs |
| 6 | taiList | IE4 (optional) | corruptOptionalIE(0x54, &f, bytes) | TAI list |
| 7 | allowedNSSAI | IE4 (optional) | corruptOptionalIE(0x15, &f, bytes) | Allowed NSSAI |
| 8 | rejectedNSSAI | IE4 (optional) | corruptOptionalIE(0x11, &f, bytes) | Rejected NSSAI |
| 9 | configuredNSSAI | IE4 (optional) | corruptOptionalIE(0x31, &f, bytes) | Configured NSSAI |
| 10 | networkFeatureSupport | IE4 (optional) | corruptOptionalIE(0x21, &f, bytes) | 5GS network feature support |
| 11 | pduSessionStatus | IE4 (optional) | corruptOptionalIE(0x50, &f, bytes) | PDU session status |
| 12 | pduSessionReactivationResult | IE4 (optional) | corruptOptionalIE(0x26, &f, bytes) | PDU session reactivation result |
| 13 | pduSessionReactivationResultErrorCause | IE4 (optional) | corruptOptionalIE(0x72, &f, bytes) | Reactivation result error cause |
| 14 | ladnInformation | IE4 (optional) | corruptOptionalIE(0x79, &f, bytes) | LADN information |
| 15 | serviceAreaList | IE4 (optional) | corruptOptionalIE(0x27, &f, bytes) | Service area list |
| 16 | t3512Value | IE4 (optional) | corruptOptionalIE(0x5E, &f, bytes) | T3512 timer value |
| 17 | non3gppDeRegistrationTimerValue | IE4 (optional) | corruptOptionalIE(0x5D, &f, bytes) | Non-3GPP de-registration timer |
| 18 | t3502Value | IE4 (optional) | corruptOptionalIE(0x16, &f, bytes) | T3502 timer value |
| 19 | emergencyNumberList | IE4 (optional) | corruptOptionalIE(0x34, &f, bytes) | Emergency number list |
| 20 | extendedEmergencyNumberList | IE4 (optional) | corruptOptionalIE(0x7A, &f, bytes) | Extended emergency number list |
| 21 | sorTransparentContainer | IE4 (optional) | corruptOptionalIE(0x73, &f, bytes) | SOR transparent container |
| 22 | eapMessage | IE4 (optional) | corruptOptionalIE(0x78, &f, bytes) | EAP message |
| 23 | operatorDefinedAccessCategoryDefinitions | IE4 (optional) | corruptOptionalIE(0x76, &f, bytes) | Operator-defined access category |
| 24 | negotiatedDrxParameters | IE4 (optional) | corruptOptionalIE(0x51, &f, bytes) | Negotiated DRX parameters |

#### RegistrationReject (registrationReject)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | mmCause | IE3 | corruptValue(&f, bytes) | 5GMM cause value |
| 1 | t3346value | IE4 (optional) | corruptOptionalIE(0x5F, &f, bytes) | T3346 timer value |
| 2 | t3502value | IE4 (optional) | corruptOptionalIE(0x16, &f, bytes) | T3502 timer value |
| 3 | eapMessage | IE4 (optional) | corruptOptionalIE(0x78, &f, bytes) | EAP message |

#### DeRegistrationRequestUeOriginating (deregistrationRequest)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | ngKSI + deRegistrationType | IE1 (compound) | corruptValue1(&a, &b, bytes) | NAS KSI + de-registration type |
| 1 | mobileIdentity | IE6 | corruptValue(&f, bytes) | 5GS mobile identity |

#### DeRegistrationRequestUeTerminated (deregistrationRequestUETerminated)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | deRegistrationType | IE1 | corruptValue1(0, &f, bytes) | De-registration type |
| 1 | mmCause | IE3 (optional) | corruptOptionalIE(0x58, &f, bytes) | 5GMM cause |
| 2 | t3346Value | IE4 (optional) | corruptOptionalIE(0x5F, &f, bytes) | T3346 timer value |

#### ServiceRequest (serviceRequest)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | serviceType + ngKSI | IE1 (compound) | corruptValue1(&a, &b, bytes) | Service type + NAS key set ID |
| 1 | tmsi | IE6 | corruptValue(&f, bytes) | 5GS TMSI identity |
| 2 | uplinkDataStatus | IE4 (optional) | corruptOptionalIE(0x40, &f, bytes) | Uplink data status |
| 3 | pduSessionStatus | IE4 (optional) | corruptOptionalIE(0x50, &f, bytes) | PDU session status |
| 4 | allowedPduSessionStatus | IE4 (optional) | corruptOptionalIE(0x25, &f, bytes) | Allowed PDU session status |
| 5 | nasMessageContainer | IE4 (optional) | corruptOptionalIE(0x71, &f, bytes) | NAS message container |

#### ServiceAccept (serviceAccept)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | pduSessionStatus | IE4 (optional) | corruptOptionalIE(0x50, &f, bytes) | PDU session status |
| 1 | pduSessionReactivationResult | IE4 (optional) | corruptOptionalIE(0x26, &f, bytes) | PDU session reactivation result |
| 2 | pduSessionReactivationResultErrorCause | IE4 (optional) | corruptOptionalIE(0x72, &f, bytes) | Reactivation result error cause |
| 3 | eapMessage | IE4 (optional) | corruptOptionalIE(0x78, &f, bytes) | EAP message |

#### ServiceReject (serviceReject)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | mmCause | IE3 | corruptValue(&f, bytes) | 5GMM cause value |
| 1 | pduSessionStatus | IE4 (optional) | corruptOptionalIE(0x50, &f, bytes) | PDU session status |
| 2 | t3346Value | IE4 (optional) | corruptOptionalIE(0x5F, &f, bytes) | T3346 timer value |
| 3 | eapMessage | IE4 (optional) | corruptOptionalIE(0x78, &f, bytes) | EAP message |

#### SecurityModeCommand (securityModeCommand)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | selectedNasSecurityAlgorithms | IE3 | corruptValue(&f, bytes) | Selected NAS security algorithms |
| 1 | ngKsi | IE1 | corruptValue1(0, &f, bytes) | NAS key set identifier |
| 2 | replayedUeSecurityCapabilities | IE4 | corruptValue(&f, bytes) | Replayed UE security capabilities |
| 3 | imeiSvRequest | IE1 (optional) | corruptOptionalIE1(0xE, &f, bytes) | IMEISV request |
| 4 | epsNasSecurityAlgorithms | IE3 (optional) | corruptOptionalIE(0x57, &f, bytes) | EPS NAS security algorithms |
| 5 | additional5gSecurityInformation | IE4 (optional) | corruptOptionalIE(0x36, &f, bytes) | Additional 5G security info |
| 6 | eapMessage | IE4 (optional) | corruptOptionalIE(0x78, &f, bytes) | EAP message |
| 7 | abba | IE4 (optional) | corruptOptionalIE(0x38, &f, bytes) | ABBA parameter |
| 8 | replayedS1UeNetworkCapability | IE4 (optional) | corruptOptionalIE(0x19, &f, bytes) | Replayed S1 UE network capability |

#### SecurityModeComplete (securityModeComplete)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | imeiSv | IE4 (optional) | corruptOptionalIE(0x77, &f, bytes) | IMEISV |
| 1 | nasMessageContainer | IE4 (optional) | corruptOptionalIE(0x71, &f, bytes) | NAS message container |

#### SecurityModeReject (securityModeReject)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | mmCause | IE3 | corruptValue(&f, bytes) | 5GMM cause value |

#### AuthenticationRequest (authenticationRequest)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | ngKSI | IE1 | corruptValue1(0, &f, bytes) | NAS key set identifier |
| 1 | abba | IE3 | corruptValue(&f, bytes) | ABBA parameter |
| 2 | authParamRAND | IE3 (optional) | corruptOptionalIE(0x21, &f, bytes) | Authentication parameter RAND |
| 3 | authParamAUTN | IE3 (optional) | corruptOptionalIE(0x20, &f, bytes) | Authentication parameter AUTN |
| 4 | eapMessage | IE4 (optional) | corruptOptionalIE(0x78, &f, bytes) | EAP message |

#### AuthenticationResponse (authenticationResponse)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | authenticationResponseParameter | IE4 (optional) | corruptOptionalIE(0x2D, &f, bytes) | RES* authentication response |
| 1 | eapMessage | IE4 (optional) | corruptOptionalIE(0x78, &f, bytes) | EAP message |

#### AuthenticationFailure (authenticationFailure)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | mmCause | IE3 | corruptValue(&f, bytes) | 5GMM cause |
| 1 | authenticationFailureParameter | IE4 (optional) | corruptOptionalIE(0x30, &f, bytes) | AUTS failure parameter |

#### AuthenticationReject (authenticationReject)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | eapMessage | IE4 (optional) | corruptOptionalIE(0x78, &f, bytes) | EAP message |

#### AuthenticationResult (authenticationResult)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | ngKSI | IE1 | corruptValue1(0, &f, bytes) | NAS key set identifier |
| 1 | eapMessage | IE4 | corruptValue(&f, bytes) | EAP message |
| 2 | abba | IE3 (optional) | corruptOptionalIE(0x38, &f, bytes) | ABBA parameter |

#### IdentityRequest (identityRequest)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | identityType | IE1 | corruptValue1(0, &f, bytes) | Requested identity type |

#### IdentityResponse (identityResponse)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | mobileIdentity | IE6 | corruptValue(&f, bytes) | 5GS mobile identity (SUCI/IMEI) |

#### ConfigurationUpdateCommand (configurationUpdateCommand)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | configurationUpdateIndication | IE1 (optional) | corruptOptionalIE1(0xD, &f, bytes) | Config update indication |
| 1 | guti | IE4 (optional) | corruptOptionalIE(0x77, &f, bytes) | 5GS GUTI |
| 2 | taiList | IE4 (optional) | corruptOptionalIE(0x54, &f, bytes) | TAI list |
| 3 | allowedNssai | IE4 (optional) | corruptOptionalIE(0x15, &f, bytes) | Allowed NSSAI |
| 4 | serviceAreaList | IE4 (optional) | corruptOptionalIE(0x27, &f, bytes) | Service area list |
| 5 | networkFullName | IE4 (optional) | corruptOptionalIE(0x43, &f, bytes) | Network full name |
| 6 | networkShortName | IE4 (optional) | corruptOptionalIE(0x45, &f, bytes) | Network short name |
| 7 | localTimeZone | IE4 (optional) | corruptOptionalIE(0x46, &f, bytes) | Local time zone |
| 8 | universalTimeAndLocalTimeZone | IE4 (optional) | corruptOptionalIE(0x47, &f, bytes) | Universal + local time zone |
| 9 | networkDaylightSavingTime | IE4 (optional) | corruptOptionalIE(0x49, &f, bytes) | Network daylight saving time |
| 10 | ladnInformation | IE4 (optional) | corruptOptionalIE(0x79, &f, bytes) | LADN information |
| 11 | micoIndication | IE1 (optional) | corruptOptionalIE1(0xB, &f, bytes) | MICO indication |
| 12 | networkSlicingIndication | IE1 (optional) | corruptOptionalIE1(0x9, &f, bytes) | Network slicing indication |
| 13 | configuredNssai | IE4 (optional) | corruptOptionalIE(0x31, &f, bytes) | Configured NSSAI |
| 14 | rejectedNssai | IE4 (optional) | corruptOptionalIE(0x11, &f, bytes) | Rejected NSSAI |
| 15 | operatorDefinedAccessCategoryDefinitions | IE4 (optional) | corruptOptionalIE(0x76, &f, bytes) | Operator-defined access category |
| 16 | smsIndication | IE1 (optional) | corruptOptionalIE1(0xF, &f, bytes) | SMS indication |

#### FiveGMmStatus (gmmStatus)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | mmCause | IE3 | corruptValue(&f, bytes) | 5GMM cause value |

#### Notification (notification)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | accessType | IE1 | corruptValue1(0, &f, bytes) | Access type |

#### NotificationResponse (notificationResponse)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | pduSessionStatus | IE4 (optional) | corruptOptionalIE(0x50, &f, bytes) | PDU session status |

#### UlNasTransport (ulNasTransport)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | payloadContainerType | IE1 | corruptValue1(0, &f, bytes) | Payload container type |
| 1 | payloadContainer | IE6 | corruptValue(&f, bytes) | Payload container (SM message) |
| 2 | pduSessionId | IE4 (optional) | corruptOptionalIE(0x12, &f, bytes) | PDU session ID |
| 3 | oldPduSessionId | IE4 (optional) | corruptOptionalIE(0x59, &f, bytes) | Old PDU session ID |
| 4 | requestType | IE1 (optional) | corruptOptionalIE1(0x8, &f, bytes) | Request type |
| 5 | sNssai | IE4 (optional) | corruptOptionalIE(0x22, &f, bytes) | S-NSSAI |
| 6 | dnn | IE4 (optional) | corruptOptionalIE(0x25, &f, bytes) | DNN |
| 7 | additionalInformation | IE4 (optional) | corruptOptionalIE(0x24, &f, bytes) | Additional information |

#### DlNasTransport (dlNasTransport)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | payloadContainerType | IE1 | corruptValue1(0, &f, bytes) | Payload container type |
| 1 | payloadContainer | IE6 | corruptValue(&f, bytes) | Payload container |
| 2 | pduSessionId | IE4 (optional) | corruptOptionalIE(0x12, &f, bytes) | PDU session ID |
| 3 | additionalInformation | IE4 (optional) | corruptOptionalIE(0x24, &f, bytes) | Additional information |
| 4 | mmCause | IE3 (optional) | corruptOptionalIE(0x58, &f, bytes) | 5GMM cause |
| 5 | backOffTimerValue | IE4 (optional) | corruptOptionalIE(0x37, &f, bytes) | Back-off timer value |

---

### SM Messages (Session Management)

SM messages are transported inside `UlNasTransport.payloadContainer`. The `onCorrupt` for SM messages operates on the decoded SM PDU.

#### PduSessionEstablishmentRequest (PDUSessionEstablishmentRequest)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | integrityProtectionMaximumDataRate | IE3 | corruptValue(&f, bytes) | Integrity protection max data rate |
| 1 | pduSessionType | IE1 (optional) | corruptOptionalIE1(0x9, &f, bytes) | PDU session type (IPv4/IPv6/IPv4v6) |
| 2 | sscMode | IE1 (optional) | corruptOptionalIE1(0xA, &f, bytes) | SSC mode |
| 3 | smCapability | IE4 (optional) | corruptOptionalIE(0x28, &f, bytes) | 5GSM capability |
| 4 | maximumNumberOfSupportedPacketFilters | IE3 (optional) | corruptOptionalIE(0x55, &f, bytes) | Max packet filters |
| 5 | alwaysOnPduSessionRequested | IE1 (optional) | corruptOptionalIE1(0xB, &f, bytes) | Always-on PDU session |
| 6 | smPduDnRequestContainer | IE4 (optional) | corruptOptionalIE(0x39, &f, bytes) | SM PDU DN request container |
| 7 | extendedProtocolConfigurationOptions | IE4 (optional) | corruptOptionalIE(0x7B, &f, bytes) | Extended PCO |

#### PduSessionEstablishmentAccept (PDUSessionEstablishmentAccept)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | selectedSscMode + selectedPduSessionType | IE1 (compound) | corruptValue1(&a, &b, bytes) | SSC mode + PDU session type |
| 1 | authorizedQoSRules | IE6 | corruptValue(&f, bytes) | Authorized QoS rules |
| 2 | sessionAmbr | IE3 | corruptValue(&f, bytes) | Session AMBR |
| 3 | smCause | IE3 (optional) | corruptOptionalIE(0x59, &f, bytes) | 5GSM cause |
| 4 | pduAddress | IE4 (optional) | corruptOptionalIE(0x29, &f, bytes) | PDU address |
| 5 | rqTimerValue | IE4 (optional) | corruptOptionalIE(0x56, &f, bytes) | RQ timer value |
| 6 | sNssai | IE4 (optional) | corruptOptionalIE(0x22, &f, bytes) | S-NSSAI |
| 7 | alwaysOnPduSessionIndication | IE1 (optional) | corruptOptionalIE1(0x8, &f, bytes) | Always-on PDU session |
| 8 | mappedEpsBearerContexts | IE4 (optional) | corruptOptionalIE(0x7F, &f, bytes) | Mapped EPS bearer contexts |
| 9 | eapMessage | IE4 (optional) | corruptOptionalIE(0x78, &f, bytes) | EAP message |
| 10 | authorizedQoSFlowDescriptions | IE4 (optional) | corruptOptionalIE(0x79, &f, bytes) | Authorized QoS flow descriptions |
| 11 | extendedProtocolConfigurationOptions | IE4 (optional) | corruptOptionalIE(0x7B, &f, bytes) | Extended PCO |
| 12 | dnn | IE4 (optional) | corruptOptionalIE(0x25, &f, bytes) | DNN |

#### PduSessionEstablishmentReject (PDUSessionEstablishmentReject)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | smCause | IE3 | corruptValue(&f, bytes) | 5GSM cause |
| 1 | backOffTimerValue | IE4 (optional) | corruptOptionalIE(0x37, &f, bytes) | Back-off timer |
| 2 | allowedSscMode | IE1 (optional) | corruptOptionalIE1(0xF, &f, bytes) | Allowed SSC mode |
| 3 | eapMessage | IE4 (optional) | corruptOptionalIE(0x78, &f, bytes) | EAP message |
| 4 | extendedProtocolConfigurationOptions | IE4 (optional) | corruptOptionalIE(0x7B, &f, bytes) | Extended PCO |

#### PduSessionAuthenticationCommand (PDUSessionAuthenticationCommand)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | eapMessage | IE6 | corruptValue(&f, bytes) | EAP message |
| 1 | extendedProtocolConfigurationOptions | IE4 (optional) | corruptOptionalIE(0x7B, &f, bytes) | Extended PCO |

#### PduSessionAuthenticationComplete (PDUSessionAuthenticationComplete)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | eapMessage | IE6 | corruptValue(&f, bytes) | EAP message |
| 1 | extendedProtocolConfigurationOptions | IE4 (optional) | corruptOptionalIE(0x7B, &f, bytes) | Extended PCO |

#### PduSessionAuthenticationResult (PDUSessionAuthenticationResult)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | eapMessage | IE4 (optional) | corruptOptionalIE(0x78, &f, bytes) | EAP message |
| 1 | extendedProtocolConfigurationOptions | IE4 (optional) | corruptOptionalIE(0x7B, &f, bytes) | Extended PCO |

#### PduSessionModificationRequest (PDUSessionModificationRequest)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | smCapability | IE4 (optional) | corruptOptionalIE(0x28, &f, bytes) | 5GSM capability |
| 1 | smCause | IE3 (optional) | corruptOptionalIE(0x59, &f, bytes) | 5GSM cause |
| 2 | maximumNumberOfSupportedPacketFilters | IE3 (optional) | corruptOptionalIE(0x55, &f, bytes) | Max packet filters |
| 3 | alwaysOnPduSessionRequested | IE1 (optional) | corruptOptionalIE1(0xB, &f, bytes) | Always-on PDU session |
| 4 | integrityProtectionMaximumDataRate | IE3 (optional) | corruptOptionalIE(0x13, &f, bytes) | Integrity protection max data rate |
| 5 | requestedQosRules | IE6 (optional) | corruptOptionalIE(0x7A, &f, bytes) | Requested QoS rules |
| 6 | requestedQosFlowDescriptions | IE4 (optional) | corruptOptionalIE(0x79, &f, bytes) | Requested QoS flow descriptions |
| 7 | mappedEpsBearerContexts | IE4 (optional) | corruptOptionalIE(0x7F, &f, bytes) | Mapped EPS bearer contexts |
| 8 | extendedProtocolConfigurationOptions | IE4 (optional) | corruptOptionalIE(0x7B, &f, bytes) | Extended PCO |

#### PduSessionModificationCommand (PDUSessionModificationCommand)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | smCause | IE3 (optional) | corruptOptionalIE(0x59, &f, bytes) | 5GSM cause |
| 1 | sessionAmbr | IE3 (optional) | corruptOptionalIE(0x2A, &f, bytes) | Session AMBR |
| 2 | rqTimerValue | IE4 (optional) | corruptOptionalIE(0x56, &f, bytes) | RQ timer value |
| 3 | alwaysOnPduSessionIndication | IE1 (optional) | corruptOptionalIE1(0x8, &f, bytes) | Always-on PDU session |
| 4 | authorizedQoSRules | IE6 (optional) | corruptOptionalIE(0x7A, &f, bytes) | Authorized QoS rules |
| 5 | mappedEpsBearerContexts | IE4 (optional) | corruptOptionalIE(0x7F, &f, bytes) | Mapped EPS bearer contexts |
| 6 | authorizedQoSFlowDescriptions | IE4 (optional) | corruptOptionalIE(0x79, &f, bytes) | Authorized QoS flow descriptions |
| 7 | extendedProtocolConfigurationOptions | IE4 (optional) | corruptOptionalIE(0x7B, &f, bytes) | Extended PCO |

#### PduSessionModificationComplete (PDUSessionModificationComplete)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | extendedProtocolConfigurationOptions | IE4 (optional) | corruptOptionalIE(0x7B, &f, bytes) | Extended PCO |

#### PduSessionModificationCommandReject (PDUSessionModificationCommandReject)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | smCause | IE3 | corruptValue(&f, bytes) | 5GSM cause |
| 1 | extendedProtocolConfigurationOptions | IE4 (optional) | corruptOptionalIE(0x7B, &f, bytes) | Extended PCO |

#### PduSessionModificationReject (PDUSessionModificationReject)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | smCause | IE3 | corruptValue(&f, bytes) | 5GSM cause |
| 1 | backOffTimerValue | IE4 (optional) | corruptOptionalIE(0x37, &f, bytes) | Back-off timer |
| 2 | extendedProtocolConfigurationOptions | IE4 (optional) | corruptOptionalIE(0x7B, &f, bytes) | Extended PCO |

#### PduSessionReleaseRequest (PDUSessionReleaseRequest)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | smCause | IE3 (optional) | corruptOptionalIE(0x59, &f, bytes) | 5GSM cause |
| 1 | extendedProtocolConfigurationOptions | IE4 (optional) | corruptOptionalIE(0x7B, &f, bytes) | Extended PCO |

#### PduSessionReleaseCommand (PDUSessionReleaseCommand)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | smCause | IE3 | corruptValue(&f, bytes) | 5GSM cause |
| 1 | backOffTimerValue | IE4 (optional) | corruptOptionalIE(0x37, &f, bytes) | Back-off timer |
| 2 | eapMessage | IE4 (optional) | corruptOptionalIE(0x78, &f, bytes) | EAP message |
| 3 | extendedProtocolConfigurationOptions | IE4 (optional) | corruptOptionalIE(0x7B, &f, bytes) | Extended PCO |

#### PduSessionReleaseComplete (PDUSessionReleaseComplete)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | smCause | IE3 (optional) | corruptOptionalIE(0x59, &f, bytes) | 5GSM cause |
| 1 | extendedProtocolConfigurationOptions | IE4 (optional) | corruptOptionalIE(0x7B, &f, bytes) | Extended PCO |

#### PduSessionReleaseReject (PDUSessionReleaseReject)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | smCause | IE3 | corruptValue(&f, bytes) | 5GSM cause |
| 1 | extendedProtocolConfigurationOptions | IE4 (optional) | corruptOptionalIE(0x7B, &f, bytes) | Extended PCO |

#### FiveGSmStatus (gsmStatus)

| IE Index | Field | Type | corruptValue Method | Description |
|----------|-------|------|---------------------|-------------|
| 0 | smCause | IE3 | corruptValue(&f, bytes) | 5GSM cause |

---

## HexBytes Encoding Reference

### IE1 (4-bit value)

Single byte, only low nibble used. Maps to enum/bit fields.

```
Example: 0x03 → 0b0011
  IE5gsRegistrationType: FOR=1 (bit0), REG_TYPE=1 (bits1-2)
  0x0A → 0b1010: FOR=0, REG_TYPE=5
```

### IE3/IE4/IE6 (variable-length)

Arbitrary raw bytes. Structure depends on the IE:

- **Enum IEs** (IE5gMmCause, IE5gSmCause): first byte = enum value. Use `FF` for illegal enum.
- **OctetString IEs** (AuthenticationFailureParameter, PayloadContainer): raw data replaces field.
- **Composite IEs** (IE5gsMobileIdentity, NSSAI, etc.): bytes fed to `Decode()`, fallback to partial parse.
- **Empty/bitset IEs**: internal structure-specific encoding.

### Common CWE-20 Test Values

| Attack Type | HexBytes | Target IE Types |
|-------------|----------|----------------|
| Enum out-of-bounds | `FF`, `FE`, `07` | IE3 enums (mmCause, smCause) |
| Reserved bits set | `80`, `C0`, `F0` | Any IE1 |
| Type confusion (SUCI→IMEI) | `03...` | IE5gsMobileIdentity |
| Null/empty | (empty string) | Optional IEs |
| Length overflow | Very long hex string | IE4/IE6 length-prefixed |
| Negative/invalid TLV | `00` repeated | Any mandatory IE |

---

## MutateAgent Strategy Guidance

### When to Use corruptValue vs mutate

| Scenario | Primitive |
|----------|-----------|
| Random exploration | `mutate` (state_learner `incomingMessage` mode) |
| Targeted IE testing | `corruptValue` (this API) |
| Auth bypass test | `corruptValue` IE0 of SecurityModeComplete to skip auth |
| Enum fuzzing | `corruptValue` IE3 mmCause with 0x00-0xFF sweep |
| Identity spoofing | `corruptValue` mobileIdentity fields |
| Optional IE injection | `corruptOptionalIE` auto-creates the IE |

### Suggested Mutation Strategies

1. **Enum boundary sweep**: For each IE3 enum field, inject `00`, `01`, `FE`, `FF`
2. **Type confusion**: Change `IE5gsMobileIdentity.type` by setting bytes[0] to different identity types (SUCI=1, GUTI=2, IMEI=3, TMSI=4)
3. **Length attacks**: For IE4/IE6 fields, inject overly long or zero-length data
4. **Bit-level corruption**: For IE1 fields, sweep 0x0-0xF to test all bit combinations
5. **Mandatory field nullification**: Set mandatory IE bytes to empty
6. **Security bypass**: Set ngKSI to NOT_AVAILABLE_OR_RESERVED (0x07) to bypass security context checks
7. **NSSAI injection**: Corrupt requestedNSSAI with crafted S-NSSAI values to test slice authorization
