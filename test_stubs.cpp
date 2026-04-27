// Stub implementations for symbols needed by libcommon-lib in test context
#include <ue/app/state_learner.hpp>

namespace nr::ue {

// Dummy UeStateLearner for test linking
UeStateLearner *state_learner = nullptr;

int FLAG_SECMOD = 0;
bool FLAG_REPLAY = false;
bool SMC_SENT = false;
int port = 45678;

// Stub methods (never actually called in test - only needed for linker)
void UeStateLearner::notify_response(std::string msg) {}
bool UeStateLearner::has_sec_ctx() { return false; }
nas::IE5gsMobileIdentity UeStateLearner::getOrGenerateId(nas::EIdentityType) { return {}; }

} // namespace nr::ue
