#include &lt;cifuzz/cifuzz.h>
#include &lt;fuzzer/FuzzedDataProvider.h>
#include "explore_me.h"
#include &lt;gtest/gtest.h>

TEST(ExploreStructuredInputChecks, DeveloperTest) {
    InputStruct inputStruct = (InputStruct) {.a=0, .b= 10, .c="Developer"};
    EXPECT_NO_THROW(ExploreStructuredInputChecks(inputStruct));
}

TEST(ExploreStructuredInputChecks, MaintainerTest) {
    InputStruct inputStruct = (InputStruct) {.a=20, .b= -10, .c="Maintainer"};
    EXPECT_NO_THROW(ExploreStructuredInputChecks(inputStruct));
}

FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    long a = fdp.ConsumeIntegral&lt;long>();
    long b = fdp.ConsumeIntegral&lt;long>();
    std::string c;
    if (size > sizeof(InputStruct::c)) { // FIX: Check size against expected limit
        c = fdp.ConsumeBytesAsString(sizeof(InputStruct::c) - 1); // FIX: Limit consumption to prevent overflow
    } else {
        c = fdp.ConsumeRemainingBytesAsString();
    }

    InputStruct inputStruct = (InputStruct) {
        .a = a,
        .b = b,
        .c = c,
    };
    ExploreStructuredInputChecks(inputStruct);
}
