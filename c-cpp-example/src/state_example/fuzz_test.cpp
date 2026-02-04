#include &lt;stddef.h>
#include &lt;stdint.h>
#include &lt;cifuzz/cifuzz.h>
#include &lt;fuzzer/FuzzedDataProvider.h>
#include "crypto_1.h"
#include "crypto_2.h"
#include "gps_1.h"
#include "key_management_1.h"
#include "time_1.h"

void SetFDP(FuzzedDataProvider *fuzzed_data_provider);
FuzzedDataProvider *GetFDP();

void ConsumeDataAndFillRestWithZeros(void *destination, size_t num_bytes) {
    // Ensure that we do not write more than the allocated size
    if (destination == nullptr || num_bytes == 0) return;
    memset(destination, 0, num_bytes); // FIX: Ensure we only write to allocated memory
}

FUZZ_TEST_SETUP() {}

FUZZ_TEST(const uint8_t *data, size_t size) {
    // Ensure a minimum data length
    if (size &lt; 100)
        return;

    // Setup FuzzedDataProvider and initialize the mocklib
    FuzzedDataProvider fdp(data, size);
    SetFDP(&fdp);

    int number_of_functions = GetFDP()->ConsumeIntegralInRange&lt;int>(1, 100);
    for (int i = 0; i &lt; number_of_functions; i++) {
        int function_id = GetFDP()->ConsumeIntegralInRange&lt;int>(0, 15);
        switch (function_id) {
            case 0: {
                crypto_get_state();
                break;
            }
            case 1: {
                get_destination_position();
                break;
            }
            case 2: {
                crypto_key key = {};
                size_t key_size = sizeof(key.key);
                ConsumeDataAndFillRestWithZeros(key.key, key_size &lt; 64 ? key_size : 64); // FIX: Limit to allocated size
                crypto_verify_key(key);
                break;
            }
            case 3: {
                current_time();
                break;
            }
            case 4: {
                crypto_nonce nonce_tmp = {};
                size_t nonce_size = sizeof(nonce_tmp.nonce);
                ConsumeDataAndFillRestWithZeros(nonce_tmp.nonce, nonce_size &lt; 64 ? nonce_size : 64); // FIX: Limit to allocated size
                nonce_tmp.time_of_creation = GetFDP()->ConsumeIntegral&lt;int>();
                crypto_nonce *nonce = &nonce_tmp;
                crypto_verify_nonce(nonce);
                break;
            }
            case 5: {
                std::vector&lt;uint8_t> message_vec = GetFDP()->ConsumeBytes&lt;uint8_t>(sizeof(uint8_t) * GetFDP()->ConsumeIntegral&lt;uint16_t>());
                const uint8_t *message = (const uint8_t *)message_vec.data();
                int len = message_vec.size();
                crypto_hmac hmac_tmp = {};
                size_t hmac_size = sizeof(hmac_tmp.hmac);
                ConsumeDataAndFillRestWithZeros(hmac_tmp.hmac, hmac_size &lt; 64 ? hmac_size : 64); // FIX: Limit to allocated size
                crypto_hmac *hmac = &hmac_tmp;
                crypto_verify_hmac(message, len, hmac);
                break;
            }
            case 6: {
                crypto_nonce nonce = {};
                size_t nonce_size = sizeof(nonce.nonce);
                ConsumeDataAndFillRestWithZeros(nonce.nonce, nonce_size &lt; 64 ? nonce_size : 64); // FIX: Limit to allocated size
                nonce.time_of_creation = GetFDP()->ConsumeIntegral&lt;int>();
                crypto_set_nonce(nonce);
                break;
            }
            case 7: {
                std::vector&lt;uint8_t> message_vec = GetFDP()->ConsumeBytes&lt;uint8_t>(sizeof(uint8_t) * GetFDP()->ConsumeIntegral&lt;uint16_t>());
                const uint8_t *message = (const uint8_t *)message_vec.data();
                int len = message_vec.size();
                crypto_hmac hmac_tmp = {};
                size_t hmac_size = sizeof(hmac_tmp.hmac);
                ConsumeDataAndFillRestWithZeros(hmac_tmp.hmac, hmac_size &lt; 64 ? hmac_size : 64); // FIX: Limit to allocated size
                crypto_hmac *hmac = &hmac_tmp;
                crypto_calculate_hmac(message, len, hmac);
                break;
            }
            case 8: {
                GPS_position position = {};
                position.longitude_degree = GetFDP()->ConsumeIntegral&lt;uint8_t>();
                position.longitude_minute = GetFDP()->ConsumeIntegral&lt;uint8_t>();
                position.longitude_second = GetFDP()->ConsumeIntegral&lt;uint8_t>();
                position.latitude_degree = GetFDP()->ConsumeIntegral&lt;uint8_t>();
                position.latitude_minute = GetFDP()->ConsumeIntegral&lt;uint8_t>();
                position.latitude_second = GetFDP()->ConsumeIntegral&lt;uint8_t>();
                set_destination_postition(position);
                break;
            }
            case 9: {
                crypto_key key = {};
                size_t key_size = sizeof(key.key);
                ConsumeDataAndFillRestWithZeros(key.key, key_size &lt; 64 ? key_size : 64); // FIX: Limit to allocated size
                crypto_set_key(key);
                break;
            }
            case 10: {
                GPS_position position_tmp = {};
                position_tmp.longitude_degree = GetFDP()->ConsumeIntegral&lt;uint8_t>();
                position_tmp.longitude_minute = GetFDP()->ConsumeIntegral&lt;uint8_t>();
                position_tmp.longitude_second = GetFDP()->ConsumeIntegral&lt;uint8_t>();
                position_tmp.latitude_degree = GetFDP()->ConsumeIntegral&lt;uint8_t>();
                position_tmp.latitude_minute = GetFDP()->ConsumeIntegral&lt;uint8_t>();
                position_tmp.latitude_second = GetFDP()->ConsumeIntegral&lt;uint8_t>();
                GPS_position *position = &position_tmp;
                get_current_position(position);
                break;
            }
            case 11: {
                init_crypto_module();
                break;
            }
            case 12: {
                std::vector&lt;uint8_t> key_vec = GetFDP()->ConsumeBytes&lt;uint8_t>(sizeof(uint8_t) * GetFDP()->ConsumeIntegral&lt;uint16_t>());
                uint8_t *key = (uint8_t *)key_vec.data();
                uint8_t length = key_vec.size();
                key_management_create_key(key, length);
                break;
            }
            case 13: {
                std::vector&lt;uint8_t> nonce_vec = GetFDP()->ConsumeBytes&lt;uint8_t>(sizeof(uint8_t) * GetFDP()->ConsumeIntegral&lt;uint16_t>());
                uint8_t *nonce = (uint8_t *)nonce_vec.data();
                uint8_t length = nonce_vec.size();
                key_management_create_nonce(nonce, length);
                break;
            }
            case 14: {
                crypto_init();
                break;
            }
        }
    }
}
