//
// Created by dagra on 04/12/2022.
//
#include <mbedtls/sha256.h>
#include <math.h>
#include <esp_random.h>
#include <mbedtls/aes.h>
#include "ERDTs.h"

QueueHandle_t packetQueue = NULL;
QueueHandle_t dataQueue = NULL;

const char erdts_OK_Flag[erdts_iv_length] = "sessionOk";
const char erdts_END_Flag[erdts_iv_length] = "sessionEND";

void erdts_init(const parser_packet_ctx *ctx, int rx_buff_size, int tx_buff_size) {
    const uart_config_t uart_config_start = {
            .baud_rate = 9600,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
            .source_clk = UART_SCLK_DEFAULT,
    };

    uart_driver_install(UART_NUM_1, rx_buff_size, tx_buff_size, 0, NULL, 0);
    uart_param_config(UART_NUM_1, &uart_config_start);
    uart_set_pin(UART_NUM_1, ERDTS_TX_PIN, ERDTS_RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    packetQueue = xQueueCreate(ctx->queueSize, ctx->maxLen);
    dataQueue = xQueueCreate(ctx->queueSize, max_cargo(ctx));

    xTaskCreatePinnedToCore(erdts_tx_task, "erdts_tx_task", 1024 * 2, (void *) ctx, configMAX_PRIORITIES - 0, NULL, PRO_CPU_NUM);
}

int max_cargo(const parser_packet_ctx *ctx) {
    return ctx->maxLen - ctx->overhead;
}

int erdts_getPacketLen(const parser_packet_ctx *ctx, uint8_t *packet) {
    int len;
    memcpy(&len, packet + ctx->lengthOffset, ctx->lengthBytes);
    return len + ctx->overhead;
}

int erdts_getCargoLen(const parser_packet_ctx *ctx, uint8_t *packet) {
    int len;
    memcpy(&len, packet + ctx->lengthOffset, ctx->lengthBytes);
    return len;
}

uint8_t *parse_packet(const parser_packet_ctx *ctx, const void *data, int len) {
    uint8_t *packet_buff = NULL;
    if (len < max_cargo(ctx)) {
        packet_buff = malloc(len + ctx->overhead);
        packet_buff[0] = ctx->delimiter;
        memcpy(packet_buff + ctx->lengthOffset, &len, ctx->lengthBytes);
        memcpy(packet_buff + ctx->overhead, data, len);
    }
    return packet_buff;
}

int erdts_send(const parser_packet_ctx *ctx, esp_aes_context *aes_ctx, uint8_t *aes_iv, uint8_t *bytes, int byte_len) {
    uint8_t encrypted[byte_len];
    esp_aes_crypt_cbc(aes_ctx, ESP_AES_ENCRYPT, byte_len, aes_iv, bytes, encrypted);
    memset(aes_iv, 0, erdts_iv_length);

    uint8_t *packet = parse_packet(ctx, encrypted, byte_len);
    int packetLen = erdts_getPacketLen(ctx, packet);
    if (packet == NULL) {
        ESP_LOGI("SEND", "packet is NULL");
        free(packet);
        return -1;
    } else {
        ESP_LOG_BUFFER_HEXDUMP("SEND", &packetLen, sizeof(packetLen), ESP_LOG_INFO);
    }
    if (uxQueueSpacesAvailable(packetQueue)) {
        xQueueSendToBack(packetQueue, packet, 0);
    } else {
        ESP_LOGI("SEND", "couldn't add packet to queue");
        free(packet);
        return -2;
    }
    free(packet);
    return packetLen;
}

int erdts_read(esp_aes_context *ctx, uint8_t* iv, uint8_t* rx_buffer, int rx_buff_size) {
    uint8_t *plaintext = (uint8_t *) malloc(rx_buff_size);
    int rx_bytes = uart_read_bytes(ERDTS_UART_NUM, plaintext, rx_buff_size, 500 / portTICK_PERIOD_MS);
    if (rx_bytes > 0) {
        esp_aes_crypt_cbc(ctx, ESP_AES_DECRYPT, rx_bytes, iv, plaintext, rx_buffer);
        memset(iv, 0, erdts_iv_length);
        esp_log_buffer_hexdump_internal("received", rx_buffer, rx_bytes, ESP_LOG_INFO);
    }
    free(plaintext);
    return rx_bytes;
}

_Noreturn static void erdts_tx_task(void *args) {
    static const char *TX_TASK_TAG = "TX_PACKET";
    esp_log_level_set(TX_TASK_TAG, ESP_LOG_INFO);
    parser_packet_ctx *ctx = (parser_packet_ctx *) args;
    uint8_t packet[ctx->maxLen];
    while (1) {
        if (packetQueue != NULL) {
            if (uxQueueMessagesWaiting(packetQueue)) {
                xQueueReceive(packetQueue, packet, 0);
                uart_write_bytes(ERDTS_UART_NUM, packet, erdts_getPacketLen(ctx, packet));
                uart_wait_tx_done(ERDTS_UART_NUM, 0);
            } else {
                vTaskDelay(10 / portTICK_PERIOD_MS);
            }
        }
    }
}


void getRandomString(char *output, int len) {
    const char *eligible_chars = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890";
    for (int i = 0; i < len - 1; i++) {
        uint32_t rand_int = (esp_random());
        int random_index = fmax((double) ((uint64_t) rand_int * strlen(eligible_chars) * 1.0) / 4294967296 - 1, 0);
        output[i] = eligible_chars[random_index];
    }
    output[len - 1] = '\0';
}

void generate_key(uint8_t *seed, unsigned int tlen, uint8_t *key) {
    mbedtls_sha256(seed, tlen, key, 0);
}

void erdts_start_session(const parser_packet_ctx *pctx, esp_aes_context *ctx, char token[6], uint8_t *iv,
                         uint8_t *session_key, int rx_buff_size) {

    uint8_t key[erdts_key_length / 8];
    uint8_t session_iv[erdts_iv_length];
    uint8_t encrypted[erdts_iv_length];
    uint8_t *plaintext = (uint8_t *) malloc(rx_buff_size);
    uint8_t *decrypted = (uint8_t *) malloc(rx_buff_size);
    char session_seed[erdts_key_length / 8 + erdts_iv_length];

    generate_key((uint8_t *) token, strlen(token), key);
    esp_log_buffer_hexdump_internal("key", key, sizeof(key), ESP_LOG_DEBUG);
    if (esp_aes_setkey(ctx, key, erdts_key_length) == MBEDTLS_ERR_AES_INVALID_KEY_LENGTH) {
        ESP_LOGE("AES_CONFIG", "Invalid Keylength");
        exit(-100);
    }
    memcpy(session_seed, key, erdts_key_length / 8);

    while (1) {
        getRandomString((char *) session_iv, (int) sizeof(session_iv));
        esp_log_buffer_hexdump_internal("session-iv", session_iv, sizeof(session_iv), ESP_LOG_INFO);

        esp_aes_crypt_cbc(ctx, ESP_AES_ENCRYPT, sizeof(session_iv), iv, (uint8_t *) session_iv, encrypted);
        memset(iv, 0, erdts_iv_length);
        esp_log_buffer_hexdump_internal("encrypted", encrypted, sizeof(encrypted), ESP_LOG_DEBUG);

        sendData(pctx, encrypted, sizeof(encrypted));

        memcpy(session_seed + (erdts_key_length / 8), session_iv, erdts_iv_length);
        esp_log_buffer_hexdump_internal("session-key seed", session_seed, sizeof(session_seed), ESP_LOG_DEBUG);
        generate_key((uint8_t *) session_seed, sizeof(session_seed), session_key);
        esp_log_buffer_hexdump_internal("Session-key", session_key, erdts_key_length / 8, ESP_LOG_INFO);
        if (esp_aes_setkey(ctx, session_key, erdts_key_length) == MBEDTLS_ERR_AES_INVALID_KEY_LENGTH) {
            ESP_LOGE("AES_CONFIG", "Invalid Keylength");
            break;
        }
        int rx_bytes = uart_read_bytes(UART_NUM_1, plaintext, rx_buff_size, 500 / portTICK_PERIOD_MS);
        if (rx_bytes > 0) {
            esp_aes_crypt_cbc(ctx, ESP_AES_DECRYPT, rx_bytes, iv, plaintext, decrypted);
            memset(iv, 0, erdts_iv_length);
            esp_log_buffer_hexdump_internal("received", decrypted, rx_bytes, ESP_LOG_INFO);
            if (memcmp(decrypted, erdts_OK_Flag, strlen(erdts_OK_Flag)) == 0) {
                return;
            } else {
                //reset key
                aes_setkey(ctx, key);
            }
        } else {
            ESP_LOGI("start_session", "rx timeout - retrying...");
            //reset key
            aes_setkey(ctx, key);
        }
        vTaskDelay(5000 / portTICK_PERIOD_MS);
    }
    free(decrypted);
    free(plaintext);
}

void erdts_end_session(esp_aes_context *ctx, const parser_packet_ctx *pctx, uint8_t *iv, char token[6]) {
    uint8_t key[erdts_key_length / 8];
    uint8_t *encrypted = malloc(sizeof(erdts_END_Flag));

    esp_aes_crypt_cbc(ctx, ESP_AES_ENCRYPT, sizeof(erdts_END_Flag), iv, (uint8_t *) erdts_END_Flag, encrypted);
    memset(iv, 0, erdts_iv_length);
    sendData(pctx, encrypted, sizeof(erdts_END_Flag));

    generate_key((uint8_t *) token, strlen(token), key);
    aes_setkey(ctx, key);
}

int sendData(const parser_packet_ctx *ctx, const void *buffer, unsigned int buff_len) {
    uint8_t packet[buff_len + ctx->overhead];
    packet[0] = ctx->delimiter;
    memcpy(packet + ctx->lengthOffset, &buff_len, ctx->lengthBytes);
    memcpy(packet + ctx->overhead, buffer, buff_len);
    const int txBytes = uart_write_bytes(ERDTS_UART_NUM, packet, sizeof(packet));
    return txBytes;
}

void aes_setkey(esp_aes_context *ctx, uint8_t *key) {
    if (esp_aes_setkey(ctx, key, erdts_key_length) == MBEDTLS_ERR_AES_INVALID_KEY_LENGTH) {
        ESP_LOGE("AES_CONFIG", "Invalid Keylength");
        exit(-100);
    }
}

int check_flag(uint8_t * data) {
    if (memcmp(data, erdts_END_Flag, strlen(erdts_END_Flag)) == 0) {
        return 1;
    } else if (memcmp(data, erdts_OK_Flag, strlen(erdts_OK_Flag)) == 0) {
        return 2;
    }
    return 0;
}