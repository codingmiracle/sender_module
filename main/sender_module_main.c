#include <mbedtls/aes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "driver/uart.h"
#include "string.h"
#include "esp_random.h"
#include "ERDTs.h"
#include "ssd1306.h"

const int RX_BUF_SIZE = 1024;
const int TX_BUF_SIZE = 0; // 0 => send imidiately

const parser_packet_ctx packetCtx = {
        .delimiter=0xaa,
        .overhead=3,
        .lengthBytes=2,
        .lengthOffset=1,
        .maxLen=1024,
        .queueSize=100
};


_Noreturn static void tx_task(void *arg) {
    static const char *TX_TASK_TAG = "TX_TASK";
    esp_log_level_set(TX_TASK_TAG, ESP_LOG_INFO);
    const char msg[] = "Hello World!! This is a test Text haskhgadl759236ß97329";
    while (1) {
        erdts_send(&packetCtx, msg, strlen(msg));
        vTaskDelay(2000 / portTICK_PERIOD_MS);
    }
}

_Noreturn static void rx_task(void *arg) {
    static const char *RX_TASK_TAG = "RX_TASK";
    esp_log_level_set(RX_TASK_TAG, ESP_LOG_INFO);
    uint8_t *data = (uint8_t *) malloc(RX_BUF_SIZE + 1);
    while (1) {
        const int rxBytes = uart_read_bytes(UART_NUM_1, data, RX_BUF_SIZE, 1000 / portTICK_PERIOD_MS);
        if (rxBytes > 0) {
            data[rxBytes] = 0;
            ESP_LOGI(RX_TASK_TAG, "Read %d bytes: '%s'", rxBytes, data);
            ESP_LOG_BUFFER_HEXDUMP(RX_TASK_TAG, data, rxBytes, ESP_LOG_INFO);
        }
    }
    free(data);
}

void app_main(void) {
    SSD1306_t device;
    esp_aes_context aes_ctx;

    const char *TAG = "SSD1306";

    char token[6];
    uint8_t key[erdts_key_length / 8];
    uint8_t session_key[erdts_key_length / 8];
    uint8_t aes_iv[erdts_iv_length];
    memset(key, 0, erdts_key_length / 8);
    memset(aes_iv, 0, erdts_iv_length);

    //*** SETUP ***//
    ESP_LOGI(TAG, "INTERFACE is i2c");
    ESP_LOGI(TAG, "CONFIG_SDA_GPIO=%d", CONFIG_SDA_GPIO);
    ESP_LOGI(TAG, "CONFIG_SCL_GPIO=%d", CONFIG_SCL_GPIO);
    ESP_LOGI(TAG, "CONFIG_RESET_GPIO=%d", CONFIG_RESET_GPIO);
    i2c_master_init(&device, CONFIG_SDA_GPIO, CONFIG_SCL_GPIO, CONFIG_RESET_GPIO);
    erdts_init(&packetCtx, RX_BUF_SIZE, TX_BUF_SIZE);

    ESP_LOGI(TAG, "Panel is 128x32");
    ssd1306_init(&device, 128, 32);
    ssd1306_clear_screen(&device, false);
    ssd1306_contrast(&device, 0xff);

    esp_aes_init(&aes_ctx);

    //*** MASTERKEY CREATION ***//
    getRandomString(token, sizeof(token));
    generate_key((uint8_t *) token, strlen(token), key);
    ssd1306_display_text_x3(&device, 1, token, 5, false);
    esp_log_buffer_hexdump_internal("key", key, sizeof(key), ESP_LOG_INFO);
    if (esp_aes_setkey(&aes_ctx, key, erdts_key_length) == MBEDTLS_ERR_AES_INVALID_KEY_LENGTH) {
        ESP_LOGE("AES_CONFIG", "Invalid Keylength");
        return;
    }

    erdts_start_session(&packetCtx, &aes_ctx, key, aes_iv, session_key, RX_BUF_SIZE);

    char msg[128];
    memset(msg, 0, sizeof(msg));


    while (1) {
        uint8_t encrypted[128];
        getRandomString(msg, 128);

        esp_log_buffer_hexdump_internal("msg:", msg, sizeof(msg), ESP_LOG_INFO);
        esp_aes_crypt_cbc(&aes_ctx, ESP_AES_ENCRYPT, sizeof(encrypted), aes_iv, (uint8_t *) msg, encrypted);
        memset(aes_iv, 0, erdts_iv_length);

        sendData(&packetCtx, encrypted, sizeof(encrypted));
        vTaskDelay(10000 / portTICK_PERIOD_MS);
    }

    //xTaskCreate(rx_task, "uart_rx_task", 1024 * 2, NULL, configMAX_PRIORITIES - 6, NULL);
    //xTaskCreate(tx_task, "uart_tx_task", 1024 * 2, NULL, configMAX_PRIORITIES - 5, NULL);
}

//xTaskCreatePinnedToCore() -> task in core zuweisen