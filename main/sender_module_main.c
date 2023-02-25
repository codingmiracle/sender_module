#include <sys/cdefs.h>
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


typedef struct {
    esp_aes_context *aes_ctx;
    uint8_t *iv;
    int rx_buff_size;
    char *token;
} rx_task_params;

_Noreturn static void rx_task(void *arg) {
    static const char *RX_TASK_TAG = "RX_TASK";
    esp_log_level_set(RX_TASK_TAG, ESP_LOG_INFO);
    rx_task_params *params = (rx_task_params*) arg;
    uint8_t *data = (uint8_t *) malloc(params->rx_buff_size);
    while (1) {
        int rx_bytes = erdts_read(params->aes_ctx, params->iv, data, params->rx_buff_size);
        if(rx_bytes > 0) {
            if(check_flag(data) == ERDTS_END) {
                erdts_end_session(params->aes_ctx, &packetCtx, params->iv, params->token);
            }
            esp_log_buffer_hexdump_internal(RX_TASK_TAG, data, rx_bytes, ESP_LOG_INFO);
        }
    }
    free(data);
}

_Noreturn void app_main(void) {
    SSD1306_t device;
    esp_aes_context aes_ctx;

    const char *TAG = "SSD1306";

    char token[6];
    uint8_t session_key[erdts_key_length / 8];
    uint8_t aes_iv[erdts_iv_length];
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
    ssd1306_display_text_x3(&device, 1, token, 5, false);

    erdts_start_session(&packetCtx, &aes_ctx, token, aes_iv, session_key, RX_BUF_SIZE);

    rx_task_params rx_params = {
            .aes_ctx = &aes_ctx,
            .iv = aes_iv,
            .token = token,
            .rx_buff_size = RX_BUF_SIZE
    };
    xTaskCreatePinnedToCore(rx_task, "uart_rx_task", 1024 * 2, (void*) &rx_params, configMAX_PRIORITIES - 6, NULL, PRO_CPU_NUM);


    char msg[128];
    memset(msg, 0, sizeof(msg));


    while (1) {
        uint8_t encrypted[128];
        getRandomString(msg, 128);

        //esp_log_buffer_hexdump_internal("msg:", msg, sizeof(msg), ESP_LOG_INFO);
        esp_aes_crypt_cbc(&aes_ctx, ESP_AES_ENCRYPT, sizeof(encrypted), aes_iv, (uint8_t *) msg, encrypted);
        memset(aes_iv, 0, erdts_iv_length);

        sendData(&packetCtx, encrypted, sizeof(encrypted));
    }
}

//TODO: test latency and bitrate