#include <sys/select.h>
#include <sys/cdefs.h>
#include <mbedtls/aes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "driver/uart.h"
#include "string.h"
#include "driver/gpio.h"
#include "aes/esp_aes.h"
#include "esp_random.h"
#include "../components/erdts/ERDTs.h"

#define TXD_PIN (GPIO_NUM_17)
#define RXD_PIN (GPIO_NUM_16)
#define SET_PIN (GPIO_NUM_4)

const int RX_BUF_SIZE = 2048;
const int TX_BUF_SIZE = 0; // 0 => send imidiately

const parser_packet_ctx packetCtx = {
        .delimiter=0xaa,
        .overhead=3,
        .lengthBytes=2,
        .lengthOffset=1,
        .maxLen=1027,
        .queueSize=100
};

QueueHandle_t messageQueue;


void gpio_setup(void) {
    esp_rom_gpio_pad_select_gpio(SET_PIN);
    gpio_set_direction(SET_PIN, GPIO_MODE_OUTPUT);
    gpio_set_level(SET_PIN, 1);
}

void init(void) {
    erdts_config(&packetCtx, RX_BUF_SIZE, TX_BUF_SIZE);
}

_Noreturn static void tx_task(void *arg) {
    static const char *TX_TASK_TAG = "TX_TASK";
    esp_log_level_set(TX_TASK_TAG, ESP_LOG_INFO);
    const char msg[] = "Hello World!! This is a test Text haskhgadl759236ß97329";
    while (1) {
        erdts_send(&packetCtx, msg, strlen(msg));
        vTaskDelay(2000/portTICK_PERIOD_MS);
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
    init();
    xTaskCreate(rx_task, "uart_rx_task", 1024 * 2, NULL, configMAX_PRIORITIES - 6, NULL);
    xTaskCreate(tx_task, "uart_tx_task", 1024 * 2, NULL, configMAX_PRIORITIES - 5, NULL);
}
