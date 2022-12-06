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
#include "ERDTs.h"

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
        .maxLen=1024,
        .queueSize=100
};

QueueHandle_t messageQueue;


void gpio_setup(void) {
    esp_rom_gpio_pad_select_gpio(SET_PIN);
    gpio_set_direction(SET_PIN, GPIO_MODE_OUTPUT);
    gpio_set_level(SET_PIN, 1);
}

void init(void) {
    const uart_config_t uart_config_start = {
            .baud_rate = 9600,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
            .source_clk = UART_SCLK_DEFAULT,
    };

    uart_driver_install(UART_NUM_1, RX_BUF_SIZE, TX_BUF_SIZE, 0, NULL, 0);
    uart_param_config(UART_NUM_1, &uart_config_start);
    uart_set_pin(UART_NUM_1, TXD_PIN, RXD_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    messageQueue = xQueueCreate(100, max_cargo(&packetCtx));
}

int sendData(const void *buffer, int buff_len) {
    uint8_t packet[buff_len + packetCtx.overhead];
    packet[0] = packetCtx.delimiter;
    memcpy(packet + packetCtx.lengthOffset, &buff_len, packetCtx.lengthBytes);
    memcpy(packet + packetCtx.overhead, buffer, buff_len);
    const int txBytes = uart_write_bytes(UART_NUM_1, packet, sizeof(packet));
    return txBytes;
}

_Noreturn static void tx_task(void *arg) {
    static const char *TX_TASK_TAG = "TX_TASK";
    esp_log_level_set(TX_TASK_TAG, ESP_LOG_INFO);
    while (1) {
        if(uxQueueMessagesWaiting(messageQueue)){
            uint8_t *cargo = malloc(max_cargo(&packetCtx));
            xQueueReceive(messageQueue, cargo, 0);
            sendData(cargo, sizeof(cargo));
        }
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
    xTaskCreate(rx_task, "uart_rx_task", 1024 * 2, NULL, configMAX_PRIORITIES, NULL);
    xTaskCreate(tx_task, "uart_tx_task", 1024 * 2, NULL, configMAX_PRIORITIES - 1, NULL);
}
