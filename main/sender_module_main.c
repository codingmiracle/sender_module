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

const uint8_t packet_delimiter = 0xaa;
const int packet_overhead = 3;
const int packet_lengthBytes = 2;
const int packet_lengthOffset = 1;
const int packet_maxLen = 1024;

const int RX_BUF_SIZE = packet_maxLen;
const int TX_BUF_SIZE = packet_maxLen;


#define TXD_PIN (GPIO_NUM_17)
#define RXD_PIN (GPIO_NUM_16)
#define SET_PIN (GPIO_NUM_4)

const uart_config_t uart_config_hc12 = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
};

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

    // We won't use a buffer for sending data.
    uart_driver_install(UART_NUM_1, RX_BUF_SIZE, TX_BUF_SIZE, 0, NULL, 0);
    uart_param_config(UART_NUM_1, &uart_config_start);
    uart_set_pin(UART_NUM_1, TXD_PIN, RXD_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
}

int sendData(const char *logName, const void *buffer, int buff_len) {
    uint8_t packet[buff_len + packet_overhead];
    packet[0] = packet_delimiter;
    memcpy(packet + packet_lengthOffset, &buff_len, packet_lengthBytes);
    memcpy(packet + packet_overhead, buffer, buff_len);
    const int txBytes = uart_write_bytes(UART_NUM_1, packet, sizeof(packet));
    ESP_LOGI(logName, "Wrote %d bytes: ", txBytes);
    ESP_LOG_BUFFER_HEXDUMP(logName, packet, sizeof(packet), ESP_LOG_INFO);
    return txBytes;
}

_Noreturn static void tx_task(void *arg) {
    static const char *TX_TASK_TAG = "TX_TASK";
    esp_log_level_set(TX_TASK_TAG, ESP_LOG_INFO);
    const char msg[] = "Hello";
    while (1) {
        sendData(TX_TASK_TAG, msg, strlen(msg));
        vTaskDelay(20 / portTICK_PERIOD_MS);
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
