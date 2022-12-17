//
// Created by dagra on 04/12/2022.
//
#include "ERDTs.h"

QueueHandle_t packetQueue = NULL;
QueueHandle_t dataQueue = NULL;

void erdts_config(const parser_packet_ctx *ctx, int rx_buff_size, int tx_buff_size) {
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

    xTaskCreate(erdts_tx_task, "erdts_tx_task", 1024 * 2, (void *) ctx, configMAX_PRIORITIES - 0, NULL);
    //xTaskCreate(erdts_encrypt_task, "erdts_encrypt_task", 1024 * 2, (void *) ctx, configMAX_PRIORITIES - 1, NULL);

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

int erdts_send(const parser_packet_ctx *ctx, uint8_t *bytes, int byte_len) {
    uint8_t *packet = parse_packet(ctx, bytes, byte_len);
    vTaskDelay(1000/portTICK_PERIOD_MS);
    int packetLen = erdts_getPacketLen(ctx, packet);
    if (packet == NULL) {
        ESP_LOGI("SEND", "packet is NULL");
        free(packet);
        return -1;
    } else {
        ESP_LOG_BUFFER_HEXDUMP("SEND", &packetLen, sizeof (packetLen), ESP_LOG_INFO);
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

_Noreturn static void erdts_tx_task(void *args) {
    static const char *TX_TASK_TAG = "TX_PACKET";
    esp_log_level_set(TX_TASK_TAG, ESP_LOG_INFO);
    parser_packet_ctx *ctx = (parser_packet_ctx *) args;
    uint8_t packet[ctx->maxLen];
    while (1) {
        if (packetQueue != NULL) {
            if (uxQueueMessagesWaiting(packetQueue)) {
                xQueueReceive(packetQueue, packet, 0);
                ESP_LOG_BUFFER_HEXDUMP(TX_TASK_TAG, packet, erdts_getPacketLen(ctx, packet), ESP_LOG_INFO);
                const int txBytes = uart_write_bytes(UART_NUM_1, packet, erdts_getPacketLen(ctx, packet));
                uart_wait_tx_done(UART_NUM_1, 0);
                ESP_LOGI(TX_TASK_TAG, "tx done");
            } else {
                vTaskDelay(10/portTICK_PERIOD_MS);
            }
        }
    }
}

_Nonnull void erdts_encrypt_task(void *args) {
    static const char *TX_TASK_TAG = "ENCRYPT_TASK";
    esp_log_level_set(TX_TASK_TAG, ESP_LOG_INFO);
    parser_packet_ctx *ctx = (parser_packet_ctx *) args;
    while (1) {

    }
}