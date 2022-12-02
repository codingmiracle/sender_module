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


static const int RX_BUF_SIZE = 1024;
uint8_t plaintext[16384];
uint8_t encrypted[16384];

QueueHandle_t messageQueue;
QueueHandle_t encryptedQueue;

int sendData(const char *logName, const char *data);

#define TXD_PIN (GPIO_NUM_17)
#define RXD_PIN (GPIO_NUM_16)
#define SET_PIN (GPIO_NUM_4)
#define FLAG_PIN (GPIO_NUM_5)

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
    esp_rom_gpio_pad_select_gpio(FLAG_PIN);
    gpio_set_direction(SET_PIN, GPIO_MODE_OUTPUT);
    gpio_set_direction(FLAG_PIN, GPIO_MODE_OUTPUT);
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
    uart_driver_install(UART_NUM_1, RX_BUF_SIZE * 2, 0, 0, NULL, 0);
    uart_param_config(UART_NUM_1, &uart_config_start);
    uart_set_pin(UART_NUM_1, TXD_PIN, RXD_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    /*gpio_set_level(SET_PIN, 0);
    vTaskDelay(200);
    sendData("TX_CONFIG", "AT+B115200");
    uart_param_config(UART_NUM_1, &uart_config_hc12);
    gpio_set_level(SET_PIN, 1);*/
}

int sendData(const char *logName, const char *data) {
    const int len = strlen(data);
    const int txBytes = uart_write_bytes(UART_NUM_1, data, len);
    ESP_LOGI(logName, "Wrote %d bytes", txBytes);
    return txBytes;
}

_Noreturn static void tx_task(void *arg) {
    static const char *TX_TASK_TAG = "TX_TASK";
    esp_log_level_set(TX_TASK_TAG, ESP_LOG_INFO);
    while (1) {
        sendData(TX_TASK_TAG, "Hello, World!\n");
        vTaskDelay(2000 / portTICK_PERIOD_MS);
    }
}

static void rx_task(void *arg) {
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

static void encrypt_task(void *arg) {
    static const char *EN_TASK_TAG = "ENC_TASK";
    esp_log_level_set(EN_TASK_TAG, ESP_LOG_INFO);
}


static inline int32_t getCycleCount(void) {
    int32_t ccount;
    __asm__ __volatile__("rsr %0,ccount": "=a" (ccount));
    return ccount;
}

double avgenc = 0;
double avgdec = 0;


int encodetest(int buff_len) {
    const int key_length = 256;
    int val[2] = {10000, 1000};
    const char* text = "Someserious stuff";
    uint8_t key[key_length];
    uint8_t iv[16];

    //If you have cryptographically random data in the start of your payload, you do not need
    //an IV.  If you start a plaintext payload, you will need an IV.
    memset(iv, 61, sizeof(iv));
    memset(key, 61, sizeof(key));
    //esp_fill_random(key, sizeof(key));

    memset(plaintext, 0, buff_len);
    strcpy((char *)plaintext, text);

    //Just FYI - you must be encrypting/decrypting data that is in BLOCKSIZE chunks!!!

    esp_aes_context ctx;
    esp_aes_init(&ctx);
    if (esp_aes_setkey(&ctx, key, key_length) == MBEDTLS_ERR_AES_INVALID_KEY_LENGTH) {
        ESP_LOGE("AES_CONFIG", "Invalid Keylength");
    }
    ESP_LOG_BUFFER_HEXDUMP("AES_DATA", plaintext, strlen(text), ESP_LOG_INFO);
    ESP_LOG_BUFFER_HEXDUMP("AES_IV", iv, 16, ESP_LOG_INFO);
    ESP_LOG_BUFFER_HEXDUMP("AES_KEY", key, key_length, ESP_LOG_INFO);
    int32_t start = getCycleCount();
    esp_aes_crypt_cbc(&ctx, ESP_AES_ENCRYPT, buff_len, iv, plaintext, encrypted);
    int32_t end = getCycleCount();
    double enctime = (end - start) / 240.0;
    avgenc += enctime;
    printf("Encryption time: %.2fus  (%f MB/s)\n", enctime, buff_len * 1.0 / enctime);
    //See encrypted payload, and wipe out plaintext.
    ESP_LOG_BUFFER_HEXDUMP("AES_ENCRYPTED", encrypted, buff_len, ESP_LOG_INFO);
    printf("%s", encrypted);
    memset(plaintext, 0, buff_len);
    //for (int i = 0; i < 128; i++) {
    //    printf("%02x[%c]%c", encrypted[i], (encrypted[i] > 31) ? encrypted[i] : ' ', ((i & 0xf) != 0xf) ? ' ' : '\n');
    //}
    //printf("\n");
    printf( "IV: %02x %02x\n", iv[0], iv[1] );
    memset(iv, 61, sizeof(iv));
    memset(&plaintext, 0, buff_len);
    memset(&val, 0, sizeof (val));

    //Use the ESP32 to decrypt the CBC block.
    start = getCycleCount();
    esp_aes_crypt_cbc(&ctx, ESP_AES_DECRYPT, buff_len, iv, (uint8_t *) encrypted, (uint8_t *) plaintext);
    end = getCycleCount();
    enctime = (end - start) / 240.0;
    avgdec += enctime;
    printf("Decryption time: %.2fus  (%f MB/s)\n", enctime, buff_len * 1.0 / enctime);

    //Verify output
    for (int i = 0; i < 128; i++) {
        printf("%02x[%c]%c", plaintext[i], (plaintext[i] > 31) ? plaintext[i] : ' ', ((i & 0xf) != 0xf) ? ' ' : '\n');
    }
    printf("\n");
    memcpy(&val, plaintext, sizeof (val));
    //ESP_LOG_BUFFER_HEXDUMP("PLAIN-INT",&val, sizeof (val), ESP_LOG_INFO);
    //printf("%d %d\n", val[0], val[1]);

    esp_aes_free(&ctx);
    return 0;
}



void app_main(void) {
    //int buff_lens_to_test[] = {256, 512, 1024, 2048, 4096, 8192,16384};
    //for(int i = 0;i<sizeof(buff_lens_to_test)/sizeof(buff_lens_to_test[0]);i++) {
    //    printf("Buffer-length-%d:\n", buff_lens_to_test[i]);
    //    encodetest(buff_lens_to_test[i]);
    //}
    int val = 1000;
    messageQueue = xQueueCreate(10, sizeof(int));
    encryptedQueue = xQueueCreate(10, sizeof(int));
    for(int i = 0; i < 10; i++) {
        xQueueSendToBack(messageQueue, &val, 0);
    }
    if(uxQueueMessagesWaiting(messageQueue)) {
        ESP_LOGI("QUEUE", "Messages in Queue");
    }
    int *plain = malloc(sizeof(int)*10);
    memset(plain, 0, 10 * sizeof(int));
    for(int i = 0; i < 10; i++) {
        xQueueReceive(messageQueue, plain+i, 0);
    }
    ESP_LOG_BUFFER_HEXDUMP("QUEUE", plain, sizeof(int)*10, ESP_LOG_INFO);
    if(val == plain[0])
        ESP_LOGI("QUEUE", "success");

    //encodetest(1024);

    //if(xQueueReceive(messageQueue, plain, 1) == pdTRUE) {
    //    ESP_LOG_BUFFER_HEXDUMP("ENC-QUEUE", plain, sizeof(plain), ESP_LOG_INFO);
    //}

    init();
    xTaskCreate(rx_task, "uart_rx_task", 1024*2, NULL, configMAX_PRIORITIES, NULL);
    xTaskCreate(tx_task, "uart_tx_task", 1024*2, NULL, configMAX_PRIORITIES-1, NULL);
}
