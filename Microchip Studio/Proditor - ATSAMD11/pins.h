/*
 * Code generated from Atmel Start.
 *
 * This file will be overwritten when reconfiguring your Atmel Start project.
 * Please copy examples or other code you want to keep to a separate file
 * to avoid losing it when reconfiguring.
 */
#ifndef ATMEL_START_PINS_H_INCLUDED
#define ATMEL_START_PINS_H_INCLUDED

#include <hal_gpio.h>

// SAMD11 has 8 pin functions

#define GPIO_PIN_FUNCTION_A 0
#define GPIO_PIN_FUNCTION_B 1
#define GPIO_PIN_FUNCTION_C 2
#define GPIO_PIN_FUNCTION_D 3
#define GPIO_PIN_FUNCTION_E 4
#define GPIO_PIN_FUNCTION_F 5
#define GPIO_PIN_FUNCTION_G 6
#define GPIO_PIN_FUNCTION_H 7

//#define BUTTON2 GPIO(GPIO_PORTA, 2)
//#define BUTTON3 GPIO(GPIO_PORTA, 3)
//#define BUTTON1 GPIO(GPIO_PORTA, 14)
#define PA24 GPIO(GPIO_PORTA, 24)
#define PA25 GPIO(GPIO_PORTA, 25)

//SAM-D11 xplained
//#define SW0 GPIO(GPIO_PORTA, 14)
//#define LED0 GPIO(GPIO_PORTA, 16)

//PRODITOR Stick
#define SW0 GPIO(GPIO_PORTA, 5)
#define LED0 GPIO(GPIO_PORTA, 4)

#endif // ATMEL_START_PINS_H_INCLUDED
