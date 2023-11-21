
/*********************************************************************/
/*   _____   ______  _____  ______  _____ _______  _____   ______    */
/*   |_____] |_____/ |     | |     \   |      |    |     | |_____/   */
/*   |       |    \_ |_____| |_____/ __|__    |    |_____| |    \_   */
/*                                                                   */
/*********************************************************************/

/* This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, version 3.
  
   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
   General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program. If not, see <http://www.gnu.org/licenses/>.*/

/*
* 
* Atmel Studio: undefined reference to `_read'
* Project Properties -> Toolchain -> ARM/GNU Linker -> General -> Additional Specs -> Use syscall stubs 
* 
*/

#include "driver_init.h"
#include "hiddf_keyboard.h"
#include "hiddf_keyboard_desc.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <hal_delay.h>
#include "hotp.h"

//read the secret from flash located at position 0x3eec ((last flash page -1) - 0x14)
#define READ_SECRET_FROM_FLASH

//set security bit on first power up for copy protection - only a full chip erase will help! 
//#define SET_SECURITY_BIT_ON_FIRST_STARTUP

//send a roll-key code every 60 seconds for presence detection
#define SEND_ROLL_KEY_EVERY_MINUTE

//hotp setup
static char secret[] = {0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30}; //12345678901234567890
#define HOTP_DIGITS 8 //6 or 8 digits
//uint32_t expected_6[] = {755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489};
//uint32_t expected_8[] = {84755224, 94287082, 37359152, 26969429, 40338314, 68254676, 18287922, 82162583, 73399871, 45520489};

//flash organization
static const uint32_t pageSize[] = { 8, 16, 32, 64, 128, 256, 512, 1024 };
static unsigned char eeBuffer[4];
static uint32_t eePageADDR = 0;

//hotp_main
static char hotpPart[8];
static uint32_t hotpResult = 0;
static uint8_t keyCode = 0;
static bool keyReleased = true;
static uint32_t hCounter = 0;
static uint8_t keyInterval;
static uint16_t softTimer = 3000;
#define rollKeyTiming 60000 //ms
static bool rollKeyReset = false;

static struct hiddf_kb_key_descriptors key_array[3] = {
    {HID_MODIFIER_LEFT_CTRL, true, HID_KB_KEY_UP},
    {HID_MODIFIER_LEFT_ALT, true, HID_KB_KEY_UP},
    {HID_DELETE, false, HID_KB_KEY_UP},
};

static uint8_t ctrl_buffer[64];

static uint8_t single_desc_bytes[] = {
	/* Device descriptors and Configuration descriptors list. */
HID_KEYBOARD_DESCES_LS_FS};

static struct usbd_descriptors single_desc[] = {{single_desc_bytes, single_desc_bytes + sizeof(single_desc_bytes)}
#if CONF_USBD_HS_SP
												,
												{NULL, NULL}
#endif
};


static void usbd_sof_event(void)
{
	/*
	#define HID_1 30
	...
	#define HID_9 38
	#define HID_0 39
	#define HID_ENTER 40
	*/

	if (keyInterval++ > 30) {
		keyInterval = 0;
		if (!keyReleased) {
			gpio_set_pin_level(LED0, 1);
			key_array[2].state = HID_KB_KEY_UP;
			keyReleased = true;
		} else {
			if (keyCode > 0) {
				gpio_set_pin_level(LED0, 0);
				key_array[2].key_id = keyCode;
				key_array[2].state = HID_KB_KEY_DOWN;
				keyCode = 0;
				keyReleased = false;
			}
		}
		hiddf_keyboard_keys_state_change(key_array, 3);
	}
	if(softTimer > 0){
		softTimer --;
	}
}

static struct usbdc_handler usbd_sof_event_h = {NULL, (FUNC_PTR)usbd_sof_event};


void flash_init(void)
{
	eePageADDR = (pageSize[NVMCTRL->PARAM.bit.PSZ] * NVMCTRL->PARAM.bit.NVMP ) - 0x100; //D11 = 0x3F00 - D21 = 0x3FF00
	uint32_t cntValueADDR1 = eePageADDR + 0xc0;
	uint32_t cntValueADDR2 = eePageADDR + 0xf0;

#ifdef READ_SECRET_FROM_FLASH

	uint32_t secretADDR = eePageADDR - 0x14;
	memcpy(secret, (char*)secretADDR, 0x14);

#endif

	memcpy(eeBuffer, (uint32_t *)cntValueADDR1, 0x04); //load counter
	if (eeBuffer[3] == 0xff){
		memcpy(eeBuffer, (uint32_t *)cntValueADDR2, 0x04); //load alt-counter - first start

#ifdef SET_SECURITY_BIT_ON_FIRST_STARTUP

		NVMCTRL->CTRLA.reg = NVMCTRL_CTRLA_CMDEX_KEY | NVMCTRL_CTRLA_CMD_SSB;
		while (!NVMCTRL->INTFLAG.bit.READY);

#endif
	}

	hCounter = (eeBuffer[3] << 24 )| (eeBuffer[2] << 16)| (eeBuffer[1] << 8)| (eeBuffer[0] << 0);
	//hCounter = 0xaabbccdd;
	
	PM->AHBMASK.reg |= PM_AHBMASK_NVMCTRL;
	PM->APBBMASK.reg |= PM_APBBMASK_NVMCTRL;
	//NVMCTRL->CTRLB.bit.MANW = 0;
	// Disable automatic page write
	NVMCTRL->CTRLB.bit.MANW = 1;
}


void flash_write(uint32_t Value)
{
	uint32_t buffer[64]; //256 bytes aligned at 4 byte boundary
	memcpy(buffer, (const void *)eePageADDR, 0x100);
    
	//EE Value store position / last row, two times 
	buffer[48] = Value; buffer[60] = Value;
	
	// Disable Cache
	//uint32_t temp = NVMCTRL->CTRLB.reg;
	//NVMCTRL->CTRLB.reg = temp | NVMCTRL_CTRLB_CACHEDIS;
	
	//Clear error flags
	NVMCTRL->STATUS.reg |= NVMCTRL_STATUS_MASK;
	
	//Set address, command will be issued elsewhere
	NVMCTRL->ADDR.reg = eePageADDR >> 1;
	
	//Erase flash
	NVMCTRL->CTRLA.reg = NVMCTRL_CTRLA_CMDEX_KEY | NVMCTRL_CTRLA_CMD_ER;
	while (0 == NVMCTRL->INTFLAG.bit.READY);

	for (uint32_t i = 0; i < NVMCTRL_ROW_SIZE / sizeof(uint32_t); i++)
	*(uint32_t *)(eePageADDR + i * sizeof(uint32_t)) = buffer[i];
	
	//Execute "WP" Write Page
	NVMCTRL->CTRLA.reg = NVMCTRL_CTRLA_CMDEX_KEY | NVMCTRL_CTRLA_CMD_WP;
	while (!NVMCTRL->INTFLAG.bit.READY);
}


int main(void)
{
	int i = 0;
	system_init();
	
	flash_init();
	
	gpio_set_pin_pull_mode(SW0, GPIO_PULL_UP);

	/* usb stack init */
	usbdc_init(ctrl_buffer);

	/* usbdc_register_funcion inside */
	hiddf_keyboard_init();

	usbdc_start(single_desc);
	usbdc_attach();

	while (!hiddf_keyboard_is_enabled()) {
		// wait hid keyboard to be installed
	};

	usbdc_register_handler(USBDC_HDL_SOF, &usbd_sof_event_h);
	
	gpio_set_pin_level(LED0, 1);
	while (1) {

#ifdef SEND_ROLL_KEY_EVERY_MINUTE

		if ((softTimer == 0) && keyReleased && (keyInterval > 5) ) {
			keyCode = 71; //rollKey (keyCode 145 on Windows)
			softTimer = rollKeyTiming;
			rollKeyReset = true;	
		}
		if (rollKeyReset && keyReleased && (keyInterval > 5) && (keyCode == 0)) {
			keyCode = 71;
			rollKeyReset = false;
		}
		
#endif

		if ((!gpio_get_pin_level(SW0)) && !rollKeyReset && (keyCode == 0)) {
			hCounter ++;
			hotpResult = hotp(HOTP_DIGITS, secret, sizeof(secret), hCounter);
			//sprintf(hotpPart, "%lu", hotpResult);
			int index = HOTP_DIGITS - 1;
			while (hotpResult != 0 && index >= 0) {
				hotpPart[index] = hotpResult % 10;
				hotpResult /= 10;
				index--;
			}

			for (i=0; i<=(HOTP_DIGITS - 1); i++){
				if(hotpPart[i] == 0) {
					keyCode = 39; //zero;
					} else {
					keyCode = (uint8_t)hotpPart[i] + 29;
				}
				while(keyCode > 0) {
				delay_ms(50);
				//gpio_get_pin_level(SW0); //dummy	
				}
			}
	
			keyCode = 40; //0x28 enter
			while ((!gpio_get_pin_level(SW0)) | (keyCode > 0) | (keyReleased == false)) {
			}

		flash_write(hCounter);
		softTimer = rollKeyTiming;
		}
	}
}

