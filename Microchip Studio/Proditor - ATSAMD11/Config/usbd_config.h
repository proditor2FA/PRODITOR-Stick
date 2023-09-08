/* Auto-generated config file usbd_config.h */
#ifndef USBD_CONFIG_H
#define USBD_CONFIG_H

// <<< Use Configuration Wizard in Context Menu >>>

// ---- USB Device Stack Core Options ----

// <q> High Speed Support
// <i> Enable high speed specific descriptors support, e.g., DeviceQualifierDescriptor and OtherSpeedConfiguration Descriptor.
// <i> High speed support require descriptors description array on start, for LS/FS and HS support in first and second place.
// <id> usbd_hs_sp
#ifndef CONF_USBD_HS_SP
#define CONF_USBD_HS_SP 0
#endif

// ---- USB Device Stack HID keyboard Options ----

// <e> Enable String Descriptors
// <id> usb_hid_keyboard_str_en
#ifndef CONF_USB_HID_KEYBOARD_STR_EN
#define CONF_USB_HID_KEYBOARD_STR_EN 0
#endif
// <s> Language IDs
// <i> Language IDs in c format, split by comma (E.g., 0x0409 ...)
// <id> usb_hid_keyboard_langid
#ifndef CONF_USB_HID_KEYBOARD_LANGID
#define CONF_USB_HID_KEYBOARD_LANGID "0x0409"
#endif

#ifndef CONF_USB_HID_KEYBOARD_LANGID_DESC
#define CONF_USB_HID_KEYBOARD_LANGID_DESC
#endif
// </e>

// <h> HID Keyboard Device Descriptor

// <o> bcdUSB
// <0x0200=> USB 2.0 version
// <0x0210=> USB 2.1 version
// <id> usb_hid_keyboard_bcdusb
#ifndef CONF_USB_HID_KEYBOARD_BCDUSB
#define CONF_USB_HID_KEYBOARD_BCDUSB 0x200
#endif

// <o> bMaxPackeSize0
// <0x0008=> 8 bytes
// <0x0010=> 16 bytes
// <0x0020=> 32 bytes
// <0x0040=> 64 bytes
// <id> usb_hid_keyboard_bmaxpksz0
#ifndef CONF_USB_HID_KEYBOARD_BMAXPKSZ0
#define CONF_USB_HID_KEYBOARD_BMAXPKSZ0 0x40
#endif

// <o> idVender <0x0000-0xFFFF>
// <id> usb_hid_keyboard_idvender
#ifndef CONF_USB_HID_KEYBOARD_IDVENDER
#define CONF_USB_HID_KEYBOARD_IDVENDER 0x3eb
#endif

// <o> idProduct <0x0000-0xFFFF>
// <id> usb_hid_keyboard_idproduct
#ifndef CONF_USB_HID_KEYBOARD_IDPRODUCT
#define CONF_USB_HID_KEYBOARD_IDPRODUCT 0x2401
#endif

// <o> bcdDevice <0x0000-0xFFFF>
// <id> usb_hid_keyboard_bcddevice
#ifndef CONF_USB_HID_KEYBOARD_BCDDEVICE
#define CONF_USB_HID_KEYBOARD_BCDDEVICE 0x100
#endif

// <e> Enable string descriptor of iManufact
// <id> usb_hid_keyboard_imanufact_en
#ifndef CONF_USB_HID_KEYBOARD_IMANUFACT_EN
#define CONF_USB_HID_KEYBOARD_IMANUFACT_EN 0
#endif

#ifndef CONF_USB_HID_KEYBOARD_IMANUFACT
#define CONF_USB_HID_KEYBOARD_IMANUFACT (CONF_USB_HID_KEYBOARD_IMANUFACT_EN * (CONF_USB_HID_KEYBOARD_IMANUFACT_EN))
#endif

// <s> Unicode string of iManufact
// <id> usb_hid_keyboard_imanufact_str
#ifndef CONF_USB_HID_KEYBOARD_IMANUFACT_STR
#define CONF_USB_HID_KEYBOARD_IMANUFACT_STR "PRODITOR"
#endif

#ifndef CONF_USB_HID_KEYBOARD_IMANUFACT_STR_DESC
#define CONF_USB_HID_KEYBOARD_IMANUFACT_STR_DESC
#endif

// </e>

// <e> Enable string descriptor of iProduct
// <id> usb_hid_keyboard_iproduct_en
#ifndef CONF_USB_HID_KEYBOARD_IPRODUCT_EN
#define CONF_USB_HID_KEYBOARD_IPRODUCT_EN 0
#endif

#ifndef CONF_USB_HID_KEYBOARD_IPRODUCT
#define CONF_USB_HID_KEYBOARD_IPRODUCT                                                                                 \
	(CONF_USB_HID_KEYBOARD_IPRODUCT_EN * (CONF_USB_HID_KEYBOARD_IMANUFACT_EN + CONF_USB_HID_KEYBOARD_IPRODUCT_EN))
#endif

// <s> Unicode string of iProduct
// <id> usb_hid_keyboard_iproduct_str
#ifndef CONF_USB_HID_KEYBOARD_IPRODUCT_STR
#define CONF_USB_HID_KEYBOARD_IPRODUCT_STR "Proditor"
#endif

#ifndef CONF_USB_HID_KEYBOARD_IPRODUCT_STR_DESC
#define CONF_USB_HID_KEYBOARD_IPRODUCT_STR_DESC
#endif

// </e>

// <e> Enable string descriptor of iSerialNum
// <id> usb_hid_keyboard_iserialnum_en
#ifndef CONF_USB_HID_KEYBOARD_ISERIALNUM_EN
#define CONF_USB_HID_KEYBOARD_ISERIALNUM_EN 0
#endif

#ifndef CONF_USB_HID_KEYBOARD_ISERIALNUM
#define CONF_USB_HID_KEYBOARD_ISERIALNUM                                                                               \
	(CONF_USB_HID_KEYBOARD_ISERIALNUM_EN                                                                               \
	 * (CONF_USB_HID_KEYBOARD_IMANUFACT_EN + CONF_USB_HID_KEYBOARD_IPRODUCT_EN + CONF_USB_HID_KEYBOARD_ISERIALNUM_EN))
#endif

// <s> Unicode string of iSerialNum
// <id> usb_hid_keyboard_iserialnum_str
#ifndef CONF_USB_HID_KEYBOARD_ISERIALNUM_STR
#define CONF_USB_HID_KEYBOARD_ISERIALNUM_STR "123456789ABCDEF"
#endif

#ifndef CONF_USB_HID_KEYBOARD_ISERIALNUM_STR_DESC
#define CONF_USB_HID_KEYBOARD_ISERIALNUM_STR_DESC
#endif

// </e>

// </h>

// <h> HID Keyboard Configuration Descriptor

// <e> Enable string descriptor of iConfig
// <id> usb_hid_keyboard_iconfig_en
#ifndef CONF_USB_HID_KEYBOARD_ICONFIG_EN
#define CONF_USB_HID_KEYBOARD_ICONFIG_EN 0
#endif

#ifndef CONF_USB_HID_KEYBOARD_ICONFIG
#define CONF_USB_HID_KEYBOARD_ICONFIG                                                                                  \
	(CONF_USB_HID_KEYBOARD_ICONFIG_EN                                                                                  \
	 * (CONF_USB_HID_KEYBOARD_IMANUFACT_EN + CONF_USB_HID_KEYBOARD_IPRODUCT_EN + CONF_USB_HID_KEYBOARD_ISERIALNUM_EN   \
	    + CONF_USB_HID_KEYBOARD_ICONFIG_EN))
#endif

// <s> Unicode string of iConfig
// <id> usb_hid_keyboard_iconfig_str
#ifndef CONF_USB_HID_KEYBOARD_ICONFIG_STR
#define CONF_USB_HID_KEYBOARD_ICONFIG_STR ""
#endif

#ifndef CONF_USB_HID_KEYBOARD_ICONFIG_STR_DESC
#define CONF_USB_HID_KEYBOARD_ICONFIG_STR_DESC
#endif

// </e>

// <o> bmAttributes
// <0x80=> Bus power supply, not support for remote wakeup
// <0xA0=> Bus power supply, support for remote wakeup
// <0xC0=> Self powered, not support for remote wakeup
// <0xE0=> Self powered, support for remote wakeup
// <id> usb_hid_keyboard_bmattri
#ifndef CONF_USB_HID_KEYBOARD_BMATTRI
#define CONF_USB_HID_KEYBOARD_BMATTRI 0x80
#endif

// <o> bMaxPower <0x00-0xFF>
// <id> usb_hid_keyboard_bmaxpower
#ifndef CONF_USB_HID_KEYBOARD_BMAXPOWER
#define CONF_USB_HID_KEYBOARD_BMAXPOWER 0x32
#endif
// </h>

// <h> HID Keyboard Interface Descriptor

// <o> bInterfaceNumber <0x00-0xFF>
// <id> usb_hid_keyboard_bifcnum
#ifndef CONF_USB_HID_KEYBOARD_BIFCNUM
#define CONF_USB_HID_KEYBOARD_BIFCNUM 0x0
#endif

// <o> iInterface <0x00-0xFF>
// <id> usb_hid_keyboard_iifc
#ifndef CONF_USB_HID_KEYBOARD_IIFC
#define CONF_USB_HID_KEYBOARD_IIFC 0x0
#endif

// <o> INTERRUPT IN Endpoint Address
// <0x81=> EndpointAddress = 0x81
// <0x82=> EndpointAddress = 0x82
// <0x83=> EndpointAddress = 0x83
// <0x84=> EndpointAddress = 0x84
// <0x85=> EndpointAddress = 0x85
// <0x86=> EndpointAddress = 0x86
// <0x87=> EndpointAddress = 0x87
// <id> usb_hid_keyboard_intin_epaddr
// <i> Please make sure that the setting here is coincide with the endpoint setting in USB device driver.
#ifndef CONF_USB_HID_KEYBOARD_INTIN_EPADDR
#define CONF_USB_HID_KEYBOARD_INTIN_EPADDR 0x81
#endif

// <o> INTERRUPT IN Endpoint wMaxPacketSize
// <0x0008=> 8 bytes
// <0x0010=> 16 bytes
// <0x0020=> 32 bytes
// <0x0040=> 64 bytes
// <id> usb_hid_keyboard_intin_maxpksz
// <i> Please make sure that the setting here is coincide with the endpoint setting in USB device driver.
#ifndef CONF_USB_HID_KEYBOARD_INTIN_MAXPKSZ
#define CONF_USB_HID_KEYBOARD_INTIN_MAXPKSZ 0x8
#endif

// <o> INTERRUPT OUT Endpoint Address
// <0x01=> EndpointAddress = 0x01
// <0x02=> EndpointAddress = 0x02
// <0x03=> EndpointAddress = 0x03
// <0x04=> EndpointAddress = 0x04
// <0x05=> EndpointAddress = 0x05
// <0x06=> EndpointAddress = 0x06
// <0x07=> EndpointAddress = 0x07
// <id> usb_hid_keyboard_intout_epaddr
// <i> Please make sure that the setting here is coincide with the endpoint setting in USB device driver.
#ifndef CONF_USB_HID_KEYBOARD_INTOUT_EPADDR
#define CONF_USB_HID_KEYBOARD_INTOUT_EPADDR 0x1
#endif

// <o> INTERRUPT OUT Endpoint wMaxPacketSize
// <0x0008=> 8 bytes
// <0x0010=> 16 bytes
// <0x0020=> 32 bytes
// <0x0040=> 64 bytes
// <id> usb_hid_keyboard_intout_maxpksz
// <i> Please make sure that the setting here is coincide with the endpoint setting in USB device driver.
#ifndef CONF_USB_HID_KEYBOARD_INTOUT_MAXPKSZ
#define CONF_USB_HID_KEYBOARD_INTOUT_MAXPKSZ 0x8
#endif

// </h>

// <<< end of configuration section >>>

#endif // USBD_CONFIG_H
