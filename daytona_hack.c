#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/gpio.h>
#include <linux/spi/cpcap.h>
#include <linux/spi/cpcap-regbits.h>
#include <linux/cpcap_wdog.h>
#include <linux/cpcap-accy.h>
#include <linux/kallsyms.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/delay.h>

#include "../../arch/arm/mach-tegra/gpio-names.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ion Agorria");
MODULE_DESCRIPTION("Daytona Halt And Catch Key - Loads payload and enters RCM ready for trigger");

enum cpcap_det_state {
    HACK_DUMMY_ENUM
};

//Copied from drivers/mfd/cpcap-usb-det.c, we only want usb_accy position (thus it has to match if used on another source)
struct hack_cpcap_usb_det_data {
        struct cpcap_device *cpcap;
        struct delayed_work work;
        struct workqueue_struct *wq;
        unsigned short sense;
        unsigned short prev_sense;
        enum cpcap_det_state state;
        enum cpcap_accy usb_accy;
        //Rest is irrelevant
};

// payload.h generated using: 
// cat fusee-tools/payloads/out/T20/dump_sbk_usb.bin | xxd -i > payload.h
const uint8_t iram_payload[] = {
#include "payload.h"
};

//Symbols to search like a caveman
struct cpcap_device *hack_cpcap_ptr = 0;
struct cpcap_wdt *hack_cpcap_wdt_ptr = 0;
int (*hack_cpcap_wdt_stop)(struct cpcap_wdt *wdt) = 0;
int (*hack_cpcap_regacc_read)(struct cpcap_device *cpcap, enum cpcap_reg reg, unsigned short *value_ptr) = 0;
int (*hack_cpcap_regacc_read_secondary)(struct cpcap_device *cpcap, enum cpcap_reg reg, unsigned short *value_ptr) = 0;
int (*hack_cpcap_regacc_write)(struct cpcap_device *cpcap, enum cpcap_reg reg, unsigned short value, unsigned short mask) = 0;
int (*hack_cpcap_regacc_write_secondary)(struct cpcap_device *cpcap, enum cpcap_reg reg, unsigned short value, unsigned short mask) = 0;

static int hack_scan_symbols(void *data, const char *namebuf, struct module *module, unsigned long address)
{
     if (!strcmp(namebuf, "misc_cpcap")) {
         hack_cpcap_ptr = *((struct cpcap_device**) address);
     }
     
     if (!strcmp(namebuf, "wdt_ptr")) {
         hack_cpcap_wdt_ptr = *((struct cpcap_wdt**) address);
     }
     
     if (!strcmp(namebuf, "cpcap_wdt_stop")) {
         hack_cpcap_wdt_stop = (void*) address;
     }

     if (!strcmp(namebuf, "cpcap_regacc_read")) {
         hack_cpcap_regacc_read  = (void*) address;
     }

     if (!strcmp(namebuf, "cpcap_regacc_read_secondary")) {
         hack_cpcap_regacc_read_secondary  = (void*) address;
     }
     
     if (!strcmp(namebuf, "cpcap_regacc_write")) {
         hack_cpcap_regacc_write = (void*) address;
     }
     
     if (!strcmp(namebuf, "cpcap_regacc_write_secondary")) {
         hack_cpcap_regacc_write_secondary = (void*) address;
     }
     
     return 0;
}

int init_module(void)
{
    int ret;
    
    printk(KERN_ALERT "Daytona HACK: Loaded module!\n");
    
    //Locate the data by symbols in kernel
    kallsyms_on_each_symbol(hack_scan_symbols, NULL);
    
    if (!hack_cpcap_ptr) {
        printk(KERN_ALERT "Daytona HACK: Where is the cpcap ptr?\n");
        return -ENOSYS;
    }
    if (!hack_cpcap_wdt_ptr) {
        printk(KERN_ALERT "Daytona HACK: Where is the cpcap_wdt ptr?\n");
        return -ENOSYS;
    }
    if (!hack_cpcap_wdt_stop) {
        printk(KERN_ALERT "Daytona HACK: Where is the cpcap_wdt_stop?\n");
        return -ENOSYS;
    }
    if (!hack_cpcap_regacc_read) {
        printk(KERN_ALERT "Daytona HACK: Where is the cpcap_regacc_read?\n");
        return -ENOSYS;
    }
    if (!hack_cpcap_regacc_read_secondary) {
        printk(KERN_ALERT "Daytona HACK: Where is the cpcap_regacc_read_secondary?\n");
        return -ENOSYS;
    }
    if (!hack_cpcap_regacc_write) {
        printk(KERN_ALERT "Daytona HACK: Where is the cpcap_regacc_write?\n");
        return -ENOSYS;
    }
    if (!hack_cpcap_regacc_write_secondary) {
        printk(KERN_ALERT "Daytona HACK: Where is the cpcap_regacc_write_secondary?\n");
        return -ENOSYS;
    }

    printk(KERN_ALERT "Daytona HACK: Found all kernel symbols!\n");
    
    //Make sure user has factory cable in, otherwise this will be useless
    if (((struct hack_cpcap_usb_det_data*) hack_cpcap_ptr->accydata)->usb_accy != CPCAP_ACCY_FACTORY) {
        printk(KERN_ALERT "Daytona HACK: Please load this module with factory cable inserted to enter RCM successfully\n");
        return -ENOSYS;
    }

    //Stop watchdog
    ret = hack_cpcap_wdt_stop(hack_cpcap_wdt_ptr);
    printk(KERN_ALERT "cpcap_wdt_stop: %d\n", ret);

    //Disable the USB transceiver
    ret = hack_cpcap_regacc_write(hack_cpcap_ptr, CPCAP_REG_USBC2, 0, CPCAP_BIT_USBXCVREN);
    printk(KERN_ALERT "CPCAP_REG_USBC2: %d\n", ret);
    
    //Disable panic
    ret = hack_cpcap_regacc_write(hack_cpcap_ptr, CPCAP_REG_VAL1, 0, CPCAP_BIT_AP_KERNEL_PANIC);
    printk(KERN_ALERT "CPCAP_BIT_AP_KERNEL_PANIC: %d\n", ret);
    
    //Stop powercut
    ret = cpcap_disable_powercut();
    printk(KERN_ALERT "cpcap_disable_powercut: %d\n", ret);

    //Clear the charger and charge path settings
    ret = hack_cpcap_regacc_write(hack_cpcap_ptr, CPCAP_REG_CRM, 0, 0x3FFF);
    printk(KERN_ALERT "CPCAP_REG_CRM: %d\n", ret);
    mdelay(100);
    
    //Reset CPCAP  
    ret = hack_cpcap_regacc_write(hack_cpcap_ptr, CPCAP_REG_UCC1, CPCAP_BIT_PRIHALT, CPCAP_BIT_PRIHALT);
    printk(KERN_ALERT "CPCAP_REG_UCC1: %d\n", ret);
    ret = hack_cpcap_regacc_write(hack_cpcap_ptr, CPCAP_REG_PGC, CPCAP_BIT_PRI_UC_SUSPEND, CPCAP_BIT_PRI_UC_SUSPEND);
    printk(KERN_ALERT "CPCAP_REG_PGC: %d\n", ret);  
    ret = hack_cpcap_regacc_write(hack_cpcap_ptr, CPCAP_REG_MIM1, 0xFFFF, 0xFFFF);
    printk(KERN_ALERT "CPCAP_REG_MIM1: %d\n", ret);
    ret = hack_cpcap_regacc_write_secondary(hack_cpcap_ptr, CPCAP_REG_MIM1, 0xFFF7, 0xFFFF);
    printk(KERN_ALERT "CPCAP_REG_MIM1 SEC: %d\n", ret);
    ret = hack_cpcap_regacc_write(hack_cpcap_ptr, CPCAP_REG_MI2, 0, 0xFFFF);
    printk(KERN_ALERT "CPCAP_REG_MI2: %d\n", ret);
    ret = hack_cpcap_regacc_write_secondary(hack_cpcap_ptr, CPCAP_REG_MI2, 0, 0xFFFF);
    printk(KERN_ALERT "CPCAP_REG_MI2 SEC: %d\n", ret);

    printk(KERN_ALERT "Daytona HACK: Copying payload to IRAM!\n");
    
    //Place payload and address for stack
    memcpy(IO_ADDRESS(0x40008000), iram_payload, sizeof(iram_payload));
    writel(0x40008000, IO_ADDRESS(0x4000222C));
    
    //Add RCM strap
    writel(readl(IO_ADDRESS(0x70000008)) | 0x02000000, IO_ADDRESS(0x70000008));
    
    printk(KERN_ALERT "Daytona HACK: Going down!\n");
    mdelay(100);
    
    //Setup timer
    writel(0x40000000, IO_ADDRESS(0x6000500C));
    writel(0x800000, IO_ADDRESS(0x60005008));
    
    mdelay(100);

    //Enable watchdog
    writel(0xC0000000, IO_ADDRESS(0x60005008));
    writel(0x37, IO_ADDRESS(0x60006000));

    return -EINPROGRESS;
}

