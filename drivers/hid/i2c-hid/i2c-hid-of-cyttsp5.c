/*
 * HID over I2C Open Firmware Subclass
 *
 * Copyright (c) 2012 Benjamin Tissoires <benjamin.tissoires@gmail.com>
 * Copyright (c) 2012 Ecole Nationale de l'Aviation Civile, France
 * Copyright (c) 2012 Red Hat, Inc
 *
 * This code was forked out of the core code, which was partly based on
 * "USB HID support for Linux":
 *
 *  Copyright (c) 1999 Andreas Gal
 *  Copyright (c) 2000-2005 Vojtech Pavlik <vojtech@suse.cz>
 *  Copyright (c) 2005 Michael Haboustak <mike-@cinci.rr.com> for Concept2, Inc
 *  Copyright (c) 2007-2008 Oliver Neukum
 *  Copyright (c) 2006-2010 Jiri Kosina
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive for
 * more details.
 */

#include <linux/delay.h>
#include <linux/device.h>
#include <linux/hid.h>
#include <linux/i2c.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/pm.h>
#include <linux/regulator/consumer.h>

#include "i2c-hid.h"

struct i2c_hid_of_cyttsp5 {
	struct i2chid_ops ops;

	struct i2c_client *client;
	struct regulator_bulk_data supplies[2];
	int post_power_delay_ms;
};

static int i2c_hid_of_cyttsp5_power_up(struct i2chid_ops *ops)
{
	struct i2c_hid_of_cyttsp5 *ihid_of_cyttsp5 = container_of(ops, struct i2c_hid_of_cyttsp5, ops);
	struct device *dev = &ihid_of_cyttsp5->client->dev;
	int ret;

	ret = regulator_bulk_enable(ARRAY_SIZE(ihid_of_cyttsp5->supplies),
				    ihid_of_cyttsp5->supplies);
	if (ret) {
		dev_warn(dev, "Failed to enable supplies: %d\n", ret);
		return ret;
	}

	if (ihid_of_cyttsp5->post_power_delay_ms)
		msleep(ihid_of_cyttsp5->post_power_delay_ms);

	return 0;
}

static void i2c_hid_of_cyttsp5_power_down(struct i2chid_ops *ops)
{
	struct i2c_hid_of_cyttsp5 *ihid_of_cyttsp5 = container_of(ops, struct i2c_hid_of_cyttsp5, ops);

	regulator_bulk_disable(ARRAY_SIZE(ihid_of_cyttsp5->supplies),
			       ihid_of_cyttsp5->supplies);
}

#include "../../input/touchscreen/cyttsp5_regs.h"
#define CY_I2C_DATA_SIZE  (2 * 256)

static int cyttsp5_i2c_read_default(struct device *dev, void *buf, int size)
{
	struct i2c_client *client = to_i2c_client(dev);
	int rc;

	if (!buf || !size || size > CY_I2C_DATA_SIZE)
		return -EINVAL;

	rc = i2c_master_recv(client, buf, size);

	return (rc < 0) ? rc : rc != size ? -EIO : 0;
}

static int cyttsp5_i2c_read_default_nosize(struct device *dev, u8 *buf, u32 max)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct i2c_msg msgs[2];
	u8 msg_count = 1;
	int rc;
	u32 size;

	if (!buf)
		return -EINVAL;

	msgs[0].addr = client->addr;
	msgs[0].flags = (client->flags & I2C_M_TEN) | I2C_M_RD;
	msgs[0].len = 2;
	msgs[0].buf = buf;
	rc = i2c_transfer(client->adapter, msgs, msg_count);
	if (rc < 0 || rc != msg_count)
		return (rc < 0) ? rc : -EIO;

	size = get_unaligned_le16(&buf[0]);
	if (!size || size == 2 || size >= CY_PIP_1P7_EMPTY_BUF)
		/* Before PIP 1.7, empty buffer is 0x0002;
		From PIP 1.7, empty buffer is 0xFFXX */
		return 0;

	if (size > max)
		return -EINVAL;

	rc = i2c_master_recv(client, buf, size);

	return (rc < 0) ? rc : rc != (int)size ? -EIO : 0;
}

static int cyttsp5_i2c_write_read_specific(struct device *dev, u8 write_len,
		u8 *write_buf, u8 *read_buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct i2c_msg msgs[2];
	u8 msg_count = 1;
	int rc;

	if (!write_buf || !write_len)
		return -EINVAL;

	printk(KERN_ERR "cyttsp5: Write %*ph operation to address 0x%x", write_buf, client->addr);

	msgs[0].addr = client->addr;
	msgs[0].flags = client->flags & I2C_M_TEN;
	msgs[0].len = write_len;
	msgs[0].buf = write_buf;
	rc = i2c_transfer(client->adapter, msgs, msg_count);

	if (rc < 0 || rc != msg_count)
		return (rc < 0) ? rc : -EIO;

	rc = 0;

	if (read_buf)
		rc = cyttsp5_i2c_read_default_nosize(dev, read_buf,
				CY_I2C_DATA_SIZE);

	return rc;
}

static struct cyttsp5_bus_ops cyttsp5_i2c_bus_ops = {
	.bustype = BUS_I2C,
	.read_default = cyttsp5_i2c_read_default,
	.read_default_nosize = cyttsp5_i2c_read_default_nosize,
	.write_read_specific = cyttsp5_i2c_write_read_specific,
};

static int i2c_hid_of_cyttsp5_probe(struct i2c_client *client,
			    const struct i2c_device_id *dev_id)
{
	struct device *dev = &client->dev;
	struct i2c_hid_of_cyttsp5 *ihid_of_cyttsp5;
	u16 hid_descriptor_address;
	u32 quirks = 0;
	int ret;
	u32 val;

	ihid_of_cyttsp5 = devm_kzalloc(&client->dev, sizeof(*ihid_of_cyttsp5), GFP_KERNEL);
	if (!ihid_of_cyttsp5)
		return -ENOMEM;

	ihid_of_cyttsp5->ops.power_up = i2c_hid_of_cyttsp5_power_up;
	ihid_of_cyttsp5->ops.power_down = i2c_hid_of_cyttsp5_power_down;

	ret = of_property_read_u32(dev->of_node, "hid-descr-addr", &val);
	if (ret) {
		dev_err(&client->dev, "HID register address not provided\n");
		return -ENODEV;
	}
	if (val >> 16) {
		dev_err(&client->dev, "Bad HID register address: 0x%08x\n",
			val);
		return -EINVAL;
	}
	hid_descriptor_address = val;

	if (!device_property_read_u32(&client->dev, "post-power-on-delay-ms",
				      &val))
		ihid_of_cyttsp5->post_power_delay_ms = val;

	ihid_of_cyttsp5->supplies[0].supply = "vdd";
	ihid_of_cyttsp5->supplies[1].supply = "vddl";
	ret = devm_regulator_bulk_get(&client->dev,
				      ARRAY_SIZE(ihid_of_cyttsp5->supplies),
				      ihid_of_cyttsp5->supplies);
	if (ret)
		return ret;

	if (device_property_read_bool(dev, "touchscreen-inverted-x")) {
		quirks |= HID_QUIRK_X_INVERT;
	}
	if (device_property_read_bool(dev, "touchscreen-inverted-y")) {
		quirks |= HID_QUIRK_Y_INVERT;
	}

	ret = cyttsp5_devtree_create_and_get_pdata(dev);
	if (ret < 0)
			return ret;

	// Power up the device for the probe to work
	i2c_hid_of_cyttsp5_power_up(&ihid_of_cyttsp5->ops);

	cyttsp5_probe(&cyttsp5_i2c_bus_ops, &client->dev, client->irq,
				  CY_I2C_DATA_SIZE);

	return i2c_hid_core_probe(client, &ihid_of_cyttsp5->ops,
				  hid_descriptor_address, quirks);
}

static const struct of_device_id i2c_hid_of_cyttsp5_match[] = {
	{ .compatible = "hid-over-i2c-cyttsp5" },
	{},
};
MODULE_DEVICE_TABLE(of, i2c_hid_of_cyttsp5_match);

static struct i2c_driver i2c_hid_of_cyttsp5_driver = {
	.driver = {
		.name	= "i2c_hid_of_cyttsp5",
		.pm	= &i2c_hid_core_pm,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
		.of_match_table = of_match_ptr(i2c_hid_of_cyttsp5_match),
	},

	.probe		= i2c_hid_of_cyttsp5_probe,
	.remove		= i2c_hid_core_remove,
	.shutdown	= i2c_hid_core_shutdown,
};

module_i2c_driver(i2c_hid_of_cyttsp5_driver);

MODULE_DESCRIPTION("HID over I2C CYTTSP5 OF driver");
MODULE_AUTHOR("Alistair Francis <alistair@alistair23.me>");
MODULE_LICENSE("GPL");
