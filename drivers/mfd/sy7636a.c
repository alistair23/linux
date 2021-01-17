// SPDX-License-Identifier: GPL-2.0+
/*
 * MFD parent driver for SY7636A chip
 *
 * Copyright (C) 2021 reMarkable AS - http://www.remarkable.com/
 *
 * Authors: Lars Ivar Miljeteig <lars.ivar.miljeteig@remarkable.com>
 *          Alistair Francis <alistair@alistair23.me>
 *
 * Based on the lp87565 driver by Keerthy <j-keerthy@ti.com>
 */

#include <linux/interrupt.h>
#include <linux/mfd/core.h>
#include <linux/module.h>
#include <linux/of_device.h>

#include <linux/mfd/sy7636a.h>

static const struct regmap_config sy7636a_regmap_config = {
	.reg_bits = 8,
	.val_bits = 8,
};

static const struct mfd_cell sy7636a_cells[] = {
	{ .name = "sy7636a-regulator", },
	{ .name = "sy7636a-temperature", },
	{ .name = "sy7636a-thermal", },
};

static int sy7636a_probe(struct i2c_client *client)
{
	struct sy7636a *ddata;
	int ret;

	ddata = devm_kzalloc(&client->dev, sizeof(*ddata), GFP_KERNEL);
	if (!ddata)
		return -ENOMEM;

	ddata->regmap = devm_regmap_init_i2c(client, &sy7636a_regmap_config);
	if (IS_ERR(ddata->regmap)) {
		ret = PTR_ERR(ddata->regmap);
		dev_err(&client->dev,
			"Failed to initialize register map: %d\n", ret);
		return ret;
	}

	i2c_set_clientdata(client, ddata);

	return devm_mfd_add_devices(&client->dev, PLATFORM_DEVID_AUTO,
				    sy7636a_cells, ARRAY_SIZE(sy7636a_cells),
				    NULL, 0, NULL);
}

static const struct of_device_id of_sy7636a_match_table[] = {
	{ .compatible = "silergy,sy7636a", },
	{}
};
MODULE_DEVICE_TABLE(of, of_sy7636a_match_table);

static struct i2c_driver sy7636a_driver = {
	.driver	= {
		.name	= "sy7636a",
		.of_match_table = of_sy7636a_match_table,
	},
	.probe_new = sy7636a_probe,
};
module_i2c_driver(sy7636a_driver);

MODULE_AUTHOR("Lars Ivar Miljeteig <lars.ivar.miljeteig@remarkable.com>");
MODULE_DESCRIPTION("Silergy SY7636A Multi-Function Device Driver");
MODULE_LICENSE("GPL v2");
