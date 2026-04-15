// SPDX-License-Identifier: GPL-2.0
/*
 * Machine Learning (ML) library
 * Testing Misc Device Driver
 *
 * Copyright (C) 2025-2026 Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/ml-lib/ml_lib.h>

#define CREATE_TRACE_POINTS
#include <trace/events/ml_lib_test.h>

#define DEVICE_NAME "mllibdev"
#define CLASS_NAME "ml_lib_test"
#define BUFFER_SIZE 1024

/* IO operation types for tracepoints */
#define ML_LIB_TEST_IO_READ	0
#define ML_LIB_TEST_IO_WRITE	1

/* IOCTL commands */
#define ML_LIB_TEST_DEV_IOC_MAGIC	'M'
#define ML_LIB_TEST_DEV_IOCRESET	_IO(ML_LIB_TEST_DEV_IOC_MAGIC, 0)
#define ML_LIB_TEST_DEV_IOCGETSIZE	_IOR(ML_LIB_TEST_DEV_IOC_MAGIC, 1, int)
#define ML_LIB_TEST_DEV_IOCSETSIZE	_IOW(ML_LIB_TEST_DEV_IOC_MAGIC, 2, int)
#define ML_LIB_TEST_DEV_IOCGETMODELID	_IOR(ML_LIB_TEST_DEV_IOC_MAGIC, 3, u32)

/* Device data structure */
struct ml_lib_test_dev_data {
	struct device *device;
	char *dataset_buf;
	size_t dataset_buf_size;
	size_t dataset_size;
	char *recommendations_buf;
	size_t recommendations_buf_size;
	size_t recommendations_size;
	struct mutex lock;
	unsigned long access_count;
	unsigned long read_count;
	unsigned long write_count;

	struct ml_lib_model *ml_model1;
};

#define ML_MODEL_1_NAME "ml_model1"

static
int ml_lib_test_dev_extract_dataset(struct ml_lib_model *ml_model,
				    struct ml_lib_dataset *dataset);

static struct ml_lib_dataset_operations ml_lib_test_dev_dataset_ops = {
	.extract = ml_lib_test_dev_extract_dataset,
};

static struct ml_lib_test_dev_data *dev_data;

/* ML model operations */
static
int ml_lib_test_dev_extract_dataset(struct ml_lib_model *ml_model,
				    struct ml_lib_dataset *dataset)
{
	struct ml_lib_test_dev_data *data =
		(struct ml_lib_test_dev_data *)ml_model->parent->private;
	u8 pattern;

	mutex_lock(&data->lock);
	get_random_bytes(&pattern, 1);
	memset(data->dataset_buf, pattern, data->dataset_buf_size);
	data->dataset_size = data->dataset_buf_size;
	atomic_set(&dataset->type, ML_LIB_MEMORY_STREAM_DATASET);
	atomic_set(&dataset->state, ML_LIB_DATASET_CLEAN);
	dataset->allocated_size = data->dataset_buf_size;
	dataset->portion_offset = 0;
	dataset->portion_size = data->dataset_buf_size;
	mutex_unlock(&data->lock);

	return 0;
}

/* File operations */
static int ml_lib_test_dev_open(struct inode *inode, struct file *file)
{
	file->private_data = dev_data;

	mutex_lock(&dev_data->lock);
	dev_data->access_count++;
	mutex_unlock(&dev_data->lock);

	trace_ml_lib_test_dev_access(dev_data->access_count);

	pr_info("ml_lib_test_dev: Device opened (total opens: %lu)\n",
		dev_data->access_count);

	return 0;
}

static int ml_lib_test_dev_release(struct inode *inode, struct file *file)
{
	pr_info("ml_lib_test_dev: Device closed\n");
	return 0;
}

static ssize_t ml_lib_test_dev_read(struct file *file, char __user *buf,
				    size_t count, loff_t *ppos)
{
	struct ml_lib_test_dev_data *data = file->private_data;
	size_t to_read;
	int ret;

	mutex_lock(&data->lock);

	if (*ppos >= data->dataset_size) {
		mutex_unlock(&data->lock);
		return 0;
	}

	to_read = min(count, data->dataset_size - (size_t)*ppos);

	ret = copy_to_user(buf, data->dataset_buf + *ppos, to_read);
	if (ret) {
		mutex_unlock(&data->lock);
		return -EFAULT;
	}

	*ppos += to_read;
	data->read_count++;

	mutex_unlock(&data->lock);

	trace_ml_lib_test_dev_io(ML_LIB_TEST_IO_READ,
				 to_read, data->read_count);

	pr_info("ml_lib_test_dev: Read %zu bytes\n", to_read);

	return to_read;
}

static ssize_t ml_lib_test_dev_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct ml_lib_test_dev_data *data = file->private_data;
	size_t to_write;
	int ret;

	mutex_lock(&data->lock);

	if (*ppos >= data->recommendations_buf_size) {
		mutex_unlock(&data->lock);
		return -ENOSPC;
	}

	to_write = min(count, data->recommendations_buf_size - (size_t)*ppos);

	ret = copy_from_user(data->recommendations_buf + *ppos, buf, to_write);
	if (ret) {
		mutex_unlock(&data->lock);
		return -EFAULT;
	}

	*ppos += to_write;
	if (*ppos > data->recommendations_size)
		data->recommendations_size = *ppos;

	data->write_count++;

	mutex_unlock(&data->lock);

	trace_ml_lib_test_dev_io(ML_LIB_TEST_IO_WRITE,
				 to_write, data->write_count);

	pr_info("ml_lib_test_dev: Wrote %zu bytes\n", to_write);

	return to_write;
}

static long ml_lib_test_dev_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	struct ml_lib_test_dev_data *data = file->private_data;
	int size;
	u32 model_id;

	switch (cmd) {
	case ML_LIB_TEST_DEV_IOCRESET:
		mutex_lock(&data->lock);
		memset(data->dataset_buf,
			0, data->dataset_buf_size);
		data->dataset_size = 0;
		memset(data->recommendations_buf,
			0, data->recommendations_buf_size);
		data->recommendations_size = 0;
		mutex_unlock(&data->lock);
		pr_info("ml_lib_test_dev: Buffer reset via IOCTL\n");
		break;

	case ML_LIB_TEST_DEV_IOCGETSIZE:
		mutex_lock(&data->lock);
		size = data->recommendations_size;
		mutex_unlock(&data->lock);
		if (copy_to_user((int __user *)arg, &size, sizeof(size)))
			return -EFAULT;
		break;

	case ML_LIB_TEST_DEV_IOCSETSIZE:
		if (copy_from_user(&size, (int __user *)arg, sizeof(size)))
			return -EFAULT;
		if (size < 0 || size > data->recommendations_buf_size)
			return -EINVAL;
		mutex_lock(&data->lock);
		data->recommendations_size = size;
		mutex_unlock(&data->lock);
		pr_info("ml_lib_test_dev: Data size set to %d via IOCTL\n", size);
		break;

	case ML_LIB_TEST_DEV_IOCGETMODELID:
		model_id = data->ml_model1->model_id;
		if (copy_to_user((u32 __user *)arg, &model_id, sizeof(model_id)))
			return -EFAULT;
		break;

	default:
		return -ENOTTY;
	}

	return 0;
}

static const struct file_operations ml_lib_test_dev_fops = {
	.owner = THIS_MODULE,
	.open = ml_lib_test_dev_open,
	.release = ml_lib_test_dev_release,
	.read = ml_lib_test_dev_read,
	.write = ml_lib_test_dev_write,
	.unlocked_ioctl = ml_lib_test_dev_ioctl,
	.llseek = default_llseek,
};

static struct miscdevice ml_lib_test_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DEVICE_NAME,
	.fops = &ml_lib_test_dev_fops,
};

/* Module initialization */
static int __init ml_lib_test_dev_init(void)
{
	struct ml_lib_model_options *options;
	int ret;

	pr_info("ml_lib_test_dev: Initializing driver\n");

	/* Allocate device data */
	dev_data = kzalloc(sizeof(struct ml_lib_test_dev_data), GFP_KERNEL);
	if (!dev_data)
		return -ENOMEM;

	/* Allocate dataset buffer */
	dev_data->dataset_buf = kzalloc(BUFFER_SIZE, GFP_KERNEL);
	if (!dev_data->dataset_buf) {
		ret = -ENOMEM;
		goto err_free_data;
	}

	dev_data->dataset_buf_size = BUFFER_SIZE;
	dev_data->dataset_size = 0;

	/* Allocate recomendations buffer */
	dev_data->recommendations_buf = kzalloc(BUFFER_SIZE, GFP_KERNEL);
	if (!dev_data->recommendations_buf) {
		ret = -ENOMEM;
		goto err_free_dataset_buffer;
	}

	dev_data->recommendations_buf_size = BUFFER_SIZE;
	dev_data->recommendations_size = 0;

	mutex_init(&dev_data->lock);

	/* Register misc device */
	ret = misc_register(&ml_lib_test_miscdev);
	if (ret < 0) {
		pr_err("ml_lib_test_dev: Failed to register misc device\n");
		goto err_free_recommendations_buffer;
	}

	dev_data->ml_model1 = allocate_ml_model(sizeof(struct ml_lib_model),
						GFP_KERNEL);
	if (IS_ERR(dev_data->ml_model1)) {
		ret = PTR_ERR(dev_data->ml_model1);
		pr_err("ml_lib_test_dev: Failed to allocate ML model\n");
		goto err_misc_deregister;
	} else if (!dev_data->ml_model1) {
		ret = -ENOMEM;
		pr_err("ml_lib_test_dev: Failed to allocate ML model\n");
		goto err_misc_deregister;
	}

	ret = ml_model_create(dev_data->ml_model1, CLASS_NAME,
			      ML_MODEL_1_NAME);
	if (ret < 0) {
		pr_err("ml_lib_test_dev: Failed to create ML model\n");
		goto err_ml_model_free;
	}

	dev_data->ml_model1->parent->private = dev_data;
	dev_data->ml_model1->model_ops = NULL;
	dev_data->ml_model1->dataset_ops = &ml_lib_test_dev_dataset_ops;

	options = allocate_ml_model_options(sizeof(struct ml_lib_model_options),
					    GFP_KERNEL);
	if (IS_ERR(options)) {
		ret = PTR_ERR(options);
		pr_err("ml_lib_test_dev: Failed to allocate ML model options\n");
		goto err_ml_model_destroy;
	} else if (!options) {
		ret = -ENOMEM;
		pr_err("ml_lib_test_dev: Failed to allocate ML model options\n");
		goto err_ml_model_destroy;
	}

	ret = ml_model_init(dev_data->ml_model1, options);
	if (ret < 0) {
		pr_err("ml_lib_test_dev: Failed to init ML model\n");
		goto err_ml_model_options_free;
	}

	pr_info("ml_lib_test_dev: Driver initialized successfully\n");
	pr_info("ml_lib_test_dev: Device created at /dev/%s\n",
		DEVICE_NAME);

	return 0;

err_ml_model_options_free:
	free_ml_model_options(options);
err_ml_model_destroy:
	ml_model_destroy(dev_data->ml_model1);
err_ml_model_free:
	free_ml_model(dev_data->ml_model1);
err_misc_deregister:
	misc_deregister(&ml_lib_test_miscdev);
err_free_recommendations_buffer:
	kfree(dev_data->recommendations_buf);
err_free_dataset_buffer:
	kfree(dev_data->dataset_buf);
err_free_data:
	kfree(dev_data);
	return ret;
}

/* Module cleanup */
static void __exit ml_lib_test_dev_exit(void)
{
	pr_info("ml_lib_test_dev: Cleaning up driver\n");

	/* Destroy ML model */
	ml_model_destroy(dev_data->ml_model1);
	free_ml_model(dev_data->ml_model1);

	/* Deregister misc device */
	misc_deregister(&ml_lib_test_miscdev);

	/* Free buffers */
	kfree(dev_data->recommendations_buf);
	kfree(dev_data->dataset_buf);
	kfree(dev_data);

	pr_info("ml_lib_test_dev: Driver removed successfully\n");
}

module_init(ml_lib_test_dev_init);
module_exit(ml_lib_test_dev_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Viacheslav Dubeyko <slava@dubeyko.com>");
MODULE_DESCRIPTION("ML library testing misc device driver");
MODULE_VERSION("1.0");
