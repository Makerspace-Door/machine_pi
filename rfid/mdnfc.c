/*
	Mifare Desfire NFC Python Module
	Copyright (C) 2022  Christian Carlowitz <chca@cmesh.de>

	This program is free software: you can redistribute it and/or modify it
	under the terms of the GNU Lesser General Public License as published by the
	Free Software Foundation, either version 3 of the License, or (at your
	option) any later version.

	This program is distributed in the hope that it will be useful, but WITHOUT
	ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
	FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
	for more details.

	You should have received a copy of the GNU Lesser General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>
*/


#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nfc/nfc.h>
#include <freefare.h>

#include <Python.h>


nfc_device* device = 0;
nfc_context* context = 0;

static PyObject* mdnfc_init(PyObject* self, PyObject* args)
{
	const int devicesLen = 8;
	nfc_connstring devices[devicesLen];
	size_t ndev;

	nfc_init(&context);
	if(!context)
	{
		PyErr_SetString(PyExc_IOError, "NFC: unable to init libnfc");
		return 0;
	}

	ndev = nfc_list_devices(context, devices, devicesLen);
	if(ndev <= 0)
	{
		PyErr_SetString(PyExc_IOError, "NFC: no device found");
		return 0;
	}

	int devFound = 0;
	for (size_t d = 0; d < ndev; d++)
	{
		device = nfc_open(context, devices[d]);
		if(!device)
		{
			PyErr_SetString(PyExc_IOError, "NFC: nfc_open() failed");
			return 0;
		}
		devFound = 1;
		break;
	}
	
	return Py_BuildValue("i", devFound);
}

static PyObject* mdnfc_deinit(PyObject* self, PyObject* args)
{
	if(device)
		nfc_close(device);
	if(context)
	    nfc_exit(context);
   	return Py_BuildValue("i", 1);
}

static PyObject* mdnfc_list_tags(PyObject* self, PyObject* args)
{
	MifareTag* tags = freefare_get_tags(device);
	if(!tags)
	{
		PyErr_SetString(PyExc_IOError, "NFC: no tags found");
		return 0;
	}

	PyObject* list = PyList_New(0);

	for(int i = 0; tags[i]; i++)
	{
		if(freefare_get_tag_type(tags[i]) != DESFIRE)
			continue;
		
		char* uid = freefare_get_tag_uid(tags[i]);
		struct mifare_desfire_version_info info;
		int res;

		res = mifare_desfire_connect(tags[i]);
		if(res < 0)
		{
			printf("NFC: warning, can't connect to tag with uid %s\n", uid);
			break;
		}

		res = mifare_desfire_get_version(tags[i], &info);
		if(res < 0)
		{
			printf("NFC: warning, can't get version for tag with uid %s\n", uid);
			break;
		}

		PyObject* dict = Py_BuildValue(
			"{s:s,s:(BBBBB),s:B,s:B,s:B,s:B,s:B,s:B,s:B,s:B,"
			"s:B,s:B,s:B,s:B,s:B,s:B,s:B,s:B}",
			"uid", uid,
			"batchNumber", info.batch_number[0], info.batch_number[1],
				info.batch_number[2], info.batch_number[3], 
				info.batch_number[4], 
			"prodWeek", info.production_week,
			"prodYear", info.production_year,
			"hwVendorId", info.hardware.vendor_id,
			"hwType", info.hardware.type,
			"hwSubtype", info.hardware.subtype,
			"hwVersionMajor", info.hardware.version_major,
			"hwVersionMinor", info.hardware.version_minor,
			"hwStorageSize", info.hardware.storage_size,
			"hwProtocol", info.hardware.protocol,
			"swVendorId", info.software.vendor_id,
			"swType", info.software.type,
			"swSubtype", info.software.subtype,
			"swVersionMajor", info.software.version_major,
			"swVersionMinor", info.software.version_minor,
			"swStorageSize", info.software.storage_size,
			"swProtocol", info.software.protocol
		);

		PyList_Append(list, dict);
		Py_XDECREF(dict);
	}

	freefare_free_tags(tags);
	return list;
}


static PyMethodDef module_methods[] = {
	{"init", &mdnfc_init, METH_VARARGS, "initialize nfc backend"},
	{"deinit", &mdnfc_deinit, METH_VARARGS, "deinitialize nfc backend"},
	{"list_tags", &mdnfc_list_tags, METH_VARARGS, "list tags"},
	{NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC PyInit_mdnfc(void)
{
	PyObject* module;
	static struct PyModuleDef moduledef = {
		PyModuleDef_HEAD_INIT,
		"mdnfc",
		"mifare desfire NFC communication",
		-1,
		module_methods,
		NULL,
		NULL,
		NULL,
		NULL
	};
	module = PyModule_Create(&moduledef);
	if(!module)
		return NULL;
	
	return module;
}

