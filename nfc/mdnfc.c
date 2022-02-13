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

#define PY_SSIZE_T_CLEAN
#include <Python.h>


nfc_device* device = 0;
nfc_context* context = 0;
MifareTag tag = 0;
MifareTag* tagList = 0;

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
	
	return Py_BuildValue("i", !devFound);
}

static PyObject* mdnfc_deinit(PyObject* self, PyObject* args)
{
	if(device)
		nfc_close(device);
	if(context)
	    nfc_exit(context);
   	return Py_BuildValue("i", 0);
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
			PyErr_Format(PyExc_IOError, "NFC: warning, can't connect to tag with uid %s\n", uid);
			goto error;
		}

		res = mifare_desfire_get_version(tags[i], &info);
		if(res < 0)
		{
			PyErr_Format(PyExc_IOError, "NFC: warning, can't get version for tag with uid %s\n", uid);
			goto error;
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

		mifare_desfire_disconnect(tags[i]);
		free(uid);
	}

	freefare_free_tags(tags);
	return list;

error:
	freefare_free_tags(tags);
	Py_XDECREF(list);
	return 0;
}

static PyObject* mdnfc_connect(PyObject* self, PyObject* args)
{
	const char* targetUid = 0;
	PyArg_ParseTuple(args, "s", &targetUid);

	MifareTag* tags = freefare_get_tags(device);
	if(!tags)
	{
		PyErr_SetString(PyExc_IOError, "NFC: no tags found");
		return 0;
	}

	for(int i = 0; tags[i]; i++)
	{
		if(freefare_get_tag_type(tags[i]) != DESFIRE)
			continue;
		
		char* uid = freefare_get_tag_uid(tags[i]);
		int cmp = strcmp(uid, targetUid);
		free(uid);
		if(cmp != 0)
			continue;

		int res;
		res = mifare_desfire_connect(tags[i]);
		if(res < 0)
		{
			PyErr_Format(PyExc_IOError, "NFC: warning, can't connect to tag with uid %s\n", targetUid);
			goto error;
		}

		tag = tags[i];
		tagList = tags;

		return Py_BuildValue("i", 0);
	}

	PyErr_Format(PyExc_IOError, "NFC: tag not found");

error:
	freefare_free_tags(tags);
	return 0;
}

static PyObject* mdnfc_disconnect(PyObject* self, PyObject* args)
{
	if(tag)
	{
		mifare_desfire_disconnect(tag);
		freefare_free_tags(tagList);
		tag = 0;
		tagList = 0;
	}
	return Py_BuildValue("i", 0);
}

static PyObject* mdnfc_get_appids(PyObject* self, PyObject* args)
{
	if(!tag)
	{
		PyErr_Format(PyExc_IOError, "NFC: no tag connected");
		return 0;
	}
	MifareDESFireAID* aids;
	size_t aids_count;
	int res = 0;
	res = mifare_desfire_get_application_ids(tag, &aids, &aids_count);
	if(res < 0)
	{
		PyErr_Format(PyExc_IOError, "NFC: get app ids failed");
		return 0;
	}

	PyObject* list = PyList_New(aids_count);
	for(size_t i = 0; i < aids_count; i++)
	{
		uint32_t aid = mifare_desfire_aid_get_aid(aids[i]);
		PyList_SetItem(list, i, Py_BuildValue("i", aid));
	}

	mifare_desfire_free_application_ids(aids);
	return list;
}

static PyObject* auth(PyObject* self, PyObject* args, bool aes)
{
	if(!tag)
	{
		PyErr_Format(PyExc_IOError, "NFC: no tag connected");
		return 0;
	}
	
	int res;
	MifareDESFireKey key;
	uint8_t keyno;
	const uint8_t* buf;
	uint8_t bufw[16];
	Py_ssize_t bufLen;
	ssize_t reqLen;
	PyArg_ParseTuple(args, "By#", &keyno, &buf, &bufLen);
	if(aes) reqLen = 16; else reqLen = 8;
	
	if(bufLen != reqLen)
	{
		PyErr_Format(PyExc_IOError, "invalid key length");
		return 0;
	}
	memcpy(bufw, buf, reqLen);
	if(aes)
		key = mifare_desfire_aes_key_new(bufw);
	else
		key = mifare_desfire_des_key_new(bufw);
	res = mifare_desfire_authenticate(tag, keyno, key);
	if(res < 0)
	{
		PyErr_Format(PyExc_IOError, "NFC: authentication failed");
		goto error;
	}

	mifare_desfire_key_free(key);
	return Py_BuildValue("i", 0);

error:
	mifare_desfire_key_free(key);
	return 0;
}

static PyObject* mdnfc_auth_insecure(PyObject* self, PyObject* args)
{
	return auth(self, args, false);
}

static PyObject* mdnfc_auth_secure(PyObject* self, PyObject* args)
{
	return auth(self, args, true);
}

static PyObject* mdnfc_get_keysettings(PyObject* self, PyObject* args)
{
	if(!tag)
	{
		PyErr_Format(PyExc_IOError, "NFC: no tag connected");
		return 0;
	}

	int res;
	uint8_t settings, max_keys;
	res = mifare_desfire_get_key_settings(tag, &settings, &max_keys);
	if(res < 0)
	{
		PyErr_Format(PyExc_IOError, "NFC: get key settings failed");
		return 0;		
	}
	return Py_BuildValue("BB", settings, max_keys);
}

static PyObject* mdnfc_set_keysettings(PyObject* self, PyObject* args)
{
	if(!tag)
	{
		PyErr_Format(PyExc_IOError, "NFC: no tag connected");
		return 0;
	}
	
	int res;
	uint8_t settings = 0;
	PyArg_ParseTuple(args, "B", &settings);
	res = mifare_desfire_change_key_settings(tag, settings);
	if(res < 0)
	{
		PyErr_Format(PyExc_IOError, "NFC: change key settings failed");
		return 0;		
	}
	return Py_BuildValue("i", 0);
}

static PyObject* mdnfc_change_key(PyObject* self, PyObject* args)
{
	if(!tag)
	{
		PyErr_Format(PyExc_IOError, "NFC: no tag connected");
		return 0;
	}
	
	int res;
	MifareDESFireKey oldkey;
	MifareDESFireKey newkey;
	uint8_t keyno;
	const uint8_t* oldbuf;
	const uint8_t* newbuf;
	uint8_t oldbufw[16];
	uint8_t newbufw[16];
	Py_ssize_t oldbufLen;
	Py_ssize_t newbufLen;
	PyArg_ParseTuple(args, "By#y#", &keyno, &oldbuf, &oldbufLen, 
		&newbuf, &newbufLen);
	//printf("%ld %ld\n", oldbufLen, newbufLen);
	
	if((newbufLen != 16) || ((oldbufLen != 8) && (oldbufLen != 16)))
	{
		PyErr_Format(PyExc_IOError, "NFC: change key - invalid key length");
		return 0;
	}
	memcpy(oldbufw, oldbuf, oldbufLen);
	memcpy(newbufw, newbuf, newbufLen);
	if(oldbufLen == 8)
		oldkey = mifare_desfire_des_key_new(oldbufw);
	else
		oldkey = mifare_desfire_aes_key_new(oldbufw);
	newkey = mifare_desfire_aes_key_new(newbufw);

	res = mifare_desfire_change_key(tag, keyno, newkey, oldkey);
	if(res < 0)
	{
		PyErr_Format(PyExc_IOError, "NFC: change key failed");
		goto error;
	}

	mifare_desfire_key_free(oldkey);
	mifare_desfire_key_free(newkey);
	return Py_BuildValue("i", 0);

error:
	mifare_desfire_key_free(oldkey);
	mifare_desfire_key_free(newkey);
	return 0;
}

static PyObject* mdnfc_format(PyObject* self, PyObject* args)
{
	if(!tag)
	{
		PyErr_Format(PyExc_IOError, "NFC: no tag connected");
		return 0;
	}

	int res;
	res = mifare_desfire_format_picc(tag);
	if(res < 0)
	{
		PyErr_Format(PyExc_IOError, "NFC: format PICC failed");
		return 0;		
	}
	return Py_BuildValue("i", 0);
}

static PyObject* mdnfc_app_select(PyObject* self, PyObject* args)
{
	if(!tag)
	{
		PyErr_Format(PyExc_IOError, "NFC: no tag connected");
		return 0;
	}

	int res;
	uint32_t aidnum = 0;
	PyArg_ParseTuple(args, "i", &aidnum);
	MifareDESFireAID aid = mifare_desfire_aid_new(aidnum);
	res = mifare_desfire_select_application(tag, aid);
	free(aid);
	if(res < 0)
	{
		PyErr_Format(PyExc_IOError, "NFC: select app failed");
		return 0;
	}
	return Py_BuildValue("i", 0);
}

static PyObject* mdnfc_app_create(PyObject* self, PyObject* args)
{
	if(!tag)
	{
		PyErr_Format(PyExc_IOError, "NFC: no tag connected");
		return 0;
	}

	int res;
	uint32_t aidnum = 0;
	uint8_t settings = 0;
	uint8_t keynum = 0;
	PyArg_ParseTuple(args, "iBB", &aidnum, &settings, &keynum);
	MifareDESFireAID aid = mifare_desfire_aid_new(aidnum);
	res = mifare_desfire_create_application_aes(tag, aid, settings, keynum);
	free(aid);
	if(res < 0)
	{
		PyErr_Format(PyExc_IOError, "NFC: app create failed");
		return 0;
	}
	return Py_BuildValue("i", 0);
}

static PyMethodDef module_methods[] = {
	{"init", &mdnfc_init, METH_VARARGS, "initialize nfc backend"},
	{"deinit", &mdnfc_deinit, METH_VARARGS, "deinitialize nfc backend"},
	{"list_tags", &mdnfc_list_tags, METH_VARARGS, "list tags"},
	{"connect", &mdnfc_connect, METH_VARARGS, "connect to tag"},
	{"disconnect", &mdnfc_disconnect, METH_VARARGS, "disconnect from tag"},
	{"get_appids", &mdnfc_get_appids, METH_VARARGS, "get application ids"},
	{"auth_insecure", &mdnfc_auth_insecure, METH_VARARGS, "authenticate with DES"},
	{"auth_secure", &mdnfc_auth_secure, METH_VARARGS, "authenticate with AES"},
	{"get_keysettings", &mdnfc_get_keysettings, METH_VARARGS, "retrieve key settings"},
	{"set_keysettings", &mdnfc_set_keysettings, METH_VARARGS, "change key settings"},
	{"change_key", &mdnfc_change_key, METH_VARARGS, "change key"},
	{"format", &mdnfc_format, METH_VARARGS, "format PICC"},
	{"app_select", &mdnfc_app_select, METH_VARARGS, "select application"},
	{"app_create", &mdnfc_app_create, METH_VARARGS, "create application"},
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

