"use strict";

function PostVault(readyCallback) {
	const _PV_LEN_INFO_DEC = 8192; // 256*32
	const _PV_LEN_INFO_ENC = _PV_LEN_INFO_DEC + sodium.crypto_secretbox_NONCEBYTES + sodium.crypto_secretbox_MACBYTES;
	const _PV_UPLOAD_SIZE_MIN = 1;
	const _PV_UPLOAD_SIZE_MAX = 4294967296; // 4 GiB

	const _PV_DOMAIN = document.head.querySelector("meta[name='postvault.domain']").content;
	const _PV_DOCSPK = document.head.querySelector("meta[name='postvault.spk']").content;

	if (!_PV_DOMAIN || !new RegExp(/^[0-9a-z.-]{1,63}\.[0-9a-z-]{2,63}$/).test(_PV_DOMAIN) || !_PV_DOCSPK || !new RegExp("^[0-9A-f]{" + (sodium.crypto_box_PUBLICKEYBYTES * 2).toString() + "}$").test(_PV_DOCSPK)) {
		readyCallback(false);
		return;
	}

	const _PV_SPK = sodium.from_hex(_PV_DOCSPK);

	let _own_upk;
	let _own_pvk;
	let _own_hsk;
	let _pvInfo;
	let _files = [256];

	const PvFile = function(ts, sz, fn) {
		this.ts = ts;
		this.sz = sz;
		this.fn = fn;
	};

	const _fetchBinary = function(urlBase, postData, callback) {
		fetch((_PV_DOMAIN.endsWith(".onion") ? "http://" : "https://") + _PV_DOMAIN + ":888/" + sodium.to_base64(urlBase, sodium.base64_variants.URLSAFE), {
			method: postData? "POST" : "GET",
			cache: "no-store",
			credentials: "omit",
			headers: new Headers({
				"Accept": "",
				"Accept-Language": ""
			}),
			mode: "cors",
			redirect: "error",
			referrer: "",
			referrerPolicy: "no-referrer",
			body: postData
		}).then(function(response) {
			switch ((response.statusText === "PV") ? response.status : -1) {
				case 200: return response.arrayBuffer();
				case 204: callback(postData? 0 : 0x21); return null;
				default:  callback(0x20); return null;
			}
		}).then(function(ab) {
			if (ab) callback(0, new Uint8Array(ab));
		}).catch(() => {
			callback(0x03);
		});
	};

	const _fetchEncrypted = function(fileNum, fileData, callback) {
		if ((fileNum && (typeof(fileNum) !== "number" || fileNum < 0 || fileNum > 255)) || (fileData && (typeof(fileData) !== "object" || fileData.length > _PV_UPLOAD_SIZE_MAX))) {
			callback(0x04);
			return;
		}

		let sealClear = new Uint8Array(sodium.crypto_box_PUBLICKEYBYTES + ((typeof(fileNum) === "number") ? 1 : 0));
		sealClear.set(_own_upk);
		if (typeof(fileNum) === "number") sealClear[sodium.crypto_box_PUBLICKEYBYTES] = fileNum;
		const sealBox = sodium.crypto_box_seal(sealClear, _PV_SPK);

		_fetchBinary(sealBox, fileData, function(ret, encData) {
			if (ret !== 0) {callback(ret); return;}

			let decData = encData;
	//		try {decData = sodium.crypto_secretbox_open_easy(encData.slice(sodium.crypto_secretbox_NONCEBYTES), encData.slice(0, sodium.crypto_secretbox_NONCEBYTES), _own_pvk);}
	//		catch(e) {callback(0x05); return;}

			callback(0, decData);
		});
	};

	const _genPvInfo = function() {
		_pvInfo = new Uint8Array(_PV_LEN_INFO_DEC);
		_pvInfo.fill(0);

		for (let i = 0; i < 256; i++) {
			if (_files[i]) {
				_pvInfo.set(sodium.from_string(_files[i].fn), i * 32);
			}
		}
	};

	const _genFileNonce = function(fileNum, fileSz, fileName) {
		let hashSource = new Uint8Array(5 + fileName.length);
		hashSource[0] = fileNum;
		hashSource.set(new Uint8Array(new Uint32Array([fileSz]).buffer), 1);
		hashSource.set(sodium.from_string(fileName), 5);
		return sodium.crypto_generichash(sodium.crypto_secretbox_NONCEBYTES, hashSource, _own_hsk);
	};

	const _getFreeSlot = function() {
		let fallback = -1;
		
		for (let i = 0; i < 256; i++) {
			if (!_files[i]) return i;
			if (fallback === -1 && _files[i].sz === 0) fallback = i;
		}

		return fallback;
	};

	// Public functions

	this.getFileCount = function() {
		let count = 0;

		for (let i = 0; i < 256; i++) {
			if (_files[i].fn) count++;
		}

		return count;
	};

	this.getFileSize = function(num) {return _files[num]? _files[num].sz : null;};
	this.getFileName = function(num) {return _files[num]? _files[num].fn : null;};
	this.getFileTime = function(num) {return _files[num]? _files[num].ts : null;};

	this.deleteFile = function(fileNum, callback) {
		_files[fileNum].sz = 0;

		_fetchEncrypted(fileNum, new Uint8Array(0), function(status) {
			// TODO: If fail, restore previous file info
			callback(status);
		});
	};

	this.uploadFile = function(fileName, fileData, callback) {
		const fileNum = _getFreeSlot();
		if (fileNum < 0) {callback(-1); return;}

		const fileTs = Math.round(Date.now() / 1000);
		_files[fileNum] = new PvFile(fileTs, fileData.length, fileName);
		_genPvInfo();

		const uploadData = new Uint8Array(_PV_LEN_INFO_ENC + fileData.length + sodium.crypto_secretbox_MACBYTES);

		// Info
		const infoNonce = new Uint8Array(sodium.crypto_secretbox_NONCEBYTES);
		window.crypto.getRandomValues(infoNonce);
		const enc_pvInfo = sodium.crypto_secretbox_easy(_pvInfo, infoNonce, _own_pvk);
		uploadData.set(infoNonce);
		uploadData.set(enc_pvInfo, sodium.crypto_secretbox_NONCEBYTES);

		// File
		uploadData.set(sodium.crypto_secretbox_easy(fileData, _genFileNonce(fileNum, fileData.length, fileName), _own_pvk), _PV_LEN_INFO_ENC);

		_fetchEncrypted(fileNum, uploadData, function(status) {
			// TODO: If fail, restore previous file info
			callback(status);
		});
	};

	this.downloadFile = function(fileNum, callback) {
		_fetchEncrypted(fileNum, null, function(status, resp) {
			if (status !== 0) {callback(status); return;}

			const dec = sodium.crypto_secretbox_open_easy(resp, _genFileNonce(fileNum, _files[fileNum].sz - sodium.crypto_secretbox_MACBYTES, _files[fileNum].fn), _own_pvk);

			const a = document.createElement("a");
			a.href = URL.createObjectURL(new Blob([dec]));
			a.download = _files[fileNum].fn;
			a.click();

			URL.revokeObjectURL(a.href);
			a.href = "";
			a.download = "";
		});
	};

	this.getInfo = function(callback) {
		_fetchEncrypted(null, null, function(status, resp) {
			if (status !== 0) {callback(status); return;}

			try {_pvInfo = sodium.crypto_secretbox_open_easy(resp.slice(sodium.crypto_secretbox_NONCEBYTES, _PV_LEN_INFO_ENC), resp.slice(0, sodium.crypto_secretbox_NONCEBYTES), _own_pvk);}
			catch(e) {_pvInfo = new Uint8Array(_PV_LEN_INFO_DEC);}

			for (let i = 0; i < 256; i++) {
				const fn = _pvInfo.slice(i * 32, (i + 1) * 32);
				_files[i] = new PvFile(0, 0, sodium.to_string(fn.slice(0, fn.indexOf(0))));
			}

			for (let i = 0; i < 256; i++) {
				_files[i].ts = new Uint32Array(resp.slice(_PV_LEN_INFO_ENC + (i * 8),     _PV_LEN_INFO_ENC + (i * 8) + 4).buffer)[0];
				_files[i].sz = new Uint32Array(resp.slice(_PV_LEN_INFO_ENC + (i * 8) + 4, _PV_LEN_INFO_ENC + (i * 8) + 8).buffer)[0];
			}

			callback(0);
		});
	};

	this.setKeys = function(skey_hex, callback) {
		if (skey_hex.length !== sodium.crypto_box_SECRETKEYBYTES * 2) {
			callback(false);
			return;
		}

		const boxSeed = sodium.crypto_kdf_derive_from_key(sodium.crypto_box_SEEDBYTES, 1, "AEM-Usr0", sodium.from_hex(skey_hex));
		const boxKeys = sodium.crypto_box_seed_keypair(boxSeed);

		_own_upk = boxKeys.publicKey;
		_own_pvk = sodium.crypto_kdf_derive_from_key(sodium.crypto_secretbox_KEYBYTES, 6, "AEM-Usr0", sodium.from_hex(skey_hex));
		_own_hsk = sodium.crypto_kdf_derive_from_key(sodium.crypto_secretbox_KEYBYTES, 7, "AEM-Usr0", sodium.from_hex(skey_hex));

		if (!_own_upk || !_own_pvk) {
			_own_upk = null;
			_own_pvk = null;
			callback(false);
			return;
		}

		callback(true);
	};

	readyCallback(true);
}
