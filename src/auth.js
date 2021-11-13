class Auth {
	constructor(lctx, authComboKeyHex, keypair, replyCallback) {
		console.log("auth class constructor");
		this.lctx = lctx;
		this.replyCallback = replyCallback;
		this.sock = [];
		this.chan = [];
		this.event = [];
		this.authKey = new Key(authComboKeyHex);
		this.keypair = (keypair !== undefined) ? keypair : sodium.crypto_box_keypair();
		this.ready = new Promise((resolve, reject) => {
			this.lctx.onconnect.then(() => {
				this.sock["auth"] = new LIBRECAST.Socket(this.lctx);
				this.sock["repl"] = new LIBRECAST.Socket(this.lctx);
				this.chan["auth"] = new LIBRECAST.Channel(this.lctx, this.authKey.combo);
				this.chan["repl"] = new LIBRECAST.Channel(this.lctx, sodium.to_hex(this.keypair.publicKey));
				const p = [];
				p.push(this.sock["auth"].oncreate);
				p.push(this.sock["repl"].oncreate);
				p.push(this.chan["auth"].oncreate);
				p.push(this.chan["repl"].oncreate);
				Promise.all(p).then(() => {
					console.log("auth sockets and channels ready");
					this.chan["auth"].bind(this.sock["auth"]);
					const boundAuth = this.chan["auth"].bind(this.sock["auth"]);
					const boundReply = this.chan["repl"].bind(this.sock["repl"]);
					Promise.all([boundAuth, boundReply])
					.then(() => {
						this.chan["repl"].join()
						.then(() => {
							console.log("reply channel joined, auth ready");
							resolve();
						});
					});
					this.sock["repl"].listen(msg => {
						console.log("message received on reply channel");
						const decoded = this.decodePacket(msg.payload);
						this.replyCallback(...decoded);
					});
				});
			});
		});
	}

	close() {
		console.log("auth.close()");
		this.sock["auth"].close();
		this.sock["repl"].close();
	}

	checkSignature(signed) {
		return sodium.crypto_sign_open(signed, this.authKey.sign);
	}

	decodePacket(payload, offset) {
		const ret = util.wireUnpack(payload);
		const opcode = ret[0];
		const flags = ret[1];
		const fields = ret[2];
		let key, nonce, ciphertext;
		[ key, nonce, ciphertext ] = ret[2];
		if (offset === undefined) { offset = 0; }
		if (!this.keysEqual(key, this.authKey.crypt)) throw "bad auth key received";
		const clear = sodium.crypto_box_open_easy(ciphertext, nonce, key, this.keypair.privateKey);
		console.log("packet decoded");
		const innerFields = util.wireUnpack7Bit(clear.buffer, offset);
		return [ opcode, flags, innerFields, clear.buffer ];
	}

	keysEqual(key1, key2) {
		const len1 = key1.byteLength;
		const len2 = key2.byteLength;
		if (len1 !== len2) return false;
		for (let i = 0; i < len1; i++) {
			if (key1[i] !== key2[i]) return false;
		}
		return true;
	}

	send(opcode, packed, flags) {
		const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
		const clear = sodium.to_string(packed);
		const ciphertext = sodium.crypto_box_easy(clear, nonce, this.authKey.crypt, this.keypair.privateKey);
		const outerFields = [ this.keypair.publicKey, nonce, ciphertext ];
		const data = util.wirePack(opcode, flags, outerFields);
		this.chan['auth'].send(data);
	}

	login(email, password) {
		const opcode = 0x8;
		const flags = 0x0;
		const replyTo = sodium.to_hex(this.keypair.publicKey);
		const fields = [ replyTo, "", email, password, "service" ];
		const payload = util.wirePackPre([], fields);
		this.send(opcode, payload, flags);
	}

	setPassword(token, password) {
		const opcode = 0x4;
		const flags = 0x0;
		const replyTo = sodium.to_hex(this.keypair.publicKey);
		const fields = [ replyTo, token, password ];
		const payload = util.wirePackPre([], fields);
		this.send(opcode, payload, flags);
	}

	signup(email, password) {
		console.log("signing up with email " + email);
		const opcode = 0x1;
		const flags = 0x7;
		const replyTo = sodium.to_hex(this.keypair.publicKey);
		const fields = [ replyTo , "", email, password, "" ];
		const payload = util.wirePackPre([], fields);
		this.send(opcode, payload, flags);
	}

}
