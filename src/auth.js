class Auth {
	constructor(keypair) {
		console.log("auth class constructor");
		this.sock = [];
		this.chan = [];
		this.authKey = new Key(authComboKeyHex);
		this.keypair = (keypair !== undefined) ? keypair : sodium.crypto_box_keypair();
		this.ready = new Promise((resolve, reject) => {
			this.lctx = new LIBRECAST.Context();
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
					this.sock["repl"].listen()
					.then(() => {
						console.log("message received on reply channel");
					});
				});
			});
		});
	}

	send(opcode, packed, flags) {
		const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
		const clear = sodium.to_string(packed);
		const ciphertext = sodium.crypto_box_easy(clear, nonce, this.authKey.crypt, this.keypair.privateKey);
		const outerFields = [ this.keypair.publicKey, nonce, ciphertext ];
		const data = util.wirePack(opcode, flags, outerFields);
		this.chan['auth'].send(data);
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
