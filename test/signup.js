QUnit.module('account signup', function() {
	QUnit.test('new user account - bad email address', function(assert) {
		console.log("== TEST: new user account - bad email address");
		assert.timeout(2000);
		const done = assert.async(3);
		sodium.ready.then(function () {
			assert.ok(true, "sodium ready");
			const kp = sodium.crypto_box_keypair();
			const localpart = sodium.to_hex(sodium.randombytes_buf(16));
			const invalidEmail = "@live.librecast.net";
			const password = sodium.to_hex(sodium.randombytes_buf(16));
			const auth = new Auth(kp, (opcode, flags, fields, pre) => {
				const view = new DataView(pre);
				const responseCode = view.getUint8(0).toString();
				assert.ok(opcode === 0x1, "opcode=" + opcode);
				assert.ok(responseCode === "1", "signup rejected");
				auth.close();
				done();
			});
			auth.ready.then( () => {
				assert.ok(true, "auth ready");
				auth.signup(invalidEmail, password);
				done();
			});
			done();
		});
	});
	QUnit.test('use bad token', function(assert) {
		console.log("== TEST: set password - bad token");
		assert.timeout(2000);
		const done = assert.async(1);
		sodium.ready.then(function () {
			const kp = sodium.crypto_box_keypair();
			const token = sodium.to_hex(sodium.randombytes_buf(16));
			const password = sodium.to_hex(sodium.randombytes_buf(16));
			const auth = new Auth(kp, (opcode, flags, fields, pre) => {
				const view = new DataView(pre);
				const responseCode = view.getUint8(0).toString();
				assert.ok(opcode === 0x4, "opcode=" + opcode);
				assert.ok(responseCode === "1", "token rejected");
				auth.close();
				done();
			});
			auth.ready.then(() => {
				assert.ok(true, "auth ready");
				auth.setPassword(token, password);
			});
		});
	});
	QUnit.test('bad login', function(assert) {
		console.log("== TEST: login - bad login");
		assert.timeout(2000);
		const done = assert.async(1);
		sodium.ready.then(function () {
			const kp = sodium.crypto_box_keypair();
			const localpart = sodium.to_hex(sodium.randombytes_buf(16));
			const email = localpart + "@live.librecast.net";
			const password = sodium.to_hex(sodium.randombytes_buf(16));
			const auth = new Auth(kp, (opcode, flags, fields, pre) => {
				const view = new DataView(pre);
				const responseCode = view.getUint8(0).toString();
				assert.ok(opcode === 0x8, "opcode=" + opcode);
				assert.ok(responseCode === "1", "login failed");
				auth.close();
				done();
			})
			auth.ready.then(() => {
				assert.ok(true, "auth ready");
				auth.login(email, password);
			});
		});
	});

	QUnit.test('new user account', function(assert) {
		console.log("== TEST: new user account");
		assert.timeout(3000);
		const done = assert.async(1);
		let signup = false;
		let passet = false;
		let login = false;
		sodium.ready.then(function () {
			const kp = sodium.crypto_box_keypair();
			const localpart = sodium.to_hex(sodium.randombytes_buf(32));
			const email = localpart + "@live.librecast.net";
			const password = sodium.to_hex(sodium.randombytes_buf(16));
			const seed = kp.publicKey.slice(0, sodium.randombytes_SEEDBYTES);
			const token = sodium.to_hex(sodium.randombytes_buf_deterministic(sodium.crypto_box_PUBLICKEYBYTES, seed));
			const hextoken = sodium.to_hex(token);
			const auth = new Auth(kp, (opcode, flags, fields, pre) => {
				const view = new DataView(pre)
				const responseCode = view.getUint8(0).toString();
				console.log("opcode: " + opcode);
				console.log("responseCode: " + responseCode);
				switch (opcode) {
					case 0x1:
						if (!signup) {
							signup = true;
							assert.ok(responseCode === "0", "signup confirmed");
							if (responseCode === "0") {
								auth.setPassword(token, password);
							}
						}
						else { console.warn("duplicate signup response received"); }
						break;
					case 0x4:
						if (!passet) {
							passet = true;
							assert.ok(responseCode === "0", "token used, password set");
							if (responseCode === "0") {
								auth.login(email, password)
							}
						}
						else { console.warn("duplicate password set response received"); }
						break;
					case 0x8:
						if (!login) {
							login = true;
							assert.ok(responseCode === "0", "login successful");
							const capClear = auth.checkSignature(fields[1]);
							const capFields = util.wireUnpack7Bit(capClear.buffer, 8);
							assert.ok(capFields.length === 3, "token has 3 fields");
							/* TODO: check expires (pre 8 bytes of token) */
							assert.ok(util.keysEqual(capFields[0], kp.publicKey), "token key matches");
							assert.strictEqual(sodium.to_string(capFields[1]), "service", "service matches");
							auth.close();
							done();
						}
						else { console.warn("duplicate login response received"); }
						break;
					default:
						throw "unknown opcode " + opcode + " received";
				}
			}, 1);
			auth.ready.then(() => {
				auth.signup(email, password);
			});
		});
	});

});
