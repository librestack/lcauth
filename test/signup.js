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
});
