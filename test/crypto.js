QUnit.module('Crypto', function() {
	QUnit.test('hash', function(assert) {
		const done = assert.async();
		sodium.ready.then(function () {
			const data = 'some data';
			const HASHSIZE = sodium.crypto_generichash_BYTES;
			assert.ok(sodium.crypto_generichash_BYTES);
			const digest = sodium.crypto_generichash(HASHSIZE, sodium.from_string(data));
			assert.ok(true, sodium.to_hex(digest));
			done();
		});
	});
	QUnit.skip('hash lots', function(assert) {
		const done = assert.async();
		sodium.ready.then(function () {
			const HASHSIZE = sodium.crypto_generichash_BYTES;
			const hashes = [];
			for (let i = 0; i <= 999999; i++) {
				const digest = sodium.crypto_generichash(HASHSIZE, i.toString());
				hashes.push(sodium.to_hex(digest));
			}
			for (let i = 999999; i >= 0; i--) {
				const digest = sodium.crypto_generichash(HASHSIZE, i.toString());
				assert.equal(hashes.pop(), sodium.to_hex(digest));
			}
			done();
		});
	});
});
