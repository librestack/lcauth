class Key {
	constructor(comboKeyHex) {
		this.comboKeyHex = comboKeyHex;
	}
	get combo() {
		return this.comboKeyHex;
	}
	get crypt() {
		if (this.cryptKey === undefined) {
			this.cryptKey = this.comboKeyHex.slice(0, sodium.crypto_box_PUBLICKEYBYTES * 2);
		}
		return this.cryptKey;
	}
	get sign() {
		if (this.signKey === undefined) {
			this.signKey = this.comboKeyHex.slice(sodium.crypto_box_PUBLICKEYBYTES * 2);
		}
		return this.signKey;
	}
	get cryptHex() {
		if (this.cryptKeyHex === undefined) {
			this.cryptKeyHex = sodium.from_hex(this.crypt);
		}
		return this.cryptKeyHex;
	}
	get signHex() {
		if (this.signKeyHex === undefined) {
			this.signKeyHex = sodium.from_hex(this.sign);
		}
		return this.signKeyHex;
	}
}
