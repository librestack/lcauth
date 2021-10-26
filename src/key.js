class Key {
	constructor(comboKeyHex) {
		this.comboKeyHex = comboKeyHex;
	}
	get combo() {
		return this.comboKeyHex;
	}
	get cryptHex() {
		if (this.cryptKeyHex === undefined) {
			this.cryptKeyHex = this.comboKeyHex.slice(0, sodium.crypto_box_PUBLICKEYBYTES * 2);
		}
		return this.cryptKeyHex;
	}
	get signHex() {
		if (this.signKeyHex === undefined) {
			this.signKeyHex = this.comboKeyHex.slice(sodium.crypto_box_PUBLICKEYBYTES * 2);
		}
		return this.signKeyHex;
	}
	get crypt() {
		if (this.cryptKey === undefined) {
			this.cryptKey = sodium.from_hex(this.cryptHex);
		}
		return this.cryptKey;
	}
	get sign() {
		if (this.signKey === undefined) {
			this.signKey = sodium.from_hex(this.signHex);
		}
		return this.signKey;
	}
}
