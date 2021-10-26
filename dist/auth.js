/* 
 * lcauth - librecast auth functions
 *
 * this file is part of LIBRECAST
 *
 * Copyright (c) 2017-2021 Brett Sheffield <brett@librecast.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING in the distribution).
 * If not, see <http://www.gnu.org/licenses/>.
 */

const authComboKeyHex = "5c146391d0bf788c19ae63ff5cd64a2b23f2c9835edd8197a93bd1bab12e2a7d3a787c20db2c95e462340cea6e6584f7c5bf1a25b40682fcaa1f45fb40cce1f8";
class Auth {
	constructor(keypair) {
		console.log("auth class constructor");
		this.sock = [];
		this.chan = [];
		this.authKey = new Key(authComboKeyHex);
		this.keypair = keypair;
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
				});
			});
		});
	}

	signup(kp, email, password) {
		console.log("signing up with email " + email);
	}

}
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
