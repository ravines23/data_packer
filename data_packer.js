async function encrypt(iv, key, data) {
	const ivB = new TextEncoder().encode(iv);
	const ivH = await crypto.subtle.digest('SHA-256', ivB); 
	const keyB = new TextEncoder().encode(key);
	const keyH = await crypto.subtle.digest('SHA-256', keyB); 
	const keyR = await crypto.subtle.importKey('raw', keyH, {name: 'AES-CBC'}, false, ['encrypt']);
	const dataB = new TextEncoder().encode(data);
	return await crypto.subtle.encrypt({name: 'AES-CBC', iv: ivH.slice(0, 16)}, keyR, dataB);
}

async function decrypt(iv, key, data) {
	const ivB = new TextEncoder().encode(iv);
	const ivH = await crypto.subtle.digest('SHA-256', ivB); 
	const keyB = new TextEncoder().encode(key);
	const keyH = await crypto.subtle.digest('SHA-256', keyB); 
	const keyR = await crypto.subtle.importKey('raw', keyH, {name: 'AES-CBC'}, false, ['decrypt']);
	const dataB = await crypto.subtle.decrypt({name: 'AES-CBC', iv: ivH.slice(0, 16)}, keyR, data);
	return new TextDecoder().decode(dataB);
}

function bufferToBase64(data) {
	return btoa(String.fromCharCode.apply(null, new Uint8Array(data)));
}

function base64ToBuffer(data) {
	var rawDecoded = atob(data);
	return new Uint8Array(new ArrayBuffer(rawDecoded.length)).map(function(x, i, a) { return this.charCodeAt(i) }, rawDecoded);
}
