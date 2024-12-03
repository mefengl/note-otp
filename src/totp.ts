import { encodeBase32NoPadding } from "@oslojs/encoding";
import { generateHOTP, verifyHOTP } from "./hotp.js";

export function generateTOTP(key: Uint8Array, intervalInSeconds: number, digits: number): string {
	if (digits < 6 || digits > 8) {
		throw new TypeError("Digits must be between 6 and 8");
	}
	const counter = BigInt(Math.floor(Date.now() / (intervalInSeconds * 1000)));
	const hotp = generateHOTP(key, counter, digits);
	return hotp;
}

export function verifyTOTP(
	key: Uint8Array,
	intervalInSeconds: number,
	digits: number,
	otp: string
): boolean {
	const counter = BigInt(Math.floor(Date.now() / (intervalInSeconds * 1000)));
	const valid = verifyHOTP(key, counter, digits, otp);
	return valid;
}

export function verifyTOTPWithGracePeriod(
	key: Uint8Array,
	intervalInSeconds: number,
	digits: number,
	otp: string,
	gracePeriodInSeconds: number
): boolean {
	if (gracePeriodInSeconds < 0) {
		throw new TypeError("Grace period must be a positive number");
	}
	if (gracePeriodInSeconds > intervalInSeconds) {
		throw new TypeError("Grace period must be equal to or smaller than the interval");
	}
	const nowUnixMilliseconds = Date.now();
	const counter = BigInt(Math.floor(nowUnixMilliseconds / (intervalInSeconds * 1000)));
	const counterBefore = BigInt(
		Math.floor((nowUnixMilliseconds - gracePeriodInSeconds * 1000) / (intervalInSeconds * 1000))
	);
	const counterAfter = BigInt(
		Math.floor((nowUnixMilliseconds + gracePeriodInSeconds * 1000) / (intervalInSeconds * 1000))
	);
	let valid = verifyHOTP(key, counter, digits, otp);
	if (valid) {
		return true;
	}
	if (counterBefore !== counter) {
		valid = verifyHOTP(key, counterBefore, digits, otp);
		if (valid) {
			return true;
		}
	}
	if (counterAfter !== counter) {
		valid = verifyHOTP(key, counterAfter, digits, otp);
		if (valid) {
			return true;
		}
	}
	return false;
}

export function createTOTPKeyURI(
	issuer: string,
	accountName: string,
	key: Uint8Array,
	periodInSeconds: number,
	digits: number
): string {
	const encodedIssuer = encodeURIComponent(issuer);
	const encodedAccountName = encodeURIComponent(accountName);
	const base = `otpauth://totp/${encodedIssuer}:${encodedAccountName}`;
	const params = new URLSearchParams();
	params.set("issuer", issuer);
	params.set("algorithm", "SHA1");
	params.set("secret", encodeBase32NoPadding(key));
	params.set("period", periodInSeconds.toString());
	params.set("digits", digits.toString());
	return base + "?" + params.toString();
}
