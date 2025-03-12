/**
 * TOTP (Time-based One-Time Password) 实现
 * 
 * 本文件实现了基于时间的一次性密码算法，符合 RFC 6238 标准。
 * TOTP 是 HOTP 的一种特殊变体，它使用当前时间而不是计数器来生成密码。
 * 
 * TOTP 算法将当前时间除以指定的时间间隔（通常为 30 秒），将结果作为计数器值，
 * 然后使用 HOTP 算法生成密码。这样，每隔一段时间就会生成一个新的密码。
 * 
 * 常见应用：Google Authenticator、Microsoft Authenticator、Authy 等验证器应用
 * 生成的动态验证码、企业登录系统的时间型验证码等。
 */

import { encodeBase32NoPadding } from "@oslojs/encoding";
import { generateHOTP, verifyHOTP } from "./hotp.js";

/**
 * 生成基于时间的一次性密码(TOTP)
 * 
 * 基本原理：
 * 1. 将当前时间戳除以时间间隔，得到一个"时间计数器"值
 * 2. 使用这个计数器值调用 HOTP 算法生成密码
 * 
 * 这样每隔 intervalInSeconds 秒，就会生成一个新的密码，
 * 因为时间计数器值会随着时间的流逝而改变。
 * 
 * @param key - 用于生成 TOTP 的共享密钥（二进制格式）
 * @param intervalInSeconds - 时间间隔，单位为秒（通常为 30 秒）
 * @param digits - 生成的密码位数，通常为 6 位或 8 位
 * @returns 指定位数的 TOTP 密码字符串
 * @throws {TypeError} 当 digits 不在 6-8 之间时抛出错误
 */
export function generateTOTP(key: Uint8Array, intervalInSeconds: number, digits: number): string {
	// 验证密码位数是否有效
	if (digits < 6 || digits > 8) {
		throw new TypeError("Digits must be between 6 and 8");
	}

	// 计算时间计数器值
	// 1. 获取当前时间戳（毫秒）
	// 2. 除以时间间隔（转换为毫秒）
	// 3. 向下取整，得到当前时间片段的计数器值
	const counter = BigInt(Math.floor(Date.now() / (intervalInSeconds * 1000)));
	
	// 使用 HOTP 算法生成密码
	const hotp = generateHOTP(key, counter, digits);
	
	return hotp;
}

/**
 * 验证用户提供的 TOTP 密码是否正确
 * 
 * 本函数使用当前确切的时间窗口来验证 TOTP 密码。
 * 这意味着用户必须在当前的时间窗口内输入正确的密码。
 * 如果需要提供宽限期（比如允许前一个或后一个时间窗口的密码），
 * 请使用 verifyTOTPWithGracePeriod 函数。
 * 
 * @param key - 用于生成 TOTP 的共享密钥（二进制格式）
 * @param intervalInSeconds - 时间间隔，单位为秒（通常为 30 秒）
 * @param digits - 密码的位数，必须与生成时相同
 * @param otp - 用户提供的 OTP 密码，用于验证
 * @returns 如果密码匹配返回 true，否则返回 false
 */
export function verifyTOTP(
	key: Uint8Array,
	intervalInSeconds: number,
	digits: number,
	otp: string
): boolean {
	// 计算当前的时间计数器值
	const counter = BigInt(Math.floor(Date.now() / (intervalInSeconds * 1000)));
	
	// 使用 HOTP 函数验证密码
	const valid = verifyHOTP(key, counter, digits, otp);
	
	return valid;
}

/**
 * 带有宽限期的 TOTP 验证函数
 * 
 * 这个函数会检查一个范围内的时间窗口，而不仅仅是当前的时间窗口。
 * 这对于处理以下情况非常有用：
 * - 客户端和服务器之间存在时间偏差
 * - 用户在生成密码后等待了一段时间才提交
 * - 用户输入速度较慢，跨越了时间窗口边界
 * 
 * @param key - 用于生成 TOTP 的共享密钥（二进制格式）
 * @param intervalInSeconds - 时间间隔，单位为秒（通常为 30 秒）
 * @param digits - 密码的位数，必须与生成时相同
 * @param otp - 用户提供的 OTP 密码，用于验证
 * @param gracePeriodInSeconds - 宽限期，单位为秒，在当前时间前后各多检查这么多秒
 * @returns 如果在宽限期内任意时间窗口的密码匹配，返回 true；否则返回 false
 * @throws {TypeError} 当 gracePeriodInSeconds 为负数时抛出错误
 */
export function verifyTOTPWithGracePeriod(
	key: Uint8Array,
	intervalInSeconds: number,
	digits: number,
	otp: string,
	gracePeriodInSeconds: number
): boolean {
	// 验证宽限期是否为正数
	if (gracePeriodInSeconds < 0) {
		throw new TypeError("Grace period must be a positive number");
	}

	// 获取当前时间戳（毫秒）
	const nowUnixMilliseconds = Date.now();
	
	// 计算宽限期开始的时间计数器值（当前时间减去宽限期）
	let counter = BigInt(
		Math.floor((nowUnixMilliseconds - gracePeriodInSeconds * 1000) / (intervalInSeconds * 1000))
	);
	
	// 计算宽限期结束的时间计数器值（当前时间加上宽限期）
	const maxCounterInclusive = BigInt(
		Math.floor((nowUnixMilliseconds + gracePeriodInSeconds * 1000) / (intervalInSeconds * 1000))
	);

	// 遍历宽限期内的所有计数器值
	while (counter <= maxCounterInclusive) {
		// 对每个计数器值进行验证
		const valid = verifyHOTP(key, counter, digits, otp);
		if (valid) {
			return true; // 如果任何一个时间窗口的密码匹配，立即返回 true
		}
		counter++; // 检查下一个时间窗口
	}
	
	// 如果所有时间窗口都不匹配，返回 false
	return false;
}

/**
 * 创建 TOTP 密钥的 URI（统一资源标识符）
 * 
 * 这个函数用于生成符合 KeyURI 格式的 URI 字符串，可以被 Google Authenticator、
 * Microsoft Authenticator、Authy 等 OTP 应用识别，通常用于生成二维码让用户扫描添加。
 * 
 * URI 格式: otpauth://totp/发行方:账户名?参数=值&参数=值...
 * 
 * 与 HOTP 的区别是协议为 "totp"，且使用 "period" 参数而不是 "counter"。
 * 
 * @param issuer - 发行方名称（如公司或服务名称）
 * @param accountName - 账户名（如用户名或邮箱）
 * @param key - 用于生成 TOTP 的密钥（二进制格式）
 * @param periodInSeconds - 时间间隔，单位为秒（通常为 30 秒）
 * @param digits - 密码位数
 * @returns 格式化的 KeyURI 字符串，可用于生成二维码
 */
export function createTOTPKeyURI(
	issuer: string,
	accountName: string,
	key: Uint8Array,
	periodInSeconds: number,
	digits: number
): string {
	// 对 issuer 和 accountName 进行 URL 编码
	const encodedIssuer = encodeURIComponent(issuer);
	const encodedAccountName = encodeURIComponent(accountName);
	
	// 构建基本的 URI 路径部分（注意这里是 totp 而不是 hotp）
	const base = `otpauth://totp/${encodedIssuer}:${encodedAccountName}`;
	
	// 创建参数部分
	const params = new URLSearchParams();
	params.set("issuer", issuer); // 发行方
	params.set("algorithm", "SHA1"); // 使用的哈希算法
	params.set("secret", encodeBase32NoPadding(key)); // 将二进制密钥转换为 Base32 编码
	params.set("period", periodInSeconds.toString()); // 时间间隔（秒）
	params.set("digits", digits.toString()); // 密码位数
	
	// 拼接完整的 URI
	return base + "?" + params.toString();
}
