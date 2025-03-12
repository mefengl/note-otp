/**
 * HOTP (HMAC-based One-Time Password) 实现
 * 
 * 本文件实现了基于 HMAC 的一次性密码算法，符合 RFC 4226 标准。
 * HOTP 是一种用于身份验证的一次性密码生成算法，通常用于双因素认证（2FA）系统。
 * 
 * HOTP 算法基于一个共享密钥和一个计数器值，生成一次性密码。每当验证成功后，
 * 计数器会递增，从而生成不同的密码。
 * 
 * 例如：银行短信验证码、硬件令牌（如 RSA SecurID）等都可能使用这种技术。
 */

import { bigEndian } from "@oslojs/binary";
import { hmac } from "@oslojs/crypto/hmac";
import { SHA1 } from "@oslojs/crypto/sha1";
import { constantTimeEqual } from "@oslojs/crypto/subtle";
import { encodeBase32NoPadding } from "@oslojs/encoding";

/**
 * 生成基于 HMAC 的一次性密码(HOTP)
 * 
 * 计算步骤：
 * 1. 将计数器转换为 8 字节的大端字节序
 * 2. 使用 HMAC-SHA1 算法计算密钥和计数器的哈希值
 * 3. 通过动态截取（dynamic truncation）获取 4 字节
 * 4. 将这 4 字节转换为整数并取模，得到指定位数的密码
 * 
 * @param key - 用于生成 HMAC 的共享密钥（二进制格式）
 * @param counter - 计数器值，用于标识当前的 OTP 生成轮次
 * @param digits - 生成的密码位数，通常为 6 位或 8 位
 * @returns 指定位数的 HOTP 密码字符串
 * @throws {TypeError} 当 digits 不在 6-8 之间时抛出错误
 */
export function generateHOTP(key: Uint8Array, counter: bigint, digits: number): string {
	// 验证密码位数是否有效（RFC 4226 推荐 6-8 位）
	if (digits < 6 || digits > 8) {
		throw new TypeError("Digits must be between 6 and 8");
	}

	// 步骤 1: 将计数器转换为 8 字节的大端字节序数组
	const counterBytes = new Uint8Array(8);
	bigEndian.putUint64(counterBytes, counter, 0);

	// 步骤 2: 使用 HMAC-SHA1 算法计算密钥和计数器的哈希值
	const HS = hmac(SHA1, key, counterBytes);

	// 步骤 3: 动态截取（从哈希的最后一个字节低 4 位决定偏移量）
	const offset = HS[HS.byteLength - 1] & 0x0f; // 取最后一个字节的低 4 位作为偏移量
	const truncated = HS.slice(offset, offset + 4); // 从偏移量开始取 4 字节
	
	// 将最高位设为 0，确保结果为正数
	truncated[0] &= 0x7f;

	// 步骤 4: 将 4 字节转换为整数并取模，得到指定位数的密码
	const SNum = bigEndian.uint32(truncated, 0);
	const D = SNum % 10 ** digits; // 取模得到指定位数的数字

	// 将数字格式化为固定长度的字符串，不足位数前面补零
	return D.toString().padStart(digits, "0");
}

/**
 * 验证用户提供的 HOTP 密码是否正确
 * 
 * 为了防止时间攻击，使用恒定时间比较算法来比较密码，
 * 即使密码错误，也会花费相同的时间来比较，避免攻击者通过比较时间来猜测密码。
 * 
 * @param key - 用于生成 HMAC 的共享密钥（二进制格式）
 * @param counter - 计数器值，用于标识当前的 OTP 验证轮次
 * @param digits - 密码的位数，必须与生成时相同
 * @param otp - 用户提供的 OTP 密码，用于与服务器生成的进行比较
 * @returns 如果密码匹配返回 true，否则返回 false
 * @throws {TypeError} 当 digits 不在 6-8 之间时抛出错误
 */
export function verifyHOTP(key: Uint8Array, counter: bigint, digits: number, otp: string): boolean {
	// 验证密码位数是否有效
	if (digits < 6 || digits > 8) {
		throw new TypeError("Digits must be between 6 and 8");
	}

	// 验证用户提供的密码长度是否符合预期
	if (otp.length !== digits) {
		return false;
	}

	// 将用户提供的密码转换为字节数组
	const bytes = new TextEncoder().encode(otp);
	
	// 计算正确的 HOTP 密码
	const expected = generateHOTP(key, counter, digits);
	const expectedBytes = new TextEncoder().encode(expected);
	
	// 使用恒定时间比较算法比较两个密码，防止时间攻击
	const valid = constantTimeEqual(bytes, expectedBytes);
	
	return valid;
}

/**
 * 创建 HOTP 密钥的 URI（统一资源标识符）
 * 
 * 这个函数用于生成符合 KeyURI 格式的 URI 字符串，可以被 Google Authenticator、
 * Authy 等 OTP 应用识别，通常用于生成二维码来方便用户添加验证器。
 * 
 * URI 格式: otpauth://hotp/发行方:账户名?参数=值&参数=值...
 * 
 * @param issuer - 发行方名称（如公司或服务名称）
 * @param accountName - 账户名（如用户名或邮箱）
 * @param key - 用于生成 HOTP 的密钥（二进制格式）
 * @param counter - 初始计数器值
 * @param digits - 密码位数
 * @returns 格式化的 KeyURI 字符串，可用于生成二维码
 */
export function createHOTPKeyURI(
	issuer: string,
	accountName: string,
	key: Uint8Array,
	counter: bigint,
	digits: number
): string {
	// 对 issuer 和 accountName 进行 URL 编码，防止特殊字符影响 URI 格式
	const encodedIssuer = encodeURIComponent(issuer);
	const encodedAccountName = encodeURIComponent(accountName);
	
	// 构建基本的 URI 路径部分
	const base = `otpauth://hotp/${encodedIssuer}:${encodedAccountName}`;
	
	// 创建参数部分
	const params = new URLSearchParams();
	params.set("issuer", issuer); // 发行方
	params.set("algorithm", "SHA1"); // 使用的哈希算法
	params.set("secret", encodeBase32NoPadding(key)); // 将二进制密钥转换为 Base32 编码
	params.set("counter", counter.toString()); // 计数器初始值
	params.set("digits", digits.toString()); // 密码位数
	
	// 拼接完整的 URI
	return base + "?" + params.toString();
}
