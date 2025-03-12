/**
 * HOTP (基于HMAC的一次性密码) 功能测试文件
 * 
 * 本文件包含用于测试 HOTP 功能的测试用例，使用 vitest 测试框架。
 * 这些测试确保 generateHOTP 和 verifyHOTP 函数按照预期工作。
 * 
 * 测试内容包括:
 * 1. 生成不同计数器值的 HOTP 密码
 * 2. 验证正确和错误的 HOTP 密码
 * 3. 验证不同位数密码的处理
 */

import { expect } from "vitest";
import { test } from "vitest";
import { generateHOTP, verifyHOTP } from "./hotp.js";

/**
 * 测试用密钥
 * 
 * 这是一个64字节的随机密钥，用于所有测试用例。
 * 在实际应用中，密钥通常由安全的随机数生成器生成，
 * 并且对每个用户都是唯一的。
 */
const secret = new Uint8Array([
	0x63, 0x07, 0x87, 0x06, 0xe4, 0x89, 0x1b, 0x07, 0x85, 0xba, 0x42, 0xbd, 0x23, 0xac, 0xdd, 0x09,
	0xe4, 0x69, 0x33, 0x63, 0xbe, 0xfa, 0x25, 0xa4, 0x13, 0x46, 0xee, 0x0b, 0xda, 0xb0, 0x72, 0x4c,
	0xa0, 0x8f, 0x8d, 0x26, 0x63, 0x0e, 0xb5, 0x6c, 0xa3, 0xfd, 0xce, 0x6c, 0xc0, 0x0e, 0xf8, 0x65,
	0x6d, 0x1f, 0xeb, 0xc7, 0x35, 0x92, 0x87, 0x16, 0x3d, 0x11, 0x34, 0x20, 0x00, 0x7a, 0x18, 0x1c
]);

/**
 * generateHOTP 函数测试
 * 
 * 这个测试用例验证 generateHOTP 函数是否能够根据不同的计数器值
 * 生成正确的 6 位 HOTP 密码。测试使用了四个不同的计数器值：
 * 0, 10, 100, 和 1000。
 * 
 * 每次调用都应该生成一个确定性的、可预测的结果，这是因为
 * 对于相同的密钥和计数器值，HOTP 算法总是生成相同的密码。
 */
test("generateHOTP()", () => {
	// 测试计数器值为 0 时生成的密码是否为 "173573"
	expect(generateHOTP(secret, 0n, 6)).toBe("173573");
	
	// 测试计数器值为 10 时生成的密码是否为 "110880"
	expect(generateHOTP(secret, 10n, 6)).toBe("110880");
	
	// 测试计数器值为 100 时生成的密码是否为 "020803"
	expect(generateHOTP(secret, 100n, 6)).toBe("020803");
	
	// 测试计数器值为 1000 时生成的密码是否为 "115716"
	expect(generateHOTP(secret, 1000n, 6)).toBe("115716");
});

/**
 * verifyHOTP 函数测试
 * 
 * 这个测试用例验证 verifyHOTP 函数是否能够正确验证 HOTP 密码。
 * 测试包括:
 * 1. 验证正确的密码是否返回 true
 * 2. 验证错误的密码是否返回 false
 * 3. 验证密码位数不匹配的情况是否返回 false
 * 
 * 密码验证是双因素认证系统的关键组成部分，必须确保其可靠性和安全性。
 */
test("verifyHOTP()", () => {
	// 测试正确的密码验证 - 计数器值为 0
	expect(verifyHOTP(secret, 0n, 6, "173573")).toBe(true);
	// 测试错误的密码验证 - 计数器值为 0
	expect(verifyHOTP(secret, 0n, 6, "000000")).toBe(false);
	
	// 测试正确的密码验证 - 计数器值为 10
	expect(verifyHOTP(secret, 10n, 6, "110880")).toBe(true);
	// 测试错误的密码验证 - 计数器值为 10
	expect(verifyHOTP(secret, 10n, 6, "000000")).toBe(false);
	
	// 测试正确的密码验证 - 计数器值为 100
	expect(verifyHOTP(secret, 100n, 6, "020803")).toBe(true);
	// 测试错误的密码验证 - 计数器值为 100
	expect(verifyHOTP(secret, 100n, 6, "000000")).toBe(false);
	
	// 测试正确的密码验证 - 计数器值为 1000
	expect(verifyHOTP(secret, 1000n, 6, "115716")).toBe(true);
	// 测试错误的密码验证 - 计数器值为 1000
	expect(verifyHOTP(secret, 1000n, 6, "000000")).toBe(false);
	
	// 测试位数不匹配的情况 - 使用 8 位验证 6 位密码
	// 尽管密码值是对的，但因为位数不同，应该返回 false
	expect(verifyHOTP(secret, 0n, 8, "173573")).toBe(false);
});
