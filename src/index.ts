/**
 * @oslojs/otp 库的主入口文件
 * 
 * 这个文件导出了所有与一次性密码（OTP）相关的功能，包括：
 * - HOTP（基于HMAC的一次性密码）：由RFC 4226定义，基于计数器生成密码
 * - TOTP（基于时间的一次性密码）：由RFC 6238定义，基于当前时间生成密码
 * 
 * 这些密码通常用于双因素认证（2FA）和多因素认证（MFA）系统中，
 * 例如，当你登录网站时收到的短信验证码，或者使用Google Authenticator等应用生成的验证码。
 */

// 从hotp.js导出HOTP相关的功能
export { generateHOTP, verifyHOTP, createHOTPKeyURI } from "./hotp.js";

// 从totp.js导出TOTP相关的功能
export { generateTOTP, verifyTOTP, verifyTOTPWithGracePeriod, createTOTPKeyURI } from "./totp.js";
