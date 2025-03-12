# @oslojs/otp

**Documentation: https://otp.oslojs.dev**

A JavaScript library for generating and verifying OTPs by [Oslo](https://oslojs.dev).

Supports HMAC-based one-time passwords (HOTP) and time-based one-time passwords (TOTP) as defined in [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) and [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238).

- Runtime-agnostic
- No third-party dependencies
- Fully typed

```ts
import { generateTOTP, verifyTOTP } from "@oslojs/otp";

const totp = generateTOTP(key, 30, 6);
const valid = verifyTOTP(totp, key, 30, 6);
```

## 代码阅读顺序 (Code Reading Order)

如果你想深入理解代码实现，以下是推荐的阅读顺序：

1. [src/index.ts](./src/index.ts) - 主入口文件，导出所有功能
2. [src/hotp.ts](./src/hotp.ts) - 基于HMAC的一次性密码(HOTP)实现
3. [src/totp.ts](./src/totp.ts) - 基于时间的一次性密码(TOTP)实现
4. [src/hotp.test.ts](./src/hotp.test.ts) - HOTP功能测试用例

## Installation

```
npm i @oslojs/otp
```
