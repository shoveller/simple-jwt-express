import crypto from "node:crypto";
import jwt from "jsonwebtoken";

export const algorithm = "HS512";

// JWT 비밀키 생성
export const secretKey: string = crypto.randomBytes(64).toString("hex");

// token 생성
const generateJwt = ({
  username,
  expires,
}: {
  username: string;
  expires: string;
}): string => {
  return jwt.sign(
    {
      iss: "your-app",
      sub: username,
    },
    secretKey,
    {
      algorithm,
      expiresIn: expires,
    }
  );
};

// accessToken, refreshToken 생성
export const generateTokens = (username: string) => {
  return {
    accessToken: generateJwt({ username, expires: "1h" }),
    // 리프레시 토큰은 만료기간이 긴 엑세스 토큰에 불과하다.
    refreshToken: generateJwt({ username, expires: "7d" }),
  };
};

if (require.main === module) {
  console.table(generateTokens("test"));
}
