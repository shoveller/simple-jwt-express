import jwt, { JwtPayload } from "jsonwebtoken";
import { algorithm, generateTokens, secretKey } from "./generate";

export const verifyToken = (token: string) => {
  const payload = jwt.verify(token, secretKey, {
    algorithms: [algorithm],
  });
  return payload as JwtPayload;
};

if (require.main === module) {
  const { accessToken, refreshToken } = generateTokens("사용자이름");


  // iss (issuer): 토큰 발급자
  // sub (subject): 토큰 제목 (일반적으로 사용자 식별자)
  // iat (issued at): 토큰 발급 시간 (Unix 시간)
  // exp (expiration time): 토큰 만료 시간 (Unix 시간)
  console.log(verifyToken(accessToken));
  console.log(verifyToken(refreshToken));
  // console.log(verifyToken("전혀 엉뚱한 값"));
}
