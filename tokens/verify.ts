import jwt, { JwtPayload } from "jsonwebtoken";
import { algorithm, generateTokens, secretKey } from "./generate";

export const verifyToken = (token: string) => {
  const payload = jwt.verify(token, secretKey, {
    algorithms: [algorithm],
  });
  return payload as JwtPayload;
};

if (require.main === module) {
  const { accessToken, refreshToken } = generateTokens("test");

  console.log(verifyToken(accessToken));
  console.log(verifyToken(refreshToken));
  //   console.log(verifyToken("검증에 실패하는 토큰은 예외를 발생시킨다"));
}
