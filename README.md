# 프로젝트 초기화

타입스크립트 프로젝트를 초기화한다.  
타입스크립트 파일을 실행하기 위한 tsx 도 설치한다.

```sh
pnpm init
pnpm i typescript
pnpm i @types/node tsx -D
pnpm tsc --init
```

익스프레스 서버를 사용해서 테스트를 할 것이다.

```sh
pnpm i express
pnpm i @types/express -D
```

vscode 를 사용하는 경우 [REST Client](https://marketplace.visualstudio.com/items?itemName=humao.rest-client) 를 설치하면 테스트를 쉽게 할 수 있다.

# 토큰 생성
엑세스 토큰은 사용자의 정보를 base64 로 인코딩하고 HMAC-SHA512 알고리즘으로 암호화한 문자열이다.  
node.js 에서는 [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken) 이라는 모듈을 사용해서 만든다.  
리프레시 토큰은 만료기간이 좀 더 긴 엑세스 토큰에 불과하다.  
엑세스 토큰과 리프레시 토큰을 동시에 만들어 반환하면 FE 에서 토큰을 관리하기 쉽다.  

```sh
pnpm i jsonwebtoken
pnpm i @types/jsonwebtoken -D
```

엑세스 토큰을 생성하는 코드와 리프레시 토큰을 생성하는 코드는 아래와 같다.  

```ts
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
export const makeTokens = (username: string) => {
  return {
    accessToken: generateJwt({ username, expires: "1h" }),
    // 리프레시 토큰은 만료기간이 긴 엑세스 토큰에 불과하다.
    refreshToken: generateJwt({ username, expires: "7d" }),
  };
};

if (require.main === module) {
  console.table(makeTokens("test"));
}
```

이렇게 테스트 할 수 있다.

```sh
pnpm tsx tokens/generate.ts
```

# 검증

토큰을 역직렬화해서 페이로드를 구하면 유효한 토큰으로 간주하고, 예외가 발생하면 유효하지 않은 토큰으로 간주한다.
유효한 토큰을 구분하는 기준이 역직렬화 성공 여부라는 것을 알아가면 좋다.

```ts
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
  console.log(verifyToken("검증에 실패하는 토큰은 페이로드를 반환하지 못한다"));
}
```

이렇게 테스트 할 수 있다.

```sh
pnpm tsx tokens/verify.ts
```

# 로그인

로그인은 엑세스 토큰과 리프레시 토큰을 발급하는 행위이다.

```ts
// 로그인 라우트
app.post("/login", ((req: LoginRequest, res: LoginResponse) => {
  const { username } = req.body;
  // 로그인에 실패하면 잘못된 요청으로 처리
  if (!username) {
    return res.status(400).json({ message: "Username is required" });
  }

  // 로그인에 성공하면 엑세스 토큰과 리프레시 토큰을 생성해서 반환
  const tokens = generateTokens(username);
  res.json(tokens);
}) as RequestHandler);

export type AuthRequest = Request & {
  user?: JwtPayload;
};
```

이렇게 테스트 할 수 있다.

```sh
POST http://0.0.0.0:8000/login
Content-Type: application/json
{
  "username": "사용자이름"
}
```

# 경로 보호

express 에서는 미들웨어라는 매커니즘으로 경로 보호를 구현한다.  
헤더에 토큰이 없으면 인증에러를 반환하는 것이 핵심이다.

```ts
// JWT 토큰 검증 미들웨어
const verification = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers.authorization;
  // 헤더에 토큰이 없으면 인증에러(401) 응답
  if (!authHeader?.startsWith("Bearer ")) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  try {
    const token = authHeader.substring(7);
    const payload = verifyToken(token);
    req.user = payload;
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid token" });
    return;
  }
};

// 보호된 리소스 라우트 시뮬레이션
app.get("/resource", verification, (req: AuthRequest, res: Response) => {
  res.json({ message: `Hello, ${req.user?.sub}!` });
});
```

이렇게 테스트 할 수 있다.

```sh
GEt http://localhost:3000/resource
Content-Type: application/json
{
  "username": "사용자이름"
}
```

# 토큰 재발급

토큰 재발급은 리프레시 토큰의 유효성을 검증하고, 올바른 리프레시 토큰의 정보로 새로운 엑세스 토큰과 리프레시 토큰을 생성하는 행위이다.

```ts
// 토큰 갱신 라우트
app.post("/refresh", ((req: Request, res: Response) => {
  const { refreshToken } = req.body;
  // 리프레시 토큰이 올바른지 검증
  if (!refreshToken) {
    return res.status(400).json({ message: "Refresh token is required" });
  }

  try {
    // 리프레시 토큰을 검증한다
    const payload = verifyToken(refreshToken);
    // 리프레시 토큰이 유효하면 새로운 액세스 토큰과 리프레시 토큰을 생성한다
    const tokens = generateTokens(payload.sub!);
    // 새로 생성한 토큰을 반환한다
    res.json(tokens);
  } catch (error) {
    res.status(401).json({ message: "Invalid refresh token" });
  }
}) as RequestHandler);
```

이렇게 테스트 할 수 있다.

```sh
GET http://localhost:3000/refresh
Content-Type: application/json
{
  "refreshToken": "리프레시 토큰"
}
```
