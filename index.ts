import express, {
  Request,
  Response,
  RequestHandler,
  NextFunction,
} from "express";
import { generateTokens } from "./tokens/generate";
import { verifyToken } from "./tokens/verify";
import { JwtPayload } from "jsonwebtoken";

const app = express();
app.use(express.json());

type LoginRequest = Request<{}, {}, { username: string }>;
type LoginResponse = Response<
  { message: string } | { accessToken: string; refreshToken: string }
>;

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

// 토큰 갱신 라우트
app.post("/refresh", ((req: Request, res: Response) => {
  const { refreshToken } = req.body;
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

// 404 처리
app.use((req: Request, res: Response) => {
  res.status(404).json({ message: "404" });
});

app.listen(3000, () => {
  console.log(`Server is running on port 3000`);
});
