import express, { Request, Response, RequestHandler, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { algorithm, makeAccessToken, makeRefreshToken, secretKey } from './tokens';

const app = express();
app.use(express.json());

// 로그인 라우트  
app.post('/login', ((req, res) => {
    const { username } = req.body;
    if (!username) {
        return res.status(400).json({ message: 'Username is required' });
    }

    const accessToken = makeAccessToken(username);
    const refreshToken = makeRefreshToken(username);

    res.json({ accessToken, refreshToken });
}) as RequestHandler);


// JWT 토큰 페이로드 타입 정의  
type JwtPayload = {
    // iss (issuer): 토큰 발급자
    iss: string;
    // sub (subject): 토큰 제목 (일반적으로 사용자 식별자)
    sub: string;
    // exp (expiration time): 토큰 만료 시간 (Unix 시간)
    exp?: number;
    // iat (issued at): 토큰 발급 시간 (Unix 시간)
    iat?: number;
}

export type AuthRequest = Request & {
    user?: JwtPayload;
}

// JWT 토큰 검증 미들웨어  
const verifyToken = async (req: AuthRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
        res.status(401).json({ message: 'Unauthorized' });
        return;
    }

    try {
        const token = authHeader.substring(7);
        const payload = jwt.verify(token, secretKey, { algorithms: [algorithm] }) as JwtPayload;
        req.user = payload;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
        return;
    }
};

// 보호된 리소스 라우트 시뮬레이션 
app.get('/resource', verifyToken, ((req: AuthRequest, res: Response) => {
    res.json({ message: `Hello, ${req.user?.sub}!` });
}) as RequestHandler);

// 토큰 갱신 라우트  
app.post('/refresh', ((req: Request, res: Response) => {
    const { refreshToken: prevRequestToken } = req.body;
    if (!prevRequestToken) {
        return res.status(400).json({ message: 'Refresh token is required' });
    }

    try {
        const payload = jwt.verify(prevRequestToken, secretKey, { algorithms: [algorithm] }) as JwtPayload;
        const accessToken = makeAccessToken(payload.sub!);
        const refreshToken = makeRefreshToken(payload.sub!);

        res.json({ accessToken, refreshToken });
    } catch (error) {
        res.status(401).json({ message: 'Invalid refresh token' });
    }
}) as RequestHandler);

// 404 처리  
app.use((req: Request, res: Response) => {
    res.status(404).json({ message: '404' });
});

app.listen(3000, () => {
    console.log(`Server is running on port 3000`);
});