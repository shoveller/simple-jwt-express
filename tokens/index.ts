import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

export const algorithm = 'HS512';

// JWT 비밀키 생성  
export const secretKey: string = crypto.randomBytes(64).toString('hex');

// token 생성
const makeToken = ({ username, expires }: { username: string, expires: string }): string => {
    return jwt.sign(
        {
            iss: 'your-app',
            sub: username
        },
        secretKey,
        {
            algorithm,
            expiresIn: expires
        }
    );
}

// Access Token 생성  
export function makeAccessToken(username: string): string {
    return makeToken({ username, expires: '1h' });
}

// Refresh Token 생성. 리프레시 토큰은 만료기간이 긴 엑세스 토큰에 불과하다.  
export function makeRefreshToken(username: string): string {
    return makeToken({ username, expires: '7d' });
}