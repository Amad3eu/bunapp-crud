import { Database } from 'bun:sqlite';
import * as jose from 'jose';

const db = new Database('mydb.sqlite', { create: true });

db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT, password TEXT)");

interface User {
    id: number;
    name: string;
    email: string;
    password: string;
}

const notFoundResponse = new Response('Not found', { status: 404 });
const unauthorizedResponse = new Response('Unauthorized', { status: 401 });

const checkAuth = async (req: Request) => {
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) return false;

    const token = authHeader.split(' ')[1]
    if (!token) return false;

    try {

        const secret = new TextEncoder().encode(Bun.env.JWT_SECRET);
        const { payload } = await jose.jwtVerify(token, secret);
        return payload;
    } catch (err) {
        return false;
    }

}

const server = Bun.serve({
    port: 3000,
    async fetch(req: Request) {
      const url = new URL(req.url);

      if (url.pathname === '/users') {

        switch (req.method) {
            case 'POST':
                
                const body = await req.json();
                
                const hashedPassword = await Bun.password.hash(body.password, 'bcrypt');
                db.run('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', body.name, body.email, hashedPassword);

                return new Response(null, { status: 201 });
            
            case 'GET':

                const payload = await checkAuth(req);
                if (!payload) return unauthorizedResponse;
    
                const users: User[] = db.query('SELECT id, name, email FROM users').all() as User[];
    
                return Response.json({
                    users
                });
            default:
                break;
        }
      } else if (url.pathname.match(/^\/users\/(\d+)$/)) {

        const id = Number(url.pathname.split('/').pop());

        const userDb = db.query('SELECT id, name, email FROM users WHERE id = ?').get(id) as User;

        if (!userDb) return notFoundResponse;

        switch (req.method) {
            case 'GET':
                
                return Response.json({
                    user: userDb
                })
            
            case 'DELETE':

                db.run('DELETE FROM users WHERE id = ?', [id]);
                return new Response();

            case 'PUT':

                const body = await req.json();
                db.run('UPDATE users set name = ?, email = ? WHERE id = ?', body.name, body.email, id);
                return new Response();
            default:
                break;
        }

      } else if (url.pathname === '/auth/signin' && req.method === 'POST') {

        const body = await req.json();
        const userDb = db.query('SELECT * FROM users WHERE email = ?').get(body.email) as User;

        if (!userDb) return unauthorizedResponse;

        const isPasswordValid = await Bun.password.verify(body.password, userDb.password);
        if (!isPasswordValid) return unauthorizedResponse;

        const secret = new TextEncoder().encode(Bun.env.JWT_SECRET);
        const token = await new jose.SignJWT({
            userId: userDb.id
        }).setProtectedHeader({ alg: 'HS256' })
        .setExpirationTime('2h')
        .sign(secret);

        return Response.json({
            token
        });
      }

      return notFoundResponse;
        
    },
  });
  
  console.log(`Listening on http://localhost:${server.port} ...`);