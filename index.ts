
import {Database} from "bun:sqlite"



interface User {
  id: number
  name: string
  email: string
  password: string
}

const db = new Database("database.sqlite", {
  create: true
});

db.run("CREATE TABLE IF NOT EXISTS users (  id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT, email TEXT, password TEXT)");

const server = Bun.serve({
  port: 3000,
  async fetch(req: Request) {

    const url = new URL(req.url);

    if (url.pathname === "/users") {
    if (req.method === "POST") {
      
      const body = await req.json();

      const hashedPassword = await Bun.password.hash(body.password, 'bcrypt');
      console.log(hashedPassword)

      db.run ("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", body.name, body.email, hashedPassword );

      // console.log(body);
      // const user: User = {
      //   id: body.id,
      //   name: body.name,
      //   email: body.email,
      //   password: body.password
      // }
      // return Response.json({
      //   user
      // })
      return new Response("Created", { status: 201 });
    }
    
      else if (req.method === "GET") {
        const users: User[] = db.query("SELECT id, name, email FROM users").all() as User[];
        return Response.json({
          users
        })
      }

    }

    return new Response("Not found", { status: 404 });
  },
});

console.log(`Listening on http://localhost:${server.port} ...`);
