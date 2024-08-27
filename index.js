const { Pool } = require('pg');
const express = require("express");
const app = express();
const ejs = require('ejs');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const crypto = require('crypto');
const path = require("path");
require("dotenv").config();
const secretKey = process.env.SESSION_SECRET_KEY;
const jwt = require("jsonwebtoken");
const cookie = require("cookie-parser");
const port = process.env.PORT || 8000;

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(session({
    store: new FileStore(),
    secret: secretKey,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));
app.use(cookie());

function isAuthenticated(req, res, next) {
    console.log('Session:', req.session);
    console.log('Cookies:', req.cookies);
    
    if (req.session.user && req.session.user.username) {
        const token = req.cookies["Token"];
        if (token) {
            try {
                const decoded = jwt.verify(token, 'abcd');
                if (req.session.user.username === decoded.username) {
                    req.session.user = decoded; // Update session with decoded token
                    req.session.user.tokenIssuedAt = decoded.iat;
                    return next();
                } else {
                    return res.status(401).send("Unauthorized: Session does not match token.");
                }
            } catch (err) {
                return res.status(401).send("Unauthorized: Invalid token.");
            }
        } else {
            console.log("No token found");
            return res.redirect('/login');
        }
    } else {
        console.log("No session found");
        return res.redirect('/login');
    }
}

app.get('/', isAuthenticated, (req, res) => {
    const sql = 'SELECT * FROM Todos WHERE user_id = $1';
    pool.query(sql, [req.session.user.id], (error, results) => {
        if (error) throw error; 
        res.render('index', { todos: results.rows });
        console.log(results.rows);
    });
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/register", (req, res) => {
    const { username, password } = req.body;
    const salt = crypto.randomBytes(64).toString("hex");
    const hashedPassword = crypto.pbkdf2Sync(password, salt, 10000, 64, "sha512").toString("hex");
    const sql = `INSERT INTO Users (username, password, salt) VALUES ($1, $2, $3)`;

    pool.query(sql, [username, hashedPassword, salt], (err) => {
        if (err) throw err;
        res.redirect("/login");
    });
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;
    const sql = "SELECT * FROM Users WHERE username = $1";

    pool.query(sql, [username], (err, results) => {
        if (err) throw err;
        
        if (results.rows.length > 0) {
            const user = results.rows[0];
            const hashedPassword = crypto.pbkdf2Sync(password, user.salt, 10000, 64, 'sha512').toString('hex');

            if (user.password === hashedPassword) {
                const payload = {
                    id: user.id,
                    username: user.username,
                };

                req.session.user = payload;
                console.log(req.session.user);
                let token = jwt.sign(payload, "abcd");
                res.cookie("Token", token);
                return res.redirect('/');
            }else if (user.password !== hashedPassword){
                res.render('login', { iscorrect: false});
            }
        }
    });
});

app.get("/logout",(req,res)=>{
   
    req.session.destroy((err) => {
        if (err) {
            console.error("Error destroying session:", err);
            return res.status(500).send("Error logging out. Please try again.");
        }
        
        // Clear the session cookie from the client
        res.clearCookie("Token");
        res.clearCookie('connect.sid'); // 'connect.sid' is the default cookie name for session

        // Redirect to the login page or homepage
        res.redirect('/login'); // Adjust the redirect path as needed
    });
})

app.post("/addtask",isAuthenticated, (req, res) => {
    let todo = req.body.todo_name;
    const sql = 'INSERT INTO Todos (user_id, todo) VALUES ($1, $2)';

    pool.query(sql, [req.session.user.id, todo], (err, result) => {
        if (err) throw err;
        console.log("Record inserted successfully");
        res.redirect("/");
    });
});

app.get("/deletetask/:id", (req, res) => {
    let sql = `DELETE FROM Todos WHERE id = $1`;
    pool.query(sql, [req.params.id], (err, result) => {
        if (err) throw err;
        res.redirect("/");
    });
});

app.get('/deleteall', (req, res) => {
    let sql = `DELETE FROM Todos WHERE user_id = $1`;
    pool.query(sql, [req.session.user.id], (err, result) => {
        if (err) throw err;
        res.redirect('/');
        console.log(req.session.user);
    });
});

app.listen(port, () => {
    console.log("localhost:8000");
});
