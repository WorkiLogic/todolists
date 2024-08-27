const connection = require("./Backend/database/db");
const express = require("express");
const app = express();
const ejs = require('ejs');
const session = require('express-session');
const crypto = require('crypto');
const path = require("path")
require("dotenv").config()
const secretKey = process.env.SESSION_SECRET_KEY;
const jwt = require("jsonwebtoken")
const cookie = require("cookie-parser")
const port = 8000

app.set('view engine', 'ejs'); 
app.use(express.json())
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({extended:true}))
app.use(session({
    secret: secretKey,
    resave:false,
    saveUninitialized:false,
    cookie: { secure: false }
}))
app.use(cookie())

function isAuthenticated(req, res, next) {
    if (req.session.user && req.session.user.username) {
      // Retrieve the token from the cookie
      let token = req.cookies["Token"];
      
      if (token) {
        try {
          // Verify the token
          let decoded = jwt.verify(token, "abcd");
  
          // Check if the session username matches the decoded email
          if (req.session.user.username === decoded.username) {
            req.session.user = decoded;
            req.session.user.tokenIssuedAt = decoded.iat;
            return next(); // User is authenticated, proceed to the next middleware or route
          } else {
            return res.status(401).send("Unauthorized: Session does not match token.");
          }
        } catch (err) {
          return res.status(401).send("Unauthorized: Invalid token.");
        }
      } else {
        return res.redirect('/login');
      }
    } else {
      return res.redirect('/login');
    }
  }

app.get('/',isAuthenticated, (req, res) => {
    const sql = 'SELECT * FROM Todos WHERE user_id = ?'
    connection.query(sql, [req.session.user.id], (error, results, fields) => {
        if (error)throw err;
        res.render('index', { todos: results }); // Render the EJS template
        console.log(results)
    });
});


app.get("/register", (req, res) => {
    res.render("register");
});


app.post("/register", (req, res) => {
    const { username, password } = req.body;
    const salt = crypto.randomBytes(64).toString("hex");
    const hashedPassword = crypto.pbkdf2Sync(password, salt, 10000, 64, "sha512").toString("hex");
    const sql = `INSERT INTO Users (username, password, salt) VALUES (?, ?, ?)`;
    
    connection.query(sql, [username, hashedPassword, salt], (err) => {
        if (err) throw err;
        res.redirect("/login");
    });
});

app.get('/login', (req, res) => {

    res.render('login');
});

app.post("/login",(req,res)=>{
    const {username, password} = req.body
    const sql = "SELECT * FROM Users WHERE username = ?"

    connection.query(sql, username, (err,results)=>{
        if(err) throw err
        if (results.length > 0) {
            const user = results[0];
            const hashedPassword = crypto.pbkdf2Sync(password, user.salt, 10000, 64, 'sha512').toString('hex');

            if (user.password === hashedPassword) {
                const payload = {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                };

                req.session.user = payload;
                console.log(req.session.user)
                let token = jwt.sign(payload,"abcd")
                res.cookie("Token",token)
                return res.redirect('/');
            }
        }
        res.redirect("/login")
    })
})

app.get("/kk",(req,res)=>{
    let token = req.cookies["Token"];
    let decoded = jwt.verify(token, "abcd"); // The secret must match the one used for signing
    res.send(decoded);
    console.log(req.session.user)
})
app.post("/addtask",isAuthenticated,(req,res)=>{
    let todo = req.body.todo_name; // Example task value
    const sql = 'INSERT INTO Todos (user_id, todo) VALUES (?, ?)';
    
    connection.query(sql, [req.session.user.id, todo], (err, result) => {
        if (err) throw err;
        console.log("Record inserted successfully");
        res.redirect("/")
    });
})

app.get("/deletetask/:id",(req,res)=>{
    let sql = `DELETE FROM Todos WHERE id = ${req.params.id}`;
    connection.query(sql,(err,result)=>{
        if(err) throw err;
        res.redirect("/")
    })
})

app.get('/deleteall', (req, res) => {
    let sql = `DELETE FROM Todos WHERE user_id = ?`; 
    connection.query(sql, req.session.user.id,(err, result) => {
        if (err) throw err;
        res.redirect('/');
        console.log(req.session.user)
    });
});
  
app.listen(port,()=>{
    console.log("localhost:8000")
})
