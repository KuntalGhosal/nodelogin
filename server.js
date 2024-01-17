const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const session = require("express-session");
const flash = require("express-flash");



const app = express();
const { pool } = require("./dbConfig");
const PORT = process.env.PORT || 4000;

app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.json()); // Parse JSON bodies
app.use(bodyParser.urlencoded({ extended: true })); // Parse URL-encoded bodies
app.use(
  session({
    secret: "secret",
    resave: false,
    saveUninitialized: false,
  })
);


app.use(flash());
app.set('view engine', 'pug')
app.get("/", (req, res) => {
  pool.query(`SELECT * FROM users`, (err, results) => {
    if (err) {
      throw err;
    }
    console.log(results.rows);
    res.status(200).jsonp(results.rows);
  });
});

app.get(`/getbyid/:id`, (req, res) => {
    const { id } = req.params;
    pool.query(
        `SELECT * FROM users
            WHERE id = $1`,
        [id],
        (err, results) => {
        if (err) {
            throw err;
        }
        res.status(200).jsonp(results.rows);
        }
    );
    });

app.post("/users/register", async (req, res) => {
  let { name, email, password, password2 } = req.body;
  let errors = [];

  if (!name || !email || !password || !password2) {
    errors.push({ message: "Please enter all fields" });
  }
  if (password.length < 6) {
    errors.push({ message: "Password should be atleast 6 characters" });
  }
  if (password != password2) {
    errors.push({ message: "Passwords do not match" });
  }
  if (errors.length > 0) {
    // res.render("register.pug", { errors });
    res.status(500).json({ error: errors[0].message });
  } else {
    let hashedPassword = await bcrypt.hash(password, 10);
    pool.query(
      `SELECT * FROM users
            WHERE email = $1`,
      [email],
      (err, results) => {
        if (err) {
          throw err;
        }
        if (results.rows.length > 0) {
          errors.push({ message: "Email already registered" });
        //   res.render("register.pug", { errors });
        res.status(500).json({ error: errors[0].message });
        } else {
          pool.query(
            `INSERT INTO users (name, email, password)
                        VALUES ($1, $2, $3)
                        RETURNING id, password`,
            [name, email, hashedPassword],
            (err, results) => {
              if (err) {
                throw err;
              }
              res.status(201).jsonp("You are now registered. Please log in");
              // res.redirect('/users/login');
            }
          );
        }
      }
    );
  }
});

app.post("/login", (req,res,next)=>{
    const {email, password} = req.body;
    if(!email || !password){
        res.status(500).json({ error: "Please enter all fields" });
    }
    pool.query(
        `SELECT * FROM users
        WHERE email = $1`, [email], (err, results) => {
            if(err){
                throw err;
            }
            if(results.rows.length > 0){
                const user = results.rows[0];
                bcrypt.compare(password, user.password, (err, isMatch) => {
                    if(err){
                        throw err;
                    }
                    if(isMatch){
                        return res.status(200).jsonp("You are now logged in");
                    }else{
                        //password is incorrect
                        return res.status(500).json({ error: "Password is incorrect" });
                    }
                });
            }else{
                // No user
                return res.status(500).json({ error: "Email is not registered" });
            }
        }
    );
})


app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}`);
});
