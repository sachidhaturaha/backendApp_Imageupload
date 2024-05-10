const express = require("express");
const jwt = require("jsonwebtoken");
const mysql = require("mysql")
const multer = require("multer");
const bcrypt = require("bcryptjs");


app = express();
app.use(express.json());

const db = mysql.createConnection({
    host : 'localhost',
    user : 'root',
    password : '',
    database : 'just_backend',
});

db.connect(err => {
    if(err) throw err;
    console.log("Database connection successfull!")
});

const storage = multer.diskStorage({
    destination : (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});

const upload = multer({ storage: storage});

app.get('/', function (req, res){
    res.send("Hey this is the beginning part!")
});


app.post('/signup', upload.single('image'), function(req, res){
    const { name, phoneNumber, age, city, email, password } = req.body;
    console.log("Received data:", req.body);

    if (!password) {
        console.error("Password is missing!");
        return res.status(400).json({ error: 'Password is required' });
    }

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            console.error("Error hashing password:", err);
            return res.status(500).json({ error: 'Password not hashed' });
        }
        console.log("Hashed password:", hash);
        
        const query = 'INSERT INTO people (name, phoneNumber, age, city, email, image, password) VALUES (?,?,?,?,?,?,?)';
        db.query(query, [name, phoneNumber, age, city, email, req.file ? req.file.path : null, hash], (err, result) => {
            if (err) {
                console.error("Database error:", err.message);
                return res.status(500).json({ error: err.message });
            }
            res.status(201).send('User registered');
        });
    });
});


app.post('/login', function(req, res){
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    const query = 'SELECT * FROM people WHERE email = ?';
    db.query(query, [email], (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (results.length === 0) {
            return res.status(404).send('User not found.');
        }

        const user = results[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                return res.status(500).json({ error: 'Error checking password' });
            }
            if (!isMatch) {
                return res.status(401).send('Password incorrect');
            }

            const token = jwt.sign({ id: user.id }, '12345', { expiresIn: '24h' });
            res.json({ token });
            console.log("Token:", token);
        });
    });
});

const port = 8080
app.listen(port, () =>{
    console.log("Server started on port 8080")
})