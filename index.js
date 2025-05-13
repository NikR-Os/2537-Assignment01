// https://expressjs.com/en/guide/routing.html


// REQUIRES
require("./utils.js");
require('dotenv').config();
const saltRounds = 12;

const { MongoClient, ObjectId } = require('mongodb');
const MongoStore = require('connect-mongo');
const express = require("express");
const session = require('express-session');
const app = express();
app.use(express.json());
const fs = require("fs");
const Joi = require("joi");
const bcrypt = require("bcrypt");
const path = require("path");

const port = process.env.PORT || 3000;


const expireTime = 1 * 60 * 60 * 1000; // Equivilent to 1 hour. 

app.set('view engine', 'ejs');

// just like a simple web server like Apache web server
// we are mapping file system paths to the app's virtual paths
// app.use("/js", express.static("./public/js"));
app.use('/css', express.static(path.join(__dirname, 'node_modules/bootstrap/dist/css')));
app.use("/img", express.static("./public/img"));
// app.use("/font", express.static("./public/font"));
app.use(express.urlencoded({ extended: false }));

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/Sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true,
    cookie: { maxAge: expireTime }
}));

const navLinks = [
    {name: 'Home', link: '/'},
    {name: 'Members', link: '/members'},
    {name: 'Admin', link: '/admin'}
];

app.get('/', (req, res) => {
    res.render('index', {name: "Home", userAuth: req.session.authenticated, username: req.session.name, navLinks: navLinks});
});

app.get('/createUser', (req, res) => {
    res.render('createUser', {name: "Create User", navLinks: navLinks});
});

app.get('/login', (req, res) => {
    
    res.render('login', {name: "Login", navLinks: navLinks});
});

app.post('/submitUser', async (req, res) => {
    const { name, email, password } = req.body;

    let missingFields = [];
    if (!name) missingFields.push('name');
    if (!email) missingFields.push('email');
    if (!password) missingFields.push('password');

    if (missingFields.length > 0) {
        const query = missingFields.map(field => `missing=${field}`).join('&');
        res.redirect(`/signupSubmit?${query}`);
        return;
    }

    const schema = Joi.object({
        name: Joi.string().max(100).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required(),
    });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error) {
        console.log(validationResult.error);
        res.redirect("/signupSubmit?missing=invalid");
        return;
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await userCollection.insertOne({ name, email, password: hashedPassword });
    console.log("User created successfully!");

    req.session.authenticated = true;
    req.session.name = name;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});


app.get('/signupSubmit', (req, res) => {
    let missingFields = req.query.missing;

    // Normalize to always be an array
    if (!missingFields) {
        missingFields = [];
    } else if (!Array.isArray(missingFields)) {
        missingFields = [missingFields];
    }

    let message = "<h3>The following are required:</h3><ul>";

    for (const field of missingFields) {
            message += `<li>${field.charAt(0).toUpperCase() + field.slice(1)}</li>`;      
    }

    message += "</ul><a href='/createUser'>Try again</a>";
    res.send(message);
});


app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    const images = ['staffy1.jpg', 'staffy2.jpg', 'staffy3.jpg'];
    res.render('dogs', {name: `Member's Area`, dogs: images, navLinks: navLinks});
});

app.post('/loggingin', async (req, res) => {
    var { email, password } = req.body;

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({ email }).project({ name: 1, email: 1, password: 1, type: 1 }).toArray();

    if (result.length != 1 || !(await bcrypt.compare(password, result[0].password))) {
        res.redirect('/loginSubmit');
        return;
    }

    console.log("correct password");
    req.session.authenticated = true;
    req.session.name = result[0].name;
    req.session.type = result[0].type; // Make sure type is set here
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

app.get('/loginSubmit', (req, res) => {
    var html = `
    <h3>Invalid email/password combination.</h3>
    <a href="/login">Try again?</a>
    `;
    res.send(html);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Middleware to protect admin routes
function isAdmin(req, res, next) {
    if (!req.session.authenticated) return res.redirect('login');
    if (req.session.type !== 'admin') return res.status(403).send('Forbidden: Not authorized');
    next();
}

// Admin page
app.get('/admin', isAdmin, async (req, res) => {
    const users = await userCollection.find().toArray();
    res.render('admin', {name: "Administration", users, navLinks: navLinks });
});

// Promote user to admin
app.post('/promote/:id', isAdmin, async (req, res) => {
    await userCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: { type: 'admin' } });
    res.redirect('/admin');
});

// Demote user to regular user
app.post('/demote/:id', isAdmin, async (req, res) => {
    await userCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: { type: 'user' } });
    res.redirect('/admin');
});


// 404
app.get("*", (req, res) => {
    res.status(404);
    res.render('404', {name: "404!", navLinks: navLinks});
})


// RUN SERVER
app.listen(port, function () {
    console.log("Example app listening on port " + port + "!");
});
