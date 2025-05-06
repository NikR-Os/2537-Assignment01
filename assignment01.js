// https://expressjs.com/en/guide/routing.html


// REQUIRES
require("./utils.js");
require('dotenv').config();
const saltRounds = 12;

const { MongoClient } = require('mongodb');
const MongoStore = require('connect-mongo');
const express = require("express");
const session = require('express-session');
const app = express();
app.use(express.json());
const fs = require("fs");
const Joi = require("joi");
const bcrypt = require("bcrypt");


const port = process.env.PORT || 3000;


const expireTime = 1 * 60 * 60 * 1000; // Equivilent to 1 hour. 

// just like a simple web server like Apache web server
// we are mapping file system paths to the app's virtual paths
// app.use("/js", express.static("./public/js"));
// app.use("/css", express.static("./public/css"));
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
}))

app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        res.send(`
            <h1>The simplest Homepage</h1>
            <form action="/login" method="get">
                <button type="submit">Log In</button>
            </form>
            <form action="/createUser" method="get">
                <button type="submit">Sign Up</button>
            </form>
        `);
    } else {
        res.send(`
            <h1>Welcome, ${req.session.name}!</h1>
            <form action="/logout" method="get">
                <button type="submit">Log Out</button>
            </form>
            <form action="/members" method="get">
                <button type="submit">Go to Members Page</button>
            </form>
        `);
    }
});

app.get('/contact', (req, res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.send(html);
});

app.post('/submitEmail', (req, res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: " + email);
    }
});


app.get('/createUser', (req, res) => {
    var html = `
    Create Account
    <form action='/submitUser' method='post'>
    <input name='name' type='text' placeholder='Full Name'>
    <input name='email' type='email' placeholder='Email'>
    <input name='password' type='password' placeholder='Password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});


app.get('/login', (req, res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='email' placeholder='Email' required>
    <input name='password' type='password' placeholder='Password' required>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
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

    res.send("Successfully created user");
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
    const randomImage = images[Math.floor(Math.random() * images.length)];

    const html = `
        <h1>Hello, ${req.session.name}!</h1>
        <img src="/img/${randomImage}" style="width:300px;">
        <form action="/logout" method="get">
            <button type="submit">Sign Out</button>
        </form>
    `;
    res.send(html);
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

    const result = await userCollection.find({ email }).project({ name: 1, email: 1, password: 1 }).toArray();

    if (result.length != 1 || !(await bcrypt.compare(password, result[0].password))) {
        // If user is not found or password is incorrect, redirect to loginSubmit
        res.redirect('/loginSubmit');
        return;
    }

    console.log("correct password");
    req.session.authenticated = true;
    req.session.name = result[0].name;  // Store user's name in session
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

// 404
app.get("*", (req, res) => {
    res.status(404);
    res.send("Page not found - 404");
})


// RUN SERVER
app.listen(port, function () {
    console.log("Example app listening on port " + port + "!");
});
