//Express stuff
const express = require('express');
const session = require('express-session');
//Database and .env stuff
const { MongoStore } = require('connect-mongo');
const dotenv = require('dotenv');
//Encrypting\password hashing stuff
const bcrypt = require('bcrypt');
const Joi = require('joi');
const saltRounds = 12;

//configures dotenv to use .env file
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;


const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;


app.use(express.urlencoded({extended: true}));  //parse req.body
app.use(express.json());                        //parse json data into req.body

app.use(express.static(__dirname + '/public'));

//for "include to work"
global.include = function(file) 
{
    return require(__dirname + '/' + file);
}

//sets up connection to database and makes a collection for users
const {database} = include('databaseConnection');
const userCollection = database.db(mongodb_database).collection('users');

/**
 * protect against nosql
 */
app.use(mongoSanitize(
    {replaceWith: '%'}
));

/**
 * Sets up MongoDB session store with encryption.
 */
const mongoStore = MongoStore.create
({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
    crypto: 
    {
        secret: mongodb_session_secret
    }
}); 

/**
 * Initialize sessions and set up cookie with max age of 1 hour.
 */
app.use(session
({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,               //dont make sesh until something stored in sesh (like req.session.something = "some value")
    resave: true,                           //always save sesh even if nothing changed (save every request)
    cookie: 
    {
        maxAge: 1000 * 60 * 60 * 1          //delets cookie (wristband) after 1 hour  
    }
}));        

/**
 * Some middleware I made for good practice. 
 * I dont really need it since its used once.
 */
function authenticateUser(req, res, next)
{
    if(!req.session.authenticated)
    {
        res.redirect('/');
        return;
    }
    next();
}

/**
 * Main page AKA "Home page".
 * Shows different content based on if user is logged in or not.
 */
app.get('/', (req, res) => 
{
    if(req.session.authenticated)
    {
        const html = `
            Hi, ${req.session.name}
            <br>
            <a href="/members">Click to view members only stuff</a>
            <br>
            <a href ="/logout">Click to logout</a>
        `;
        res.send(html);
    }

    else
    {
        const html = `
            <a href="/login">click to login</a>
            <br>
            <a href = "/signup">click to signup</a>
        `;
        res.send(html);
    }
});

/**
 * Signup page.
 */
app.get('/signup', async (req, res) =>
{
    const html = `
        <form action='signup' method='post'>
            <input name='name' type='text' placeholder='name'>
            <br>
            <input name='email' type='email' placeholder='email'>
            <br>
            <input name='password' type='password' placeholder='password'>
            <br>
            <button type='submit'>Submit</button>
        </form>
    `;
    res.send(html);
});

/**
 * Resoponse for signup submission. 
 * 
 * Uses Joi to validate data and bcrypt 
 * to hash password before storing in database.
 * 
 * I put the async thing cause it uses await.
 */
app.post('/signup', async (req, res) =>
{
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;

    const schema = Joi.object
    ({
        name : Joi.string().alphanum().min(2).max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().alphanum().min(2).max(20).required()
    });

    const validationResult = schema.validate({name, email, password});

    if(validationResult.error)
    {
        console.log(validationResult.error + " error validating with joi");
        res.redirect('/signup');
        return; 
        //i returned so i dont get error code flow direction split
    }

    //i did it async cause it takes a while with 12 rounds
    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne
    ({
        name: name,
        email: email,
        password: hashedPassword
    });

    //create session and send to members page
    req.session.authenticated = true;

    //storing name in session so i can use it on members page
    req.session.name = name;          
    
    res.redirect('/');
});

/**
 * Login page.
 * 
 * Uses Joi to validate data and bcrypt to compare 
 * password with hashed password in database.
 */
app.get('/login', async (req, res) =>
{
    const html = `
        <form action='login' method='post'>
            <input name='email' type='email' placeholder='email'>
            <br>
            <input name='password' type='password' placeholder='password'>
            <br>
            <button type='submit'>Submit</button>
        </form>
    `;
    res.send(html);
});

/**
 * Resonse for login submisssion.
 */
app.post('/login', async(req,res) =>
{
    const email = req.body.email;
    const password = req.body.password;

    const schema = Joi.object
    ({
        email: Joi.string().email().required(),
        password: Joi.string().alphanum().min(2).max(20).required()
    });

    const validationResult = schema.validate({email, password});

    if(validationResult.error)
    {
        console.log(validationResult.error + "error validating with joi");
        res.redirect('/login');
        return;
    }

    //to check if email exists in database
    const user = await userCollection.findOne({email: email});
    if(user && await bcrypt.compare(password, user.password))
    {
        req.session.authenticated = true;
        req.session.name = user.name;       //set session name to name from DB
        res.redirect('/');
    }
    else
    {
        console.log("wrong password or email");
        res.redirect("/login")
    }
});

/**
 * Members only page.
 */
app.get('/members', authenticateUser, (req, res) =>
{
    //uses random class ot generate number from 0 to 2 and uses that number to get random image from array
    const images = ["image1.png", "image2.png", "image3.png"];
    const randomImage = images[Math.floor(Math.random() * images.length)]; 

    const html = `
        <h1>Hello ${req.session.name}.</h1>
        <br>
        <img src='${randomImage}' alt='random image'>
        <br>
        <a href='/logout'>Sign out</a>
    `;
    res.send(html);
});

/**
 * Will destroy session and redirect back to home.
 */
app.get('/logout', (req, res) =>
{
    req.session.destroy();
    res.redirect('/');
});

app.use( (req, res) =>
{
    res.status(404);
    res.send("404 Page not found :(😔😔😔😔😔😔😔😔😔😔😔😔😔😔😔😔😔😔😔😔");
});

/**
 * Listens on our port.
 */
app.listen(PORT, () =>
{
    console.log(`server run on ${PORT}`);
});