require("./utils.js");

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var { database } = include("databaseConnection");

const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
  })
);

app.get("/", (req, res) => {
  res.send(`<h1>Hello!</h1>
  <form action="/createUser">
    <button>Sign Up</button>
  </form>
    <form action="/login">
    <button>Login</button>
    </form>
    <form action="/members">
    <button>Members page</button>
    </form>
    <form action="/logout">
    <button>Logout</button>
    </form>`);
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/login");
    return;
  }

  const blocks = ["Dirt.png", "Grass_Block.png", "Stone.png"];
  const randomBlock = blocks[Math.floor(Math.random() * blocks.length)];
  res.send(`<h1>Hello, ${req.session.username}</h1>
  <img src='/${randomBlock}' style='width:250px;'>
  <br><a href="/logout">Logout</a>`);
});

app.get("/nosql-injection", async (req, res) => {
  var username = req.query.user;

  if (!username) {
    res.send(
      `<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`
    );
    return;
  }
  console.log("user: " + username);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);

  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(
      "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
    );
    return;
  }

  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);

  res.send(`<h1>Hello ${username}</h1>`);
});

app.get("/about", (req, res) => {
  var color = req.query.color;

  res.send("<h1 style='color:" + color + ";'>Kevin Liang</h1>");
});

app.get("/contact", (req, res) => {
  var missingEmail = req.query.missing;
  var html = `
        Your E-mail Address: 
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

app.post("/submitEmail", (req, res) => {
  var email = req.body.email;
  if (!email) {
    res.redirect("/contact?missing=1");
  } else {
    res.send("You have subscribed with the email: " + email);
  }
});

app.get("/createUser", (req, res) => {
  var html = `
    <h1>Sign up</h1>
    <form action='/submitUser' method='post'>
        <input name='username' type='text' placeholder='Username'>
        <input name='password' type='password' placeholder='Password'>
        <button>Sign up</button>
    </form>
    `;
  res.send(html);
});

app.get("/login", (req, res) => {
  var html = `
    <h1>Log in</h1>
    <form action='/loggingin' method='post'>
        <input name='username' type='text' placeholder='Username'>
        <input name='password' type='password' placeholder='Password'>
        <button>Submit</button>
    </form>
    `;
  res.send(html);
});

app.get("/login-wrong-password", (req, res) => {
  var html = `
    <h1>Log in!</h1>
    <p>Wrong Password</p>
    <form action='/loggingin' method='post'>
    <input name='username' type='text' placeholder='Username'>
    <input name='password' type='password' placeholder='Password'>
    <button>Submit</button>
    </form>
    `;
  res.send(html);
});

app.post("/submitUser", async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;

  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ username, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/createUser");
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    username: username,
    password: hashedPassword,
  });
  console.log("User has been inserted");
  req.session.authenticated = true;
  req.session.username = username;

  var html = `Welcome!<br><a href="/members">Members Page</a>`;
  res.send(html);
});

app.post("/loggingin", async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");
    return;
  }

  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);
  if (result.length != 1) {
    console.log("User is not found...");
    res.redirect("/login");
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("right password");
    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/loggedIn");
    return;
  } else {
    console.log("wrong password");
    res.redirect("/login-wrong-password");
    return;
  }
});

app.get("/loggedin", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/login");
  }
  var html = `
    Successfully logged in.<br><a href="/members">Members Page</a>
    <a href="/logout">Logout</a>`;
  res.send(html);
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  var html = `
    Successfully logged out.<br><a href="/">Home</a>
    `;
  res.send(html);
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  res.send(
    "Page isn't here! It's a 404 Error<br><img src='/Coal_Ore.png' style='width:250px;'>"
  );
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
