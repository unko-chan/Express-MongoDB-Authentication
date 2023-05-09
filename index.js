require("./utils.js");

require("dotenv").config();
const { ObjectId } = require("mongodb");
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

app.set("view engine", "ejs");

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

function user_type(req, res, next) {
  console.log(req.session);
  if (req.session.authenticated) {
    if (req.session.user_type === "admin") {
      next();
    } else {
      res.status(403).send("Error: You do not have permission to access this page.");
    }
  } else {
    res.redirect("/login");
  }
}

app.get("/", (req, res) => {
  const session = req.session;
  res.render("index", { session: session });
});

app.get("/error", (req, res) => {
  res.render("error");
});

app.get("/users", (req, res) => {
  res.render("users", {
    users: [
      { name: "me", email: "me@b.ca" },
      { name: "you", email: "you@b.ca" },
    ],
  });
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/");
    return;
  }

  const blocks = ["Dirt.png", "Grass_Block.png", "Stone.png"];
  const randomBlock = blocks[Math.floor(Math.random() * blocks.length)];
  res.render("members", { session: req.session, randomBlock: randomBlock });
});

app.get("/nosql-injection", async (req, res) => {
  var name = req.query.user;

  if (!name) {
    res.render(
      `<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`
    );
    return;
  }

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(name);

  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.render(
      "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
    );
    return;
  }

  const result = await userCollection
    .find({ name: name })
    .project({ name: 1, password: 1, _id: 1 })
    .toArray();

  res.render(`<h1>Hello ${name}</h1>`);
});

app.get("/about", (req, res) => {
  res.render("about");
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
  res.render(html);
});

app.post("/submitEmail", (req, res) => {
  var email = req.body.email;
  if (!email) {
    res.redirect("/contact?missing=1");
  } else {
    res.render("You have subscribed with the email: " + email);
  }
});

app.get("/createUser", (req, res) => {
  res.render("createUser");
});

app.get("/login", (req, res) => {
  if (req.session.authenticated) {
    res.redirect("/members");
    return;
  }
  res.render("login");
});

app.get("/login-wrong-password", (req, res) => {
  res.render("login-wrong-password");
});

app.post("/submitUser", async (req, res) => {
  var name = req.body.name;
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object({
    name: Joi.string().alphanum().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ name, email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    const missingFields = [];
    if (!name) {
      missingFields.push("a name");
    }
    if (!email) {
      missingFields.push("an email address");
    }
    if (!password) {
      missingFields.push("a password");
    }

    if (missingFields.length > 0) {
      res.render("signupError", { missingFields });
      return;
    }
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    name: name,
    email: email,
    password: hashedPassword,
    user_type: "user",
  });
  console.log("User has been inserted");
  req.session.authenticated = true;
  req.session.name = name;

  res.redirect("/");
});

app.post("/loggingin", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().email().required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.render("loginError");
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ email: 1, name: 1, password: 1, user_type: 1, _id: 1 })
    .toArray();

  if (result.length != 1) {
    res.render("loginError");
    return;
  }

  console.log(result);
  if (await bcrypt.compare(password, result[0].password)) {
    req.session.authenticated = true;
    req.session.email = email;
    req.session.name = result[0].name;
    req.session.user_type = result[0].user_type;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/loggedIn");
    return;
  } else {
    res.render("loginError");
    return;
  }
});

app.get("/loggedin", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/login");
  }
  res.redirect("/");
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.use(express.static(__dirname + "/public"));

app.get("/admin", user_type, async (req, res) => {
  const users = await userCollection.find().toArray();
  res.render("admin", { users });
});

app.get("/promote/:userId", user_type, async (req, res) => {
  const userId = req.params.userId;
  await userCollection.updateOne(
    { _id: new ObjectId(userId) },
    { $set: { user_type: "admin" } }
  );
  res.redirect("/admin");
});

app.get("/demote/:userId", user_type, async (req, res) => {
  const userId = req.params.userId;
  await userCollection.updateOne(
    { _id: new ObjectId(userId) },
    { $set: { user_type: "user" } }
  );
  res.redirect("/admin");
});

app.get("*", (req, res) => {
  res.status(404);
  res.render("404");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
