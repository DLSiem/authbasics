const express = require("express");
const { default: mongoose } = require("mongoose");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const User = require("./models/userModel");
const bcryptjs = require("bcryptjs");
const path = require("path");

require("dotenv").config();

const app = express();

const { PORT, MONGODB_URI, SECRET_KEY } = process.env;

mongoose.connect(MONGODB_URI).then(() => {
  console.log("Connect to Successfully to MongoDB");
  app.listen(PORT, () =>
    console.log(`App running on http://localhost:${PORT}`)
  );
});

const mongoDB = mongoose.connection;

mongoDB.on("error", console.error.bind(console, "MongoDB connection error:"));

app.set("views", __dirname + "/views");
app.set("view engine", "ejs");

app.use(express.static(path.join(__dirname, "public")));

// using connect-mongo amd express-session to store user sessions

const MongoStore = require("connect-mongo");
const session = require("express-session");
app.use(
  session({
    secret: SECRET_KEY,
    resave: false,
    saveUninitialized: true,
    store: MongoStore.create({ mongoUrl: MONGODB_URI }),
  })
);

// initialize passport and session
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.get("/", (req, res) => {
  const isAuthenticated = req.isAuthenticated();

  res.render("index", { user: req.user });
});

app.get("/signup", (req, res) => res.render("signup-form"));
app.post("/signup", async (req, res, next) => {
  try {
    const hashedPassword = await bcryptjs.hash(req.body.password, 12);
    if (!hashedPassword) throw new Error("Password hashing failed!");
    const user = new User({
      username: req.body.username,
      password: hashedPassword,
    });

    await user.save();
    res.redirect("/");
  } catch (error) {
    return next(error);
  }
});

app.get("/login", (req, res) => res.render("login-form"));

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
  })
);

app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/");
  });
});

app.get("/verify", (req, res) => {
  res.render("verify", { user: req.user });
});

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      const match = await bcryptjs.compare(password, user.password);
      if (!match) {
        return done(null, false, { message: "Incorrect password" });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});
