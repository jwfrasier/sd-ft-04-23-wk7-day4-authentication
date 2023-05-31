const express = require("express");
const app = express();
const port = 3000;
const { User } = require("./models");
const db = require("./models");
const bcrypt = require("bcrypt");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const session = require("express-session");
const SequelizeStore = require("connect-session-sequelize")(session.Store);
const myStore = new SequelizeStore({
  db: db.sequelize,
});

// Configure session middleware
app.use(
  session({
    secret: "keyboard cat", // Secret used to sign the session ID cookie
    store: myStore, // Store sessions in SequelizeStore
    resave: false, // Do not save sessions if no modifications were made
    proxy: true, // Trust the reverse proxy when determining the connection's IP address
  })
);
myStore.sync(); // Sync the session store with the database

// Middleware setup
app.use(express.json()); // Parse JSON request bodies
app.use(express.urlencoded({ extended: false })); // Parse URL-encoded request bodies

// Configure LocalStrategy for Passport
passport.use(
  new LocalStrategy(
    {
      usernameField: "email", // Field name for the email in the request body
      passwordField: "password", // Field name for the password in the request body
    },

    async (email, password, done) => {
      try {
        // Find the user by email
        const userToFind = await User.findOne({
          where: {
            email: email,
          },
        });
        // Check if the user exists and compare the password
        if (!userToFind) {
          return done(null, false, {
            message: "Invalid email or password",
          });
        }
        const passwordMatch = await bcrypt.compare(
          password,
          userToFind.password
        );
        if (passwordMatch) {
          return done(null, userToFind); // User authenticated successfully {id:name,created}
        } else {
          return done(null, false, {
            message: "Invalid email or password",
          });
        }
      } catch (error) {
        return done(error);
      }
    }
  )
);

// Serialize user for session storage
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user from session storage
passport.deserializeUser(async (id, done) => {
  try {
    const userToFind = await User.findOne({
      where: {
        id: id,
      },
    });
    done(null, userToFind);
  } catch (error) {
    done(error);
  }
});

// Initialize Passport and session middleware
app.use(passport.initialize()); // Initialize Passport
app.use(passport.session()); // Enable session support for Passport

// Custom middleware to authenticate requests
function authenticate(req, res, next) {
  passport.authenticate("local", (err, user, info) => {
    console.log(err, user, info);
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.status(401).json({
        message: "Invalid email or password",
      });
    }
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      next();
    });
  })(req, res, next);
}

// Route for user sign-up
app.post("/sign_up", async (req, res) => {
  // Expect the user to send the email and password in the req.body
  const { email, password } = req.body;
  if (!email) {
    res.status(400).send("Please include an email");
    return;
  }
  if (!password) {
    res.status(400).send("Please include a password");
    return;
  }
  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
    // Create a new user with the hashed password
    const userToCreate = { email: email, password: hashedPassword };
    const newUser = await User.create(userToCreate);
    res.json({ message: `User successfully created with ID ${newUser.id}` });
  } catch (error) {
    res.status(500).json({ error: "Failed to create user" });
  }
});

// Route for user login
app.post("/login", authenticate, (req, res) => {
  res.send("Successfully logged in");
});

// Route that requires authentication
app.post("/delete_secret_information", authenticate, (req, res) => {
  console.log(req.user);
  res.json({ message: "You deleted some stuff" });
});

// Start the server
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
