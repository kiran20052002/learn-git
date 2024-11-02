import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import User from "./model/myUser.js";
import dotenv from "dotenv";
import cors from "cors";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as GitHubStrategy } from "passport-github2";
import { Strategy as FacebookStrategy } from "passport-facebook";
import session from "express-session";
import jwt from "jsonwebtoken";

import multer from "multer";
import path from "path";

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: "myPublic", 
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Unique file name
  },
});
const upload = multer({ storage });

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware setup
app.use(cors({
  origin: 'http://localhost:8000', // Adjust this to your frontend's URL
  credentials: true, // Allow credentials (cookies, etc.)
}));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("myPublic"));

app.use(
  session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS
  })
);

app.use(passport.initialize());
app.use(passport.session());

// MongoDB connection
mongoose
  .connect(`${process.env.MONGODB_URI}`, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected..."))
  .catch((err) => console.error("MongoDB connection error:", err));



// Singer Insertion Endpoint
app.post("/add-singer", upload.single("image"), async (req, res) => {
  try {
    const { name, username } = req.body;
    const imagePath = req.file ? req.file.path : null;

    // Check required fields
    if (!imagePath || !name || !username) {
      return res
        .status(400)
        .json({ message: "Image, name, and username are required fields." });
    }

    // Create a new Singer document
    const newSinger = new Singer({
      name,
      username,
      image: imagePath, // Save the path of the uploaded image
      rank: null,
      winrate: null,
      wins: null,
      losses: null,
      trend: null,
    });

    // Save singer to the database
    await newSinger.save();
    res
      .status(201)
      .json({ message: "Singer added successfully", singer: newSinger });
  } catch (error) {
    console.error("Error adding singer:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

// API endpoint to update singer stats
app.post("/api/updateSingerStats", async (req, res) => {
  // Updated to a relative path
  const { name, isWin, likesRapper1, likesRapper2 } = req.body; // Include likes if necessary

  try {
    const singer = await Singer.findOne({ name });
    if (!singer) return res.status(404).json({ message: "Singer not found." });

    if (isWin) {
      singer.wins += 1;
    } else {
      singer.losses += 1;
    }

    // Update winrate calculation
    singer.winrate = (singer.wins / (singer.wins + singer.losses)) * 100;

    await singer.save();
    res.status(200).json(singer);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// API endpoint to get artist rankings
app.get("/api/artists", async (req, res) => {
  try {
    const artists = await Singer.find().sort({ wins: -1 }); // Sort by rank
    res.json(artists);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Passport Google Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails[0]?.value;
        if (!email) return done(new Error("Email is required"), null);

        const existingUser = await User.findOne({ googleId: profile.id });
        if (existingUser) return done(null, existingUser);

        const newUser = await new User({
          username: profile.displayName,
          googleId: profile.id,
          firstName: profile.name.givenName,
          lastName: profile.name.familyName || "",
          email,
          role: "",
        }).save();
        done(null, newUser);
      } catch (err) {
        console.error("Google Strategy Error:", err);
        done(err, null);
      }
    }
  )
);

// Passport GitHub Strategy
passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: "/auth/github/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const existingUser = await User.findOne({ githubId: profile.id });
        if (existingUser) return done(null, existingUser);

        const newUser = new User({
          username: profile.username,
          githubId: profile.id,
          firstName: profile.displayName || profile.username,
          lastName: "",
          role: "",
        });
        await newUser.save();
        done(null, newUser);
      } catch (error) {
        console.error("GitHub Strategy Error:", error);
        done(error, null);
      }
    }
  )
);

// Passport Facebook Strategy
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: "/auth/facebook/callback",
      profileFields: ["id", "displayName", "emails", "name"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const existingUser = await User.findOne({ facebookId: profile.id });
        if (existingUser) return done(null, existingUser);

        const newUser = await new User({
          username: profile.emails[0].value,
          facebookId: profile.id,
          firstName: profile.name.givenName,
          lastName: profile.name.familyName || "",
          role: "",
        }).save();
        return cb(null, profile);
      } catch (err) {
        console.error("Facebook Strategy Error:", err);
        return cb(null, profile);
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  User.findById(id)
    .then((user) => done(null, user))
    .catch((err) => done(err, null));
});

// Registration Endpoint
app.post("/register", async (req, res) => {
  try {
    console.log('Request Body:', req.body); // Check the incoming request body

    const {
      username,
      password,
      firstName,
      lastName,
      email,
      songStyles,
      musicPreferences,
      role,
      songs,
    } = req.body;

    if (!username || !password || !firstName || !lastName || !email || !role) {
      return res.status(400).send("All fields are required");
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).send("User already exists");

    const hashedPassword = await bcrypt.hash(password, 10);
    let newUser;

    if (role === "Singer") {
      newUser = new User({
        name: firstName + " " + lastName,
        username,
        password: hashedPassword,
        email,
        trend: null,
        rank: null,
        winrate: null,
        wins: null,
        losses: null,
        image: req.body.image || null,
        songs: songs ? songs.split(",") : [],
        role,
      });
    } else {
      newUser = new User({
        username,
        password: hashedPassword,
        firstName,
        lastName,
        email,
        songStyles: Array.isArray(songStyles) ? songStyles : [songStyles],
        musicPreferences: Array.isArray(musicPreferences) ? musicPreferences : [musicPreferences],
        role,
      });
    }

    console.log('New User Before Save:', newUser); // Log before saving
    await newUser.save(); // Save the new user to the database
    req.session.userId = newUser._id; // Set the session user ID to the new user's ID

    res.redirect("/mainPage.html");
  } catch (err) {
    console.error("Error during registration:", err);
    if (!res.headersSent) {
      return res.status(500).send("Server error");
    }
  }
});


// Login Endpoint
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user)
      return res.status(401).json({ message: "Invalid email or password" });

    const isMatch = await bcrypt.compare(password.trim(), user.password);
    if (!isMatch)
      return res.status(401).json({ message: "Invalid email or password" });

    req.session.userId = user._id;
    return res.json({ message: "Login successful", user });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});



// Endpoint to get user profile data
app.get('/api/user/profileDetails', async (req, res) => {
  try {
      const userId = req.session.userId; // Use userId from session
      if (!userId) {
          return res.status(401).json({ error: 'Unauthorized' });
      }

      const userProfile = await User.findById(userId); // Fetch by user ID
      console.log('User profile:', userProfile);
      
      if (!userProfile) {
          return res.status(404).json({ error: 'User not found' });
      }
      res.json(userProfile);
  } catch (error) {
      console.error('Error fetching user profile:', error);
      res.status(500).json({ error: 'Server error' });
  }
});



// Route to update user profile
app.put('/api/user/profile', async (req, res) => {
  try {
      const { username, firstName, lastName, email, songStyles, musicPreferences, role, songs } = req.body;

      // Assume you have a way to get the current user's ID (e.g., from session)
     
      const userId = req.session.userId;
      if (!userId) {
        console.error("No user ID found in session.");
        return res.status(401).send("Unauthorized: No session user ID.");
      }
    
      console.log("Session User ID:", userId);


      const updatedUser = await User.findByIdAndUpdate(userId, {
          username,
          firstName,
          lastName,
          email,
          songStyles: Array.isArray(songStyles) ? songStyles : [songStyles], // Ensure it's an array
          musicPreferences: Array.isArray(musicPreferences) ? musicPreferences : [musicPreferences], // Keep as an array
 // Convert array to string
          role,
          songs,
      }, { new: true }); // Returns the updated document

      if (updatedUser) {
          res.status(200).json(updatedUser);
      } else {
          res.status(404).send('User not found');
      }
  } catch (error) {
      console.error(error);
      res.status(500).send('Server error');
  }
});




// Google Auth Routes
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    req.session.userId = req.user._id; // Set the user ID in the session
    res.redirect("/mainPage.html");
  }
);

// Facebook Auth Routes
app.get(
  "/auth/facebook",
  passport.authenticate("facebook", { scope: ["email"] })
);
app.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  (req, res) => {
    req.session.userId = req.user._id;
    res.redirect("/mainPage.html");
  }
);

// GitHub Auth Routes
app.get(
  "/auth/github",
  passport.authenticate("github", { scope: ["user:email"] })
);
app.get(
  "/auth/github/callback",
  passport.authenticate("github", { failureRedirect: "/login" }),
  (req, res) => {
    req.session.userId = req.user._id;
    res.redirect("/mainPage.html");
  }
);

// Forgot Password
app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  try {
    const oldUser = await User.findOne({ email });
    if (!oldUser) return res.status(404).json({ status: "User Not Exists!!" });

    const secret = process.env.JWT_SECRET + oldUser.password;
    const token = jwt.sign({ email: oldUser.email, id: oldUser._id }, secret, {
      expiresIn: "15m",
    });
    const link = `http://localhost:${PORT}/reset-password/${oldUser._id}/${token}`;

    // Send email logic (not shown)
    res.send({ status: "success", link });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// Reset Password
app.post("/reset-password/:id/:token", async (req, res) => {
  const { password } = req.body;
  const { id, token } = req.params;

  const oldUser = await User.findById(id);
  if (!oldUser) return res.status(404).json({ status: "User Not Exists!!" });

  const secret = process.env.JWT_SECRET + oldUser.password;

  try {
    jwt.verify(token, secret);

    const hashedPassword = await bcrypt.hash(password, 10);
    oldUser.password = hashedPassword;
    await oldUser.save();

    res.status(200).send("Password Reset Successfully");
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Invalid Token or Server error" });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
