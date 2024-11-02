import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true},
  password: { type: String, required: false },
  firstName: { type: String, required: true },
  lastName: { type: String, required: false },
  email: { type: String, unique: true },
  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date },
  role: { type: String, required: false },
  githubId: { type: String },
  songStyles: { type: [String], default: [] },
  musicPreferences: { type: [String], default: [] },
  songs: { type: [String], default: [] },
  
  name: { type: String, required: false },
  
  trend: { type: Number, default: null },
  rank: { type: Number, default: null },
  winrate: { type: Number, default: null },
  wins: { type: Number, default: null },
  losses: { type: Number, default: null },
  image: { type: String, required: false },
  
});

const User = mongoose.model("User", userSchema);
export default User;
