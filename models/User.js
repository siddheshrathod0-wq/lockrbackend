const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String }, // Hashed password
    username: { type: String },
    settings: {
        biometricEnabled: { type: Boolean, default: false },
        autoLockTimer: { type: Number, default: 5 },
        hasCompletedOnboarding: { type: Boolean, default: false },
        masterPasscodeHash: { type: String }
    },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);
