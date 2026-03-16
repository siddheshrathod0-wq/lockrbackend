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
    // Vault key management for future-proof encryption
    vaultKeyEncryptedForServer: { type: String }, // Enc_SK(DK)
    vaultKeyEncryptedForUser: { type: String },   // Enc_PK(DK) - client-managed
    encryptionVersion: { type: Number, default: 1 },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);
