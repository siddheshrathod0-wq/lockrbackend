require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const Otp = require('./models/Otp');

const User = require('./models/User');
const Category = require('./models/Category');
const Entry = require('./models/Entry');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { authMiddleware, JWT_SECRET } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 5003;
const MONGO_URI = process.env.MONGO_URI;

// Encryption Configuration
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY || '', 'hex');
const IV_LENGTH = 16;
const ALGORITHM = 'aes-256-cbc';

function encrypt(text) {
    if (!text) return text;
    try {
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
        let encrypted = cipher.update(text);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return iv.toString('hex') + ':' + encrypted.toString('hex');
    } catch (e) {
        console.error('Encryption error:', e);
        return text;
    }
}

function decrypt(text) {
    if (!text) return text;
    try {
        const textParts = text.split(':');
        // Handle legacy unencrypted data or invalid format
        if (textParts.length < 2) return text;

        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (e) {
        // If decryption fails (e.g. wrong key, or plain text data in DB), return original
        console.error('Decryption error:', e);
        return text;
    }
}

app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

// Routes

// Send OTP
app.post('/api/auth/send-otp', async (req, res) => {
    try {
        const { email, type } = req.body;
        if (!email) return res.status(400).json({ error: 'Email is required' });

        // If registering, check if user exists
        if (type === 'register') {
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                return res.status(400).json({ error: 'Email already registered. Please login.' });
            }
        }
        // If login or password/passcode reset, check if user exists
        else if (type === 'login' || type === 'forgot-password' || type === 'reset-passcode') {
            const existingUser = await User.findOne({ email });
            if (!existingUser) {
                return res.status(400).json({ error: 'Email not found. Please create an account.' });
            }
        }

        // Generate 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // Save to DB (upsert: update if exists, else insert)
        await Otp.findOneAndUpdate({ email }, { otp }, { upsert: true, new: true });

        // Send Email via External API
        const response = await fetch("https://custom-mail-sender.vercel.app/api/send", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                to: email,
                subject: "Your Lockr Verification Code",
                html: `<div style="font-family: 'Helvetica Neue', Arial, sans-serif; background-color: #09090b; color: #ffffff; padding: 40px; text-align: center;">
                 <div style="max-width: 400px; margin: 0 auto; background-color: #18181b; padding: 40px; border-radius: 20px; border: 1px solid #27272a; box-shadow: 0 4px 20px rgba(0,0,0,0.5);">
                   <h2 style="color: #3b82f6; margin: 0 0 30px 0; font-size: 24px; letter-spacing: 2px; text-transform: uppercase;">Lockr</h2>
                   <p style="color: #a1a1aa; font-size: 14px; margin-bottom: 20px; line-height: 1.5;">Your verification code is</p>
                   <div style="background-color: #09090b; border: 1px solid #3b82f6; border-radius: 12px; padding: 20px; margin-bottom: 20px;">
                     <h1 style="font-size: 42px; letter-spacing: 8px; color: #60a5fa; margin: 0; font-weight: 700; font-family: monospace;">${otp}</h1>
                   </div>
                   <p style="color: #71717a; font-size: 13px;">This code expires in 5 minutes.</p>
                 </div>
                 <p style="color: #3f3f46; font-size: 12px; margin-top: 30px;">Secure Vault Protection</p>
               </div>`
            })
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error("Mail API Error:", errorText);
            // Fallback for demo if Mail API fails (or return error)
            // return res.status(500).json({ error: 'Failed to send email' });
        }

        res.json({ message: 'OTP sent successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Verify OTP & Register
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp, username } = req.body;
        if (!email || !otp) return res.status(400).json({ error: 'Email and OTP are required' });

        // Check OTP
        const record = await Otp.findOne({ email, otp });
        if (!record) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }

        // Register User (or get existing)
        let user = await User.findOne({ email });
        let passwordHash = undefined;

        if (req.body.password) {
            const salt = await bcrypt.genSalt(10);
            passwordHash = await bcrypt.hash(req.body.password, salt);
        }

        if (!user) {
            user = new User({
                email,
                username,
                password: passwordHash
            });
            await user.save();
        } else if (passwordHash) {
            // Update password if provided (for registration update or forgot-password)
            user.password = passwordHash;
            await user.save();
        }

        // Delete OTP after usage
        await Otp.deleteMany({ email });

        // Generate JWT token
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

        // For reset-passcode, we just need verification success
        if (req.body.type === 'reset-passcode') {
            return res.json({ message: 'OTP verified', resetToken: 'valid', token, user });
        }

        res.json({ message: 'Verification successful', user, token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- Settings Routes ---

// Get User Settings
app.get('/api/users/:userId/settings', authMiddleware, async (req, res) => {
    try {
        // Verify the userId matches the authenticated user
        if (req.params.userId !== req.userId.toString()) {
            return res.status(403).json({ error: 'Forbidden' });
        }

        const user = await User.findById(req.params.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(user.settings || {});
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Update User Settings
app.put('/api/users/:userId/settings', authMiddleware, async (req, res) => {
    try {
        // Verify the userId matches the authenticated user
        if (req.params.userId !== req.userId.toString()) {
            return res.status(403).json({ error: 'Forbidden' });
        }

        const user = await User.findByIdAndUpdate(
            req.params.userId,
            { $set: { settings: { ...req.body } } },
            { new: true, upsert: true }
        );
        res.json(user.settings);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// --- Category Routes ---

// Get All Categories
app.get('/api/categories/:userId', authMiddleware, async (req, res) => {
    try {
        if (req.params.userId !== req.userId.toString()) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const categories = await Category.find({ userId: req.params.userId });
        res.json(categories);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Create Category
app.post('/api/categories', authMiddleware, async (req, res) => {
    try {
        const { userId, name, icon, color } = req.body;
        if (userId !== req.userId.toString()) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const newCategory = new Category({ userId, name, icon, color });
        const savedCategory = await newCategory.save();
        res.json(savedCategory);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Update Category
app.put('/api/categories/:id', authMiddleware, async (req, res) => {
    try {
        const updatedCategory = await Category.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true }
        );
        res.json(updatedCategory);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete Category
app.delete('/api/categories/:id', authMiddleware, async (req, res) => {
    try {
        await Category.findByIdAndDelete(req.params.id);
        await Entry.deleteMany({ categoryId: req.params.id });
        res.json({ message: 'Category deleted' });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// --- Entry Routes ---

// Get All Entries for User
app.get('/api/entries/:userId', authMiddleware, async (req, res) => {
    try {
        if (req.params.userId !== req.userId.toString()) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const entries = await Entry.find({ userId: req.params.userId });

        // Decrypt sensitive data before sending to client
        const decryptedEntries = entries.map(entry => {
            const entryObj = entry.toObject();
            entryObj.password = decrypt(entryObj.password);

            if (entryObj.customFields) {
                entryObj.customFields = entryObj.customFields.map(field => {
                    if (field.isEncrypted) {
                        return { ...field, value: decrypt(field.value) };
                    }
                    return field;
                });
            }
            return entryObj;
        });

        res.json(decryptedEntries);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Create Entry
app.post('/api/entries', async (req, res) => {
    try {
        const entryData = { ...req.body };

        // Encrypt password
        entryData.password = encrypt(entryData.password);

        // Encrypt custom fields if marked
        if (entryData.customFields) {
            entryData.customFields = entryData.customFields.map(field => {
                if (field.isEncrypted) {
                    return { ...field, value: encrypt(field.value) };
                }
                return field;
            });
        }

        const newEntry = new Entry(entryData);
        const savedEntry = await newEntry.save();

        // Update category count
        await Category.findByIdAndUpdate(req.body.categoryId, { $inc: { entryCount: 1 } });

        // Return decrypted version
        const savedObj = savedEntry.toObject();
        savedObj.password = decrypt(savedObj.password);
        if (savedObj.customFields) {
            savedObj.customFields = savedObj.customFields.map(field => {
                if (field.isEncrypted) {
                    return { ...field, value: decrypt(field.value) };
                }
                return field;
            });
        }

        res.json(savedObj);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Update Entry
app.put('/api/entries/:id', authMiddleware, async (req, res) => {
    try {
        const entryData = { ...req.body };

        // Encrypt password
        entryData.password = encrypt(entryData.password);

        // Encrypt custom fields if marked
        if (entryData.customFields) {
            entryData.customFields = entryData.customFields.map(field => {
                if (field.isEncrypted) {
                    return { ...field, value: encrypt(field.value) };
                }
                return field;
            });
        }

        const updatedEntry = await Entry.findByIdAndUpdate(
            req.params.id,
            { ...entryData, updatedAt: Date.now() },
            { new: true }
        );

        const savedObj = updatedEntry.toObject();
        savedObj.password = decrypt(savedObj.password);
        if (savedObj.customFields) {
            savedObj.customFields = savedObj.customFields.map(field => {
                if (field.isEncrypted) {
                    return { ...field, value: decrypt(field.value) };
                }
                return field;
            });
        }

        res.json(savedObj);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete Entry
app.delete('/api/entries/:id', authMiddleware, async (req, res) => {
    try {
        const entry = await Entry.findById(req.params.id);
        if (entry) {
            await Entry.findByIdAndDelete(req.params.id);
            // Update category count
            await Category.findByIdAndUpdate(entry.categoryId, { $inc: { entryCount: -1 } });
        }
        res.json({ message: 'Entry deleted' });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Login with Password (Updated to return JWT token)
app.post('/api/auth/login-password', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ error: 'Invalid credentials' });

        // Check if user has a password set
        if (!user.password) return res.status(400).json({ error: 'No password set for this account. Please login via OTP.' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

        // Generate JWT token
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

        res.json({ message: 'Login successful', user, token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

module.exports = app;
