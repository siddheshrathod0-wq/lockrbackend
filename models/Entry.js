const mongoose = require('mongoose');

const entrySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    categoryId: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true },
    title: { type: String, required: true },
    username: { type: String, required: true },
    password: { type: String, required: true },
    notes: { type: String },
    customFields: [{
        id: String,
        name: String,
        value: String,
        isEncrypted: { type: Boolean, default: false }
    }],
    tags: [{ type: String }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Entry', entrySchema);
