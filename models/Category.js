const mongoose = require('mongoose');

const categorySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, required: true },
    icon: { type: String, required: true },
    color: { type: String },
    entryCount: { type: Number, default: 0 }
});

module.exports = mongoose.model('Category', categorySchema);
