const mongoose = require('mongoose');

const MessageSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true
    },
    message: {
        type: String,
        required: true
    },
    status: {
        type: String,
        enum: ['pending', 'read'],
        default: 'pending'
    }
}, { timestamps: true });

module.exports = mongoose.model('Message', MessageSchema);