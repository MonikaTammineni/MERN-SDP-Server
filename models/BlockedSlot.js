const mongoose = require('mongoose');

const BlockedSlotSchema = new mongoose.Schema({
    doctor: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    date: {
        type: Date,
        required: true
    },
    time: {
        type: String,
        required: true
    },
    reason: {
        type: String,
        required: true
    }
}, { timestamps: true });

module.exports = mongoose.model('BlockedSlot', BlockedSlotSchema);
