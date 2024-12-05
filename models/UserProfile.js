const mongoose = require('mongoose');

const userProfileSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true }, // Reference to User
    name: { type: String, required: true },
    age: { type: Number, required: true },
    contactNumber: { type: String, required: true },
    chronicDiseases: { type: String },
});

const UserProfile = mongoose.model('UserProfile', userProfileSchema);
module.exports = UserProfile;
