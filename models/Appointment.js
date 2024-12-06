const mongoose = require('mongoose');

const AppointmentSchema = new mongoose.Schema({
    doctor: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    patient: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    appointmentDate: {
        type: Date,
        required: true
    },
    appointmentTime: {
        type: String,
        required: true
    },
    reason: {
        type: String,
        required: true
    },
    status: {
        type: String,
        enum: ['pending', 'confirmed', 'completed', 'cancelled'],
        default: 'pending'
    },
    prescriptionDetails: {
        medicines: [{
            name: String,
            dosage: String,
            duration: String
        }],
        instructions: String,
        prescribedDate: {
            type: Date,
            default: Date.now
        }
    }
}, { timestamps: true });

module.exports = mongoose.model('Appointment', AppointmentSchema);
