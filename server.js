require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const Appointment = require('./models/Appointment');
const BlockedSlot = require('./models/BlockedSlot');
const authMiddleware = require('./middleware/authMiddleware');
const moment = require('moment');

const app = express();
const PORT = 8080;

// Middleware
app.use(cors());
app.use(express.json()); // To parse JSON request bodies
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URL)
    .then(() => console.log('MongoDB Connected Successfully'))
    .catch(err => console.error('MongoDB Connection Error:', err));

// Registration route
app.post('/api/v1/user/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        
        // Set default role to 'user'
        const role = 'user';

        // Create new user
        const user = new User({
            name,
            email,
            password,
            role
        });

        // Hash password
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);

        await user.save();

        res.status(201).json({
            success: true,
            message: 'User registered successfully'
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: error.message || 'Error in registration'
        });
    }
});

// Login route
app.post('/api/v1/user/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('Login attempt for:', email); // Debug log

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            console.log('User not found'); // Debug log
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        console.log('User found:', user); // Debug log

        // Compare password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log('Password mismatch'); // Debug log
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        // Generate token
        const token = jwt.sign(
            { id: user._id, role: user.role },
            process.env.JWT_SECRET || 'MONIKA281005',
            { expiresIn: '1d' }
        );

        console.log('Login successful, sending response'); // Debug log

        // Send response
        res.status(200).json({
            success: true,
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Error in login',
            error: error.message
        });
    }
});

// Admin routes for managing doctors
app.post('/api/v1/admin/add-doctor', async (req, res) => {
    try {
        const { name, email, password, specialization } = req.body;
        
        // Check if doctor already exists
        const existingDoctor = await User.findOne({ email });
        if (existingDoctor) {
            return res.status(400).json({
                success: false,
                message: 'Doctor already exists with this email'
            });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new doctor
        const newDoctor = new User({
            name,
            email,
            password: hashedPassword,
            role: 'doctor',
            specialization
        });

        await newDoctor.save();

        res.status(201).json({
            success: true,
            message: 'Doctor added successfully'
        });

    } catch (error) {
        console.error('Error adding doctor:', error);
        res.status(500).json({
            success: false,
            message: 'Error adding doctor'
        });
    }
});

// Get all doctors
app.get('/api/v1/admin/doctors', async (req, res) => {
    try {
        const doctors = await User.find({ role: 'doctor' })
            .select('-password')
            .sort({ createdAt: -1 });
        
        res.status(200).json({
            success: true,
            doctors
        });
    } catch (error) {
        console.error('Error fetching doctors:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching doctors',
            error: error.message
        });
    }
});

// Get all users (excluding admins and doctors)
app.get('/api/v1/admin/users', async (req, res) => {
    try {
        const users = await User.find({ role: 'user' })
            .select('-password')
            .sort({ createdAt: -1 });
        
        res.status(200).json({
            success: true,
            users
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching users',
            error: error.message
        });
    }
});

// Get all appointments
app.get('/api/v1/admin/appointments', async (req, res) => {
    try {
        const appointments = await Appointment.find()
            .populate('doctor', 'name')
            .populate('patient', 'name')
            .sort({ appointmentDate: -1 });
        
        res.status(200).json({
            success: true,
            appointments
        });
    } catch (error) {
        console.error('Error fetching appointments:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching appointments',
            error: error.message
        });
    }
});

// Add new doctor
app.post('/api/v1/admin/add-doctor', async (req, res) => {
    try {
        const { name, email, password, specialization } = req.body;

        // Check if doctor already exists
        const existingDoctor = await User.findOne({ email });
        if (existingDoctor) {
            return res.status(400).json({
                success: false,
                message: 'Doctor already exists with this email'
            });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new doctor
        const newDoctor = new User({
            name,
            email,
            password: hashedPassword,
            role: 'doctor',
            specialization
        });

        await newDoctor.save();

        res.status(201).json({
            success: true,
            message: 'Doctor added successfully'
        });

    } catch (error) {
        console.error('Error adding doctor:', error);
        res.status(500).json({
            success: false,
            message: 'Error adding doctor',
            error: error.message
        });
    }
});

// Add new user
app.post('/api/v1/admin/add-user', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'User already exists with this email'
            });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new user
        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            role: 'user'
        });

        await newUser.save();

        res.status(201).json({
            success: true,
            message: 'User added successfully'
        });

    } catch (error) {
        console.error('Error adding user:', error);
        res.status(500).json({
            success: false,
            message: 'Error adding user',
            error: error.message
        });
    }
});

// Delete doctor
app.delete('/api/v1/admin/doctor/:id', async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.status(200).json({
            success: true,
            message: 'Doctor deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting doctor:', error);
        res.status(500).json({
            success: false,
            message: 'Error deleting doctor',
            error: error.message
        });
    }
});

// Delete user
app.delete('/api/v1/admin/user/:id', async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.status(200).json({
            success: true,
            message: 'User deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({
            success: false,
            message: 'Error deleting user',
            error: error.message
        });
    }
});

// Get all doctors for patients
app.get('/api/v1/user/doctors', async (req, res) => {
    try {
        const doctors = await User.find({ role: 'doctor' })
            .select('-password')
            .sort({ name: 1 });
        res.json({ success: true, doctors });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching doctors' });
    }
});

// Book appointment
app.post('/api/v1/user/book-appointment', authMiddleware, async (req, res) => {
    try {
        const { doctorId, appointmentDate, appointmentTime, reason } = req.body;
        console.log('Received appointment request:', { doctorId, appointmentDate, appointmentTime, reason }); // Debug log

        // Validate inputs
        if (!doctorId || !appointmentDate || !appointmentTime || !reason) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }

        // Check if doctor exists
        const doctor = await User.findOne({ _id: doctorId, role: 'doctor' });
        if (!doctor) {
            return res.status(404).json({
                success: false,
                message: 'Doctor not found'
            });
        }

        // Convert appointment time to moment objects for comparison
        const appointmentDateTime = moment(`${appointmentDate} ${appointmentTime}`, 'YYYY-MM-DD HH:mm');
        const oneHourBefore = moment(appointmentDateTime).subtract(1, 'hour');
        const oneHourAfter = moment(appointmentDateTime).add(1, 'hour');

        // Check for existing appointments
        const existingAppointment = await Appointment.findOne({
            doctor: doctorId,
            appointmentDate: moment(appointmentDate).toDate(),
            status: { $ne: 'cancelled' },
            appointmentTime: {
                $gte: oneHourBefore.format('HH:mm'),
                $lte: oneHourAfter.format('HH:mm')
            }
        });

        if (existingAppointment) {
            return res.status(400).json({
                success: false,
                message: 'This time slot is not available. Please choose a time that is at least 1 hour apart from existing appointments.'
            });
        }

        // Create new appointment
        const newAppointment = new Appointment({
            doctor: doctorId,
            patient: req.user._id,
            appointmentDate: moment(appointmentDate).toDate(),
            appointmentTime: appointmentTime,
            reason: reason,
            status: 'pending'
        });

        await newAppointment.save();
        console.log('Appointment saved:', newAppointment); // Debug log

        res.status(201).json({
            success: true,
            message: 'Appointment booked successfully',
            appointment: newAppointment
        });

    } catch (error) {
        console.error('Error booking appointment:', error);
        res.status(500).json({
            success: false,
            message: 'Error booking appointment',
            error: error.message
        });
    }
});

// Get user appointments
app.get('/api/v1/user/appointments', authMiddleware, async (req, res) => {
    try {
        console.log('Fetching appointments for user:', req.user._id); // Debug log
        const appointments = await Appointment.find({ patient: req.user._id })
            .populate('doctor', 'name email specialization')
            .sort({ appointmentDate: -1, appointmentTime: -1 });

        console.log('Found appointments:', appointments); // Debug log

        res.status(200).json({
            success: true,
            appointments
        });
    } catch (error) {
        console.error('Error fetching appointments:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching appointments',
            error: error.message
        });
    }
});

// Doctor Routes

// Get doctor's appointments
app.get('/api/v1/doctor/appointments', authMiddleware, async (req, res) => {
    try {
        const doctorId = req.user._id; // You'll need to implement auth middleware
        const appointments = await Appointment.find({ doctor: doctorId })
            .populate('patient', 'name email')
            .sort({ appointmentDate: -1, appointmentTime: -1 });

        res.status(200).json({
            success: true,
            appointments
        });
    } catch (error) {
        console.error('Error fetching doctor appointments:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching appointments'
        });
    }
});

// Get doctor's blocked slots
app.get('/api/v1/doctor/blocked-slots', authMiddleware, async (req, res) => {
    try {
        const doctorId = req.user._id;
        const blockedSlots = await BlockedSlot.find({ doctor: doctorId })
            .sort({ date: 1, time: 1 });

        res.status(200).json({
            success: true,
            blockedSlots
        });
    } catch (error) {
        console.error('Error fetching blocked slots:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching blocked slots'
        });
    }
});

// Block a time slot
app.post('/api/v1/doctor/block-slot', authMiddleware, async (req, res) => {
    try {
        const { date, time, reason } = req.body;
        const doctorId = req.user._id;

        const newBlockedSlot = new BlockedSlot({
            doctor: doctorId,
            date,
            time,
            reason
        });

        await newBlockedSlot.save();

        res.status(201).json({
            success: true,
            message: 'Time slot blocked successfully'
        });
    } catch (error) {
        console.error('Error blocking time slot:', error);
        res.status(500).json({
            success: false,
            message: 'Error blocking time slot'
        });
    }
});

// Update appointment status
app.put('/api/v1/doctor/appointment-status', authMiddleware, async (req, res) => {
    try {
        const { appointmentId, status, prescription } = req.body; // Get prescription from request
        const doctorId = req.user._id;

        const appointment = await Appointment.findOne({
            _id: appointmentId,
            doctor: doctorId
        });

        if (!appointment) {
            return res.status(404).json({
                success: false,
                message: 'Appointment not found'
            });
        }

        appointment.status = status;
        if (prescription) {
            appointment.prescription = prescription; // Save prescription URL
        }
        await appointment.save();

        res.status(200).json({
            success: true,
            message: 'Appointment status updated successfully'
        });
    } catch (error) {
        console.error('Error updating appointment status:', error);
        res.status(500).json({
            success: false,
            message: 'Error updating appointment status'
        });
    }
});

// Patient/User Routes

// Get all doctors for appointment booking
app.get('/api/v1/user/doctors', authMiddleware, async (req, res) => {
    try {
        const doctors = await User.find({ role: 'doctor' })
            .select('name email specialization')
            .sort({ name: 1 });
        
        res.status(200).json({
            success: true,
            doctors
        });
    } catch (error) {
        console.error('Error fetching doctors:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching doctors'
        });
    }
});

// Get user's appointments
app.get('/api/v1/user/appointments', authMiddleware, async (req, res) => {
    try {
        const appointments = await Appointment.find({ patient: req.user._id })
            .populate('doctor', 'name specialization')
            .sort({ appointmentDate: -1, appointmentTime: -1 });
        
        res.status(200).json({
            success: true,
            appointments
        });
    } catch (error) {
        console.error('Error fetching appointments:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching appointments'
        });
    }
});

// Book new appointment
app.post('/api/v1/user/book-appointment', authMiddleware, async (req, res) => {
    try {
        const { doctorId, appointmentDate, appointmentTime, reason } = req.body;

        // Check if slot is already booked
        const existingAppointment = await Appointment.findOne({
            doctor: doctorId,
            appointmentDate,
            appointmentTime,
            status: { $ne: 'cancelled' }
        });

        if (existingAppointment) {
            return res.status(400).json({
                success: false,
                message: 'This time slot is already booked'
            });
        }

        // Check if slot is blocked by doctor
        const blockedSlot = await BlockedSlot.findOne({
            doctor: doctorId,
            date: appointmentDate,
            time: appointmentTime
        });

        if (blockedSlot) {
            return res.status(400).json({
                success: false,
                message: 'This time slot is not available'
            });
        }

        // Create new appointment
        const appointment = new Appointment({
            doctor: doctorId,
            patient: req.user._id,
            appointmentDate,
            appointmentTime,
            reason,
            status: 'pending'
        });

        await appointment.save();

        res.status(201).json({
            success: true,
            message: 'Appointment booked successfully'
        });

    } catch (error) {
        console.error('Error booking appointment:', error);
        res.status(500).json({
            success: false,
            message: 'Error booking appointment'
        });
    }
});

// Cancel appointment
app.put('/api/v1/user/cancel-appointment/:id', authMiddleware, async (req, res) => {
    try {
        const appointment = await Appointment.findOne({
            _id: req.params.id,
            patient: req.user._id
        });

        if (!appointment) {
            return res.status(404).json({
                success: false,
                message: 'Appointment not found'
            });
        }

        appointment.status = 'cancelled';
        await appointment.save();

        res.status(200).json({
            success: true,
            message: 'Appointment cancelled successfully'
        });
    } catch (error) {
        console.error('Error cancelling appointment:', error);
        res.status(500).json({
            success: false,
            message: 'Error cancelling appointment'
        });
    }
});

// Add a new route to check available slots
app.get('/api/v1/user/available-slots', authMiddleware, async (req, res) => {
    try {
        const { doctorId, date } = req.query;
        
        // Get all appointments for the doctor on the selected date
        const bookedAppointments = await Appointment.find({
            doctor: doctorId,
            appointmentDate: moment(date).toDate(),
            status: { $ne: 'cancelled' }
        }).select('appointmentTime');

        // Get blocked slots
        const blockedSlots = await BlockedSlot.find({
            doctor: doctorId,
            date: moment(date).toDate()
        }).select('time');

        res.status(200).json({
            success: true,
            bookedAppointments,
            blockedSlots
        });

    } catch (error) {
        console.error('Error fetching available slots:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching available slots',
            error: error.message
        });
    }
});

// API endpoint to create a profile
app.post('/api/v1/user/profile', authMiddleware, async (req, res) => {
    console.log('Creating profile for user:', req.user._id); // Debug log
    try {
        const { name, age, contactNumber, chronicDiseases } = req.body;
        console.log('Profile data received:', req.body); // Debug log

        // Check if a profile already exists for the user
        const existingProfile = await UserProfile.findOne({ userId: req.user._id });
        if (existingProfile) {
            return res.status(400).json({ success: false, message: 'Profile already exists for this user' });
        }

        // Create a new profile
        const profile = new UserProfile({
            userId: req.user._id, // Associate profile with the user
            name,
            age,
            contactNumber,
            chronicDiseases,
        });
        await profile.save();
        res.status(201).json({ success: true, message: 'Profile created successfully' });
    } catch (error) {
        console.error('Error creating profile:', error); // Debug log
        res.status(400).json({ success: false, message: 'Error creating profile', error });
    }
});

// API endpoint to retrieve a profile
app.get('/api/v1/user/profile', authMiddleware, async (req, res) => {
    console.log('Retrieving profile for user:', req.user._id); // Debug log
    try {
        const profile = await UserProfile.findOne({ userId: req.user._id }); // Retrieve profile for the authenticated user
        if (!profile) {
            return res.status(404).json({ success: false, message: 'Profile not found' });
        }
        res.status(200).json(profile);
    } catch (error) {
        console.error('Error fetching profile:', error); // Debug log
        res.status(400).json({ success: false, message: 'Error fetching profile', error });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});