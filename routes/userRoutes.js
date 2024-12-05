// routes/userRoutes.js
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const { protect, authorizeRoles } = require('../middleware/authMiddleware');

router.post('/register', async (req, res) => {
  const { name, email, password, role } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'User already exists with this email' });
    }

    const user = new User({ name, email, password, role });
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    res.status(201).json({ success: true, token, message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server Error' });
  }
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.status(200).json({ success: true, token, role: user.role });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server Error' });
  }
});

// Admin-only route
router.get('/admin', protect, authorizeRoles('admin'), (req, res) => {
  res.status(200).json({ message: 'Welcome Admin' });
});

// Doctor-only route
router.get('/doctor', protect, authorizeRoles('doctor'), (req, res) => {
  res.status(200).json({ message: 'Welcome Doctor' });
});

// User route (accessible to all roles)
router.get('/user', protect, (req, res) => {
  res.status(200).json({ message: 'Welcome User' });
});

// Fetch user profile
router.get('/profile', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('-password'); // Exclude password from response
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        res.status(200).json(user);
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ success: false, message: 'Error fetching profile' });
    }
});

// Update user profile
router.put('/profile', protect, async (req, res) => {
    try {
        const { name, age, chronicDiseases } = req.body;
        const user = await User.findById(req.user._id);

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Update user fields
        user.name = name || user.name;
        user.age = age || user.age;
        user.chronicDiseases = chronicDiseases || user.chronicDiseases;

        await user.save();
        res.status(200).json({ success: true, message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ success: false, message: 'Error updating profile' });
    }
});

// Create a new user profile (if needed)
router.post('/profile', protect, async (req, res) => {
    try {
        const { name, age, chronicDiseases } = req.body;
        const user = await User.findById(req.user._id);

        if (user) {
            return res.status(400).json({ success: false, message: 'Profile already exists' });
        }

        // Create a new user profile
        const newUser = new User({
            name,
            age,
            chronicDiseases,
            email: req.user.email // Assuming email is part of the user object
        });

        await newUser.save();
        res.status(201).json({ success: true, message: 'Profile created successfully' });
    } catch (error) {
        console.error('Error creating profile:', error);
        res.status(500).json({ success: false, message: 'Error creating profile' });
    }
});

module.exports = router;
