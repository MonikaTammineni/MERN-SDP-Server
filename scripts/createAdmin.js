const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('../models/User');

// MongoDB connection string from your .env
const mongoURI = 'mongodb+srv://2300032536:Monika_281005@cluster0.mv84j.mongodb.net/health-management';

const createAdmin = async () => {
    try {
        // Connect to MongoDB
        await mongoose.connect(mongoURI);
        console.log('Connected to MongoDB');

        // Check if admin already exists
        const existingAdmin = await User.findOne({ email: 'admin@example.com' });
        if (existingAdmin) {
            console.log('Admin user already exists');
            mongoose.connection.close();
            return;
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash('admin123', salt);

        // Create admin user
        const adminUser = new User({
            name: 'Admin User',
            email: 'admin@example.com',
            password: hashedPassword,
            role: 'admin'
        });

        await adminUser.save();
        console.log('Admin user created successfully');

    } catch (error) {
        console.error('Error creating admin user:', error);
    } finally {
        // Close the MongoDB connection
        mongoose.connection.close();
    }
};

// Execute the function
createAdmin();
